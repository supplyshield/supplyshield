import logging
from datetime import datetime
from datetime import timezone

from jira import JIRA

from libinv.base import conn
from libinv.env import JIRA_TOKEN
from libinv.env import JIRA_URL
from libinv.env import JIRA_USER
from libinv.helpers import explode_git_url
from libinv.models import MAX_LENGTH_VULNERABILITY_DESCRIPTION
from libinv.models import ConflictingInfoError
from libinv.models import Repository
from libinv.models import Secbug
from libinv.models import get_or_create
from libinv.models import get_or_update_entry
from libinv.models import update_safely

logger = logging.getLogger("libinv.jira-integration")


def safe_get_field(issue, field_id):
    """
    Safely get a custom field value from a JIRA issue.
    Returns None if field_id is None or if the field doesn't exist on the issue.
    """
    if field_id is None:
        return None

    try:
        return issue.get_field(field_id)
    except AttributeError:
        # This is expected when an issue doesn't have a particular custom field
        # (e.g., some issues have "Github Repo" field, others have "Repo name" field)
        return None


def get_repository_name_from_field(field_value):
    if not field_value:
        return None

    if isinstance(field_value, list):
        if not field_value:
            return None
        field_value = field_value[0]

    if isinstance(field_value, str) and ("://" in field_value or "@" in field_value):
        try:
            return explode_git_url(field_value)["name"]
        except Exception as e:
            logger.warning(f"Failed to parse git URL '{field_value}': {e}")
            return None

    return field_value


class JiraProject:
    def __init__(self, project_name, user, token):
        self.name = project_name
        self.jira = JIRA(server=JIRA_URL, basic_auth=(user, token))
        self.id = self.jira.project(project_name).id

    def get_customfield_id_by_name(self, name: str):
        """
        Return **first** customfield id where the given name matches scoped for given project id
        """
        for field in self.jira.fields():
            try:
                if name == field["name"] and field["scope"]["project"]["id"] == self.id:
                    return field["id"]
            except KeyError:
                pass
        return None

    def print_customfields(self):
        for field in self.jira.fields():
            try:
                if field["scope"]["project"]["id"] == self.id:
                    print(f"{field['id']}: {field['name']}")
            except KeyError:
                pass
        return None

    @property
    def issues(self):
        jql = f'project={self.name} AND status in ("TO DO", "IN PROGRESS") order by created DESC'
        return self.jira.enhanced_search_issues(
            jql_str=jql,
            maxResults=0,  # 0 means get all issues in batches
        )


class JiraSecbug(JiraProject):
    def __init__(self):
        super().__init__(project_name="SECBUG", user=JIRA_USER, token=JIRA_TOKEN)


def get_or_update_repository(repository_name: str, pod: str, subpod: str):
    repository = conn.query(Repository).filter(Repository.name == repository_name).one_or_none()
    if not repository:
        logger.error(f"Unknown repository: {repository_name}, lob: {pod}, pod: {subpod}. Skipped")
        # FIXME: We probably want to add this repository, but what's source of truth for pod and
        # subpod ?
        return

    try:
        update_safely(session=conn, model=repository, attr="pod", value=pod)
        update_safely(session=conn, model=repository, attr="subpod", value=subpod)
    except ConflictingInfoError as exc:
        logger.warning(exc)
        # FIXME: Something should be done here, for now we ignore and don't update anything

    return repository


def fix_severity(severity):
    if severity.casefold() == "highest":
        return "Critical"
    if severity.casefold() == "lowest":
        return "Low"
    return severity


def pop_or_none(lst):
    if lst:
        return lst.pop()
    return None


def to_datetime(date_string):
    return datetime.strptime(date_string, "%Y-%m-%dT%H:%M:%S.%f%z")


def delete_outdated_secbugs(all_fetched_secbug_keys):
    # Why don't we use the "resolved" field ?
    # - It isn't consistent across all secbugs (mostly old ones)

    logger.info(f"DEBUG: Fetched {len(all_fetched_secbug_keys)} secbugs from Jira API")

    secbugs_in_db = Secbug.all_active().all()
    logger.info(f"DEBUG: Found {len(secbugs_in_db)} active secbugs in database")

    deleted_count = 0
    for secbug in secbugs_in_db:
        if secbug.key not in all_fetched_secbug_keys:
            logger.info(f"DEBUG: Deleting secbug {secbug.key} (not in API response)")
            secbug.delete()
            deleted_count += 1

    logger.info(f"DEBUG: Deleted {deleted_count} secbugs")
    conn.commit()


def get_field_value(issue, field_id):
    """Get field value with safe access and automatic .value extraction for choice fields"""
    field_data = safe_get_field(issue, field_id)
    if hasattr(field_data, "value"):
        return field_data.value
    return field_data


def create_secbug_data(
    secbug_id,
    environment,
    severity,
    summary,
    description,
    created_at,
    updated_at,
    company,
    vulnerability_category,
    identified_by,
    repository_id=None,
    pulled_at=None,
):
    """Create standardized secbug data dictionary"""
    return {
        "id": secbug_id,
        "environment": environment,
        "severity": severity,
        "summary": summary,
        "description": description[:MAX_LENGTH_VULNERABILITY_DESCRIPTION],
        "created_at": created_at,
        "updated_at": updated_at,
        "company": company,
        "vulnerability_category": vulnerability_category,
        "identified_by": identified_by,
        "repository_id": repository_id,
        "pulled_at": pulled_at,
    }


def process_secbug_repository(repository_name, lob, pod):
    """Process repository and return repository object if found"""
    if not repository_name:
        return None

    repository = get_or_update_repository(repository_name=repository_name, pod=lob, subpod=pod)
    return repository


def connect():
    secbug = JiraSecbug()
    environment_field_id = secbug.get_customfield_id_by_name("Accessibility")
    lob_field_id = secbug.get_customfield_id_by_name("pod")
    pod_field_id = secbug.get_customfield_id_by_name("subpod")
    repo_field_id = secbug.get_customfield_id_by_name("Github Repo")
    repo_name_field_id = secbug.get_customfield_id_by_name("Repo Name")
    company_field_id = secbug.get_customfield_id_by_name("Company")
    vulnerability_category_id = secbug.get_customfield_id_by_name("OWASP Category")
    identified_by_id = secbug.get_customfield_id_by_name("Identified Using")
    pulled_at = datetime.now(timezone.utc)

    delete_outdated_secbugs([issue.key for issue in secbug.issues])

    for issue in secbug.issues:
        secbug_id = issue.key

        # Extract all field values
        environment = get_field_value(issue, environment_field_id)[:20]
        severity = fix_severity(issue.fields.priority.name)
        description = issue.fields.description
        lob = pop_or_none(safe_get_field(issue, lob_field_id))
        pod = pop_or_none(safe_get_field(issue, pod_field_id))
        created_at = to_datetime(issue.fields.created)
        updated_at = to_datetime(issue.fields.updated)
        summary = issue.fields.summary
        company = get_field_value(issue, company_field_id)
        vulnerability_category = get_field_value(issue, vulnerability_category_id)
        identified_by = get_field_value(issue, identified_by_id)

        # Get repository name from either field
        repository_name = None
        repo_url_value = safe_get_field(issue, repo_field_id)
        if repo_url_value:
            repository_name = get_repository_name_from_field(repo_url_value)

        if not repository_name:
            repo_name_value = safe_get_field(issue, repo_name_field_id)
            if repo_name_value:
                repository_name = get_repository_name_from_field(repo_name_value)
        # Process repository
        repository = process_secbug_repository(repository_name, lob, pod)
        repository_id = repository.id if repository else None

        # Create secbug data
        secbug_data = create_secbug_data(
            secbug_id=secbug_id,
            environment=environment,
            severity=severity,
            summary=summary,
            description=description,
            created_at=created_at,
            updated_at=updated_at,
            company=company,
            vulnerability_category=vulnerability_category,
            identified_by=identified_by,
            repository_id=repository_id,
            pulled_at=pulled_at,
        )

        # Update existing or create new secbug
        if Secbug.get_any(secbug_id):
            logger.debug(f"Already exists, updating {secbug_id}")
            # Always update existing secbugs (original behavior)
            get_or_update_entry(
                session=conn,
                model=Secbug,
                query_filter={"id": secbug_id},
                deleted_at=None,  # probably recreated, see jql used
                **{k: v for k, v in secbug_data.items() if k not in ["id", "pulled_at"]},
            )
        else:
            logger.info(f"[+] New secbug: {secbug_id}")
            # For new secbugs: create if repository found OR no repository specified
            if repository_name is None:
                # No repository specified - create secbug without repository
                logger.warning(f"No repository data present for {secbug_id}")
                secbug_data_no_repo = {k: v for k, v in secbug_data.items() if k != "repository_id"}
                get_or_create(session=conn, model=Secbug, **secbug_data_no_repo)
            elif repository is not None:
                # Repository found - create secbug with repository
                get_or_create(session=conn, model=Secbug, **secbug_data)
            # If repository_name exists but repository not found - skip (original behavior)

        logger.debug(f"[+] Processed {issue.key}")
