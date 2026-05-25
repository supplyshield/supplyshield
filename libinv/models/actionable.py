"""Sprint 41.2: Actionable-family ORM extraction from ``libinv.models._legacy``.

Owns three closely-coupled ORM classes:

- ``Actionable`` — a versionless package row (``safe_actionable`` table).
- ``ActionablePackageAvailableVersion`` — a single (purl, version) leaf.
- ``RepositoryActionablePackageAvailableVersion`` — the many-to-many
  association row tying APAV ↔ Repository through a Wasp commit.

Co-locating them keeps ``Actionable.populate``, the bulk INSERT…ON
CONFLICT path, and the selectinload eager-load chain in a single
domain file rather than scattered across siblings.

Re-exports + back-imports follow the same pattern as Sprint 39/40
extractions — ``_legacy.py`` back-imports these names so historical
``from libinv.models._legacy import Actionable`` callers keep working,
and the package ``__init__`` re-exports them as top-level names.
"""

from __future__ import annotations

import json
import logging
import time
from io import BytesIO
from typing import TYPE_CHECKING
from uuid import uuid4

import requests
from packageurl import PackageURL
from sqlalchemy import Boolean
from sqlalchemy import Column
from sqlalchemy import DateTime
from sqlalchemy import Float
from sqlalchemy import ForeignKey
from sqlalchemy import Index
from sqlalchemy import Integer
from sqlalchemy import String
from sqlalchemy import Text
from sqlalchemy import cast
from sqlalchemy import exists
from sqlalchemy import func
from sqlalchemy import select
from sqlalchemy import text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session as OrmSession
from sqlalchemy.orm import relationship
from sqlalchemy.orm import selectinload
from sqlalchemy.schema import UniqueConstraint
from univers.versions import MavenVersion

from libinv.base import Base
from libinv.base import conn
from libinv.base import session_scope
from libinv.env import PURLDB_API_URL
from libinv.env import SCANCODEIO_API_KEY
from libinv.env import SCANCODEIO_URL
from libinv.services import issue_reporter

try:
    from libinv.scio_models import DiscoveredPackage
except SQLAlchemyError:  # pragma: no cover - fallback for bootstrap when scanpipe tables missing
    # Sprint 47.2: narrowed from `except Exception`. The only failure
    # mode for ``libinv.scio_models`` import is the SQLAlchemy reflection
    # call (``inspect(engine).has_table``) when scanpipe tables are
    # missing or the SCIO DB is unreachable.
    DiscoveredPackage = None

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)


class Actionable(Base):
    """
    Stores next safe version of an actionable package
    """

    __tablename__ = "safe_actionable"

    uuid = Column(String(36), nullable=False, unique=True, default=uuid4, primary_key=True)
    package_url = Column(String(300), nullable=False, unique=True)
    # Sprint 34.1: server_default guarantees population — NOT NULL.
    updated_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    # Sprint 37.2: traversed in api/onboard_package.py:45,64 (actionable.available_versions)
    # and via the selectinload chain in get_actionable (Actionable.get_safe_versions /
    # get_latest use the __dict__ sentinel to detect pre-loaded state). Keep select.
    available_versions = relationship(
        "ActionablePackageAvailableVersion",
        back_populates="actionable",
        cascade="all, delete-orphan",
        lazy="select",
    )

    @classmethod
    def populate(
        cls,
        repository_id: int | None = None,
        environment: str | None = None,
        session: OrmSession | None = None,
    ) -> None:
        """Bulk-insert Actionable + ActionablePackageAvailableVersion rows.

        Sprint 38.2: replaced the per-purl ``get_or_create`` + commit-in-loop
        pattern with two ``INSERT ... ON CONFLICT DO NOTHING`` statements:
        one for the Actionable parent rows (conflict on ``package_url``)
        and one for the version child rows (conflict on the
        ``uq_package_version`` constraint of ``(package_url, version)``).
        A single ``session.commit()`` is issued after the bulk operation.
        """
        # Sprint 41.2: ``is_blacklist`` lives in ``_legacy`` (shared helper
        # — also exported via ``libinv.models``); import lazily to avoid
        # an import-time cycle (``_legacy`` re-imports this module at the
        # bottom for back-compatibility).
        from libinv.models._legacy import is_blacklist

        actionable_purls = cls.get_actionable_for(repository_id, environment)

        # Stage 1: assemble parent + child rows in-memory, skipping blacklisted
        # purls. We need a stable uuid per parent so the child row's FK can
        # reference it deterministically; we mint it here rather than relying
        # on a server-side default because the child INSERT runs in the same
        # statement batch as the parent and cannot read back generated PKs
        # without an extra round-trip.
        from uuid import uuid4 as _uuid4

        actionable_rows: list[dict] = []
        version_rows: list[dict] = []
        # purl_name -> uuid map deduplicates parents within the batch so two
        # purls that share a package_url use the SAME actionable_id for their
        # version children.
        purl_to_uuid: dict[str, str] = {}

        for purl in actionable_purls:
            purl_name = f"pkg:{purl.type}/{purl.namespace}/{purl.name}"
            if is_blacklist(purl_name):
                logger.debug(f"Blacklisted package: {purl_name}")
                continue

            if purl_name not in purl_to_uuid:
                new_uuid = str(_uuid4())
                purl_to_uuid[purl_name] = new_uuid
                actionable_rows.append(
                    {"uuid": new_uuid, "package_url": purl_name}
                )

            version_rows.append(
                {
                    "uuid": str(_uuid4()),
                    "package_url": purl_name,
                    "version": purl.version,
                    "is_version_in_use": True,
                    "actionable_id": purl_to_uuid[purl_name],
                    "scan_status": "ADDED",
                    "is_latest": False,
                }
            )

        if not actionable_rows and not version_rows:
            return

        # Stage 2: emit at most two INSERT statements, then commit once.
        # ``on_conflict_do_nothing`` resolves duplicates server-side:
        #   - Actionable: ``package_url`` is UNIQUE — use it as the index.
        #   - APAV: composite UNIQUE ``(package_url, version)`` via
        #     ``uq_package_version``.
        # Existing rows are left untouched; new rows are inserted atomically.
        with session_scope() as s:
            if actionable_rows:
                act_stmt = pg_insert(Actionable).values(actionable_rows)
                act_stmt = act_stmt.on_conflict_do_nothing(
                    index_elements=["package_url"]
                )
                s.execute(act_stmt)

            if version_rows:
                ver_stmt = pg_insert(ActionablePackageAvailableVersion).values(
                    version_rows
                )
                ver_stmt = ver_stmt.on_conflict_do_nothing(
                    index_elements=["package_url", "version"]
                )
                s.execute(ver_stmt)

            # Commit AFTER the bulk operation — not in the loop above.
            s.commit()

    def fetch_and_store_versions(self, session: OrmSession | None = None) -> None:
        s = session or conn
        logger.info(f"Processing: {self.package_url}")
        try:
            query = {"packages": [{"purl": self.package_url}]}
            try:
                response = requests.post(
                    f"{PURLDB_API_URL}/collect/index_packages/",
                    json=query,
                    timeout=30,
                )
                response.raise_for_status()
            except requests.RequestException as exc:
                logger.error("PURLDB index_packages request failed: %s", exc)
                raise

            if response.status_code == 200:
                response_json = response.json()
                new_versions = set(
                    PackageURL.from_string(purl).version
                    for purl in response_json.get("unqueued_packages", [])
                    + response_json.get("queued_packages", [])
                )

                if new_versions == ():
                    logger.error(f"No available versions found for package: {self.package_url}")
                    return

                # Sprint 38.2: bulk INSERT ... ON CONFLICT DO NOTHING
                # instead of per-row get_or_create + commit-in-loop. The
                # unique constraint ``uq_package_version`` on
                # ``(package_url, version)`` is the conflict target — any
                # duplicate purl@version we already stored is silently
                # skipped server-side.
                from uuid import uuid4 as _uuid4

                results = []
                for version in new_versions:
                    results.append(
                        {
                            "uuid": str(_uuid4()),
                            "package_url": self.package_url,
                            "scan_status": "ADDED",
                            "is_latest": False,
                            "vulns_count": None,
                            "scan_output": None,
                            "actionable_id": self.uuid,
                            "version": version,
                            "is_version_in_use": False,
                        }
                    )

                if results:
                    with session_scope() as session:
                        stmt = pg_insert(ActionablePackageAvailableVersion).values(
                            results
                        )
                        stmt = stmt.on_conflict_do_nothing(
                            index_elements=["package_url", "version"]
                        )
                        session.execute(stmt)
                        # Commit AFTER the bulk insert — not per-row.
                        session.commit()
            else:
                logger.error(f"Error fetching package: {self.package_url} - Error: {response.text}")
                return
            s.commit()
        except (requests.RequestException, SQLAlchemyError, ValueError) as e:
            # Sprint 47.2: narrowed from `except Exception`. Sources:
            # * ``requests.post`` -> requests.RequestException
            # * ``response.json()`` -> ValueError (JSONDecodeError subclass)
            # * ``PackageURL.from_string`` -> ValueError on malformed purl
            # * ``pg_insert`` / ``session.commit`` -> SQLAlchemyError
            logger.error(f"Error processing package: {self.package_url} - {e}")
            s.rollback()

    def get_available_versions(self):
        available_versions = list()
        with session_scope() as session:
            available_versions = (
                session.query(ActionablePackageAvailableVersion)
                .filter(ActionablePackageAvailableVersion.actionable_id == self.uuid)
                .all()
            )
        sorted_versions = sorted(available_versions, key=lambda v: MavenVersion(v.version))
        return sorted_versions

    @classmethod
    def get_packages_without_versions(cls, session: OrmSession | None = None):
        s = session or conn
        subquery = select(1).where(
            ActionablePackageAvailableVersion.actionable_id == Actionable.uuid
        )
        query = select(Actionable).where(~exists(subquery))
        return s.execute(query).scalars().all()

    def get_versions_in_use(self, session):
        return list(
            session.query(ActionablePackageAvailableVersion)
            .filter(ActionablePackageAvailableVersion.actionable_id == self.uuid)
            .filter(ActionablePackageAvailableVersion.is_version_in_use == True)
            .all()
        )

    def get_safe_versions(self, session: OrmSession | None = None):
        # Prefer eagerly-loaded relationship to avoid N+1 round trips when
        # the caller pre-loaded `available_versions` (e.g. via selectinload
        # in `get_actionable_and_secure_versions`). `"available_versions" in
        # self.__dict__` is the canonical sentinel for "this collection has
        # already been populated on the instance" — it does NOT trigger a
        # lazy load (which `getattr(self, "available_versions")` would).
        if "available_versions" in self.__dict__:
            result = [
                v
                for v in self.available_versions
                if v.vulns_count == 0 and v.scan_status == "SUCCESS"
            ]
            return sorted(result, key=lambda v: MavenVersion(v.version))
        s = session or conn
        result = list(
            s.query(ActionablePackageAvailableVersion)
            .filter(ActionablePackageAvailableVersion.actionable_id == self.uuid)
            .filter(ActionablePackageAvailableVersion.vulns_count == 0)
            .filter(ActionablePackageAvailableVersion.scan_status == "SUCCESS")
            .all()
        )
        return sorted(result, key=lambda v: MavenVersion(v.version))

    def get_versions_between(self, start_version, end_version):
        versions = self.get_available_versions()
        start_index = None
        end_index = None
        for i in range(0, len(versions)):
            if not start_index and versions[i].version == start_version.version:
                start_index = i
            if not end_index and versions[i].version == end_version:
                end_index = i

        return versions[start_index : end_index + 1]

    def find_safe_version_in(
        self, list_of_versions, session: OrmSession | None = None
    ) -> None:
        s = session or conn
        logger.info(f"Finding closest safe version for : {self.package_url}")

        if len(list_of_versions) == 0:
            logger.error(f"No available versions found for package: {self.package_url}")
            return

        left, right = 0, len(list_of_versions) - 1
        safe_version_obj = None

        while left <= right:
            mid = (left + right) // 2
            mid_version = list_of_versions[mid]
            logger.info(f"Checking version: {mid_version}")

            mid_version.scan_and_update_results()

            if mid_version._get_vulnerabilities_count() == 0:
                safe_version_obj = mid_version
                right = mid - 1
            else:
                left = mid + 1

        if safe_version_obj:
            logger.warning(
                f"Closest safe version for {self.package_url}: {safe_version_obj.version}"
            )
            self.scan_complete = True
        else:
            logger.warning(f"No safe version found for {self.package_url}")
            self.scan_complete = True

        s.commit()

    def get_latest(
        self, session: OrmSession | None = None
    ) -> "ActionablePackageAvailableVersion | None":
        # Prefer eagerly-loaded relationship to avoid N+1 round trips.
        # See `get_safe_versions` for the `__dict__` sentinel rationale.
        if "available_versions" in self.__dict__:
            latest = [v for v in self.available_versions if v.is_latest]
            return latest[0] if latest else None
        s = session or conn
        return (
            s.query(ActionablePackageAvailableVersion)
            .filter(ActionablePackageAvailableVersion.actionable_id == self.uuid)
            .filter(ActionablePackageAvailableVersion.is_latest == True)
            .one_or_none()
        )

    @classmethod
    def get_safe_version_for(cls, session, package_url):
        package_url = PackageURL.from_string(package_url)
        current_version = (
            session.query(ActionablePackageAvailableVersion)
            .filter(
                ActionablePackageAvailableVersion.package_url
                == f"pkg:{package_url.type}/{package_url.namespace}/{package_url.name}",
                ActionablePackageAvailableVersion.version == package_url.version,
            )
            .one_or_none()
        )
        if current_version:
            return current_version.get_safe_upgrade()
        else:
            return "NO_SAFE_VERSION"

    def mark_latest_version(self):
        """
        Mark the maximum version as latest for each actionable package.
        """
        with session_scope() as session:
            versions = (
                session.query(ActionablePackageAvailableVersion)
                .filter(ActionablePackageAvailableVersion.actionable_id == self.uuid)
                .all()
            )
            for version in versions:
                version.is_latest = False

            latest_version = max(versions, key=lambda v: MavenVersion(v.version))
            latest_version.is_latest = True
            session.commit()

    @classmethod
    def get_actionable(cls, session, repository_id, environment):
        # Eagerly load the per-row chain that `get_actionable_and_secure_versions`
        # walks for every row:
        #   row.available_version            -> ActionablePackageAvailableVersion
        #   row.available_version.actionable -> Actionable
        #   row.available_version.actionable.available_versions
        #                                    -> all sibling versions (used by
        #                                       Actionable.get_latest /
        #                                       get_safe_versions)
        #   row.wasp                         -> commit + jenkins_url metadata
        # Without selectinload this is the classic N+1 cascade: per outer row
        # SQLAlchemy issues 3+ lazy-load queries. With selectinload each level
        # is a single IN(...) query, collapsing O(P) -> O(1).
        return (
            session.query(RepositoryActionablePackageAvailableVersion)
            .options(
                selectinload(
                    RepositoryActionablePackageAvailableVersion.available_version
                )
                .selectinload(ActionablePackageAvailableVersion.actionable)
                .selectinload(Actionable.available_versions),
                selectinload(RepositoryActionablePackageAvailableVersion.wasp),
            )
            .join(ActionablePackageAvailableVersion)
            .filter(RepositoryActionablePackageAvailableVersion.repository_id == repository_id)
            .filter(RepositoryActionablePackageAvailableVersion.environment == environment)
            .all()
        )

    @classmethod
    def get_actionable_and_secure_versions(
        cls, session, repository_id, environment, with_metadata=True
    ):
        actionable_packages = Actionable.get_actionable(session, repository_id, environment)
        results = []

        for package in actionable_packages:
            current_version = package.available_version.version

            if (
                not package.available_version.vulns_count
                or package.available_version.vulns_count == 0
            ):
                continue

            latest_version = package.available_version.actionable.get_latest()

            secure_versions = None
            secure_versions = [
                package.version
                for package in package.available_version.actionable.get_safe_versions()
            ]

            results.append(
                {
                    "secure_version_available": len(secure_versions) > 0,
                    "full_package_url": package.available_version.package_url,
                    "current_version": current_version,
                    "current_version_score": package.available_version.epss_score,
                    "latest_version_score": latest_version.score,
                    "suggested_versions": secure_versions,
                    "versionless_id": package.available_version.actionable.uuid,
                }
            )

        commit_id = ""
        jenkins_url = ""

        if with_metadata and len(actionable_packages) > 0:
            commit_id = actionable_packages[0].wasp.commit
            jenkins_url = actionable_packages[0].wasp.jenkins_url

        results = sorted(results, key=lambda x: x["secure_version_available"], reverse=True)

        if with_metadata:
            return {"commit_id": commit_id, "jenkins_url": jenkins_url, "results": results}
        return results

    @staticmethod
    def get_actionables_issue(repo):
        """
        Checks if an issue already exists in the GitHub repository.
        """
        issues = repo.vcs.get_issues(repo)
        for issue in issues:
            for label in issue["labels"]:
                if label["name"] == f"sca-actionable-{repo.name}":
                    return issue["url"], True
        return None, False

    @classmethod
    def raise_sca_as_issue(cls, repo, actionables):
        """
        Creates an issue in the GitHub repository or updates if the issue already exists.
        """
        issue_url, existing_issue = cls.get_actionables_issue(repo)
        title, message = issue_reporter.prepare_git_issue_content(actionables)

        if existing_issue:
            repo.vcs.update_issue(
                issue_url, title, message, [f"sca-actionable-{repo.name}"], "Task"
            )
        else:
            repo.vcs.create_issue(repo, title, message, [f"sca-actionable-{repo.name}"], "Task")
            repo.vcs.update_label(repo, f"sca-actionable-{repo.name}", {"color": "b62c41"})

    @classmethod
    def close_sca_issue(cls, repo):
        """
        Closes an issue in the GitHub repository.
        """
        issue_url, existing_issue = cls.get_actionables_issue(repo)
        if existing_issue:
            repo.vcs.close_issue(issue_url)
        else:
            logger.error("No Issues were created for this repo")


class ActionablePackageAvailableVersion(Base):
    """
    Stores all available versions of an actionable package
    """

    __tablename__ = "actionable_package_available_versions"

    uuid = Column(String(36), nullable=False, unique=True, default=uuid4, primary_key=True)
    scan_status = Column(String(20), nullable=False)
    package_url = Column(String(300), nullable=False)
    version = Column(String(100), nullable=False)
    is_latest = Column(Boolean, nullable=False)
    vulns_count = Column(Integer, nullable=True)
    epss_score = Column(Float(precision=6), nullable=True)
    scan_output = Column(Text, nullable=True)
    # Sprint 34.1: server_default guarantees population — NOT NULL.
    updated_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )
    # Sprint 34.1: Python default=False; pair with server_default + NOT NULL.
    is_version_in_use = Column(
        Boolean, default=False, server_default="false", nullable=False
    )
    # Sprint 34.1: actionable_id FK left nullable=True — an APAV row may
    # transiently exist without an Actionable parent during ingestion.
    actionable_id = Column(
        ForeignKey("libinv.safe_actionable.uuid", onupdate="CASCADE", ondelete="CASCADE"),
        nullable=True,
    )
    scancode_project_uuid = Column(String(36), nullable=True)
    # Sprint 37.2: lazy= audit.
    # - actionable: traversed in api/actionable/package_scan.py:45 and
    #   api/actionable/dashboards.py via the get_actionable selectinload chain
    #   (Repository_APAV.available_version -> APAV.actionable -> Actionable.available_versions).
    #   cli/actionable.py:221 also walks package.available_version.actionable. Keep select.
    # - associated_repositories: never traversed in api/cli/scanners (queries go
    #   through Repository_APAV directly).
    actionable = relationship("Actionable", back_populates="available_versions", lazy="select")
    associated_repositories = relationship(
        "RepositoryActionablePackageAvailableVersion",
        back_populates="available_version",
        primaryjoin="ActionablePackageAvailableVersion.uuid == RepositoryActionablePackageAvailableVersion.actionable_package_version_id",
        lazy="raise_on_sql",
    )

    __table_args__ = (
        UniqueConstraint("package_url", "version", name="uq_package_version"),
        # Sprint 33.1/33.2: declare indexes already created by alembic 0002_fk_indexes
        Index("ix_actionable_pkg_available_versions_actionable_id", "actionable_id"),
        {"schema": "libinv"},
    )

    def __str__(self):
        return str(self.uuid)

    @property
    def purl(self):
        return PackageURL.from_string(self.package_url + "@" + self.version)

    @property
    def parsed_purl(self):
        """Return the parsed PackageURL without version for easy access to type, namespace, name"""
        return PackageURL.from_string(self.package_url)

    def _set_vulns_count(self, vulns_count):
        self.vulns_count = vulns_count

    def _get_vulnerabilities_count(self):
        if not self.scancode_project_uuid:
            return 0

        from libinv.services.scancodeio import ScancodeioError
        from libinv.services.scancodeio_client import get_default_client

        http_client = get_default_client()
        if http_client is not None:
            try:
                return http_client.get_vulnerability_count(self.scancode_project_uuid)
            except (ScancodeioError, requests.RequestException) as exc:
                # Sprint 47.2: narrowed from `except Exception`. The HTTP
                # client wraps all transport failures (4xx/5xx, timeouts,
                # connection errors) as ``ScancodeioError`` /
                # ``ScancodeioNotFound`` via _request_json; the raw
                # ``requests.RequestException`` clause guards against any
                # leak from session-level retries.
                logger.warning(
                    "SCIO HTTP get_vulnerability_count failed for %s: %s; "
                    "falling back to SQL",
                    self.scancode_project_uuid,
                    exc,
                )

        if DiscoveredPackage is None:
            return 0

        with session_scope() as session:
            result = (
                session.query(
                    func.sum(
                        func.jsonb_array_length(
                            cast(DiscoveredPackage.affected_by_vulnerabilities, JSONB)
                        )
                    ).label("total_vulnerabilities")
                )
                .filter(DiscoveredPackage.project_id == self.scancode_project_uuid)
                .filter(DiscoveredPackage.affected_by_vulnerabilities != "[]")
                .one()
            )
            total_vulnerabilities = result.total_vulnerabilities
            if total_vulnerabilities is None:
                return 0
            return int(total_vulnerabilities)

    @property
    def vulnerability_severities(self):
        if self.scancode_project_uuid is None:
            return None

        from libinv.services.scancodeio import ScancodeioError
        from libinv.services.scancodeio_client import get_default_client

        http_client = get_default_client()
        if http_client is not None:
            try:
                return http_client.get_severity_counts(self.scancode_project_uuid)
            except (ScancodeioError, requests.RequestException) as exc:
                # Sprint 47.2: narrowed from `except Exception`. Same
                # rationale as ``_get_vulnerabilities_count``: SCIO HTTP
                # client raises ``ScancodeioError`` subclasses on all
                # documented failure modes (404, 5xx, transport).
                logger.warning(
                    "SCIO HTTP get_severity_counts failed for %s: %s; "
                    "falling back to SQL",
                    self.scancode_project_uuid,
                    exc,
                )

        query = text(
            """
            WITH RECURSIVE severities(level) AS (
                VALUES ('critical'), ('high'), ('medium'), ('low'), ('unknown')
            ),
            mdata AS (
                SELECT
                    CASE
                        WHEN EXISTS (SELECT 1 FROM jsonb_array_elements(sd.affected_by_vulnerabilities) AS elem WHERE elem::varchar LIKE '%CRITICAL%') THEN 'critical'
                        WHEN EXISTS (SELECT 1 FROM jsonb_array_elements(sd.affected_by_vulnerabilities) AS elem WHERE elem::varchar LIKE '%HIGH%') THEN 'high'
                        WHEN EXISTS (SELECT 1 FROM jsonb_array_elements(sd.affected_by_vulnerabilities) AS elem WHERE elem::varchar LIKE '%MEDIUM%' OR elem::varchar LIKE '%MODERATE%') THEN 'medium'
                        WHEN EXISTS (SELECT 1 FROM jsonb_array_elements(sd.affected_by_vulnerabilities) AS elem WHERE elem::varchar LIKE '%LOW%') THEN 'low'
                        ELSE 'unknown'
                    END AS severity_level
                FROM public.scanpipe_discoveredpackage sd
                WHERE
                    jsonb_array_length(sd.affected_by_vulnerabilities) > 0
                    AND sd.project_id = :project_id
            )
            SELECT
                s.level AS severity_level,
                COALESCE(COUNT(m.severity_level), 0) as count
            FROM severities s
            LEFT JOIN mdata m ON m.severity_level = s.level
            GROUP BY s.level
            ORDER BY
                CASE s.level
                    WHEN 'critical' THEN 1
                    WHEN 'high' THEN 2
                    WHEN 'medium' THEN 3
                    WHEN 'low' THEN 4
                    ELSE 5
                END;
            """
        )

        with session_scope() as session:
            result = session.execute(query, {"project_id": self.scancode_project_uuid})
            data = [{"severity_level": row.severity_level, "count": row.count} for row in result]
            return data

    @property
    def score(self):
        severities = self.vulnerability_severities
        if not severities:
            return None
        score = 0
        for severity in severities:
            if severity["severity_level"] == "critical":
                score += severity["count"] * 20
            elif severity["severity_level"] == "high":
                score += severity["count"] * 10
            elif severity["severity_level"] == "medium":
                score += severity["count"] * 5
            elif severity["severity_level"] == "low":
                score += severity["count"] * 1
        return score

    @classmethod
    def get_latest_packages(cls):
        with session_scope() as session:
            return session.query(cls).filter(cls.is_latest == True).all()

    @classmethod
    def get_scan_failed_packages(cls):
        with session_scope() as session:
            return (
                session.query(cls)
                .filter(cls.vulns_count == None)
                .filter(cls.scan_status == "FAILED")
                .all()
            )

    @classmethod
    def get_packages_in_use(cls):
        with session_scope() as session:
            return session.query(cls).filter(cls.is_version_in_use == True).all()

    def scan_and_update_results(
        self, session: OrmSession | None = None, is_rescan: bool = False
    ) -> None:
        """ "
        The function triggers a scan for the package and updates the results.
        """
        s = session or conn
        logger.info(f"Scanning: {self}")
        if self.scan_status == "SUCCESS" and not is_rescan:
            logger.info(f"Scan already completed for: {self}")
            return

        try:
            request_session = requests.Session()
            self.scan_status = "TRIGGERED"
            if SCANCODEIO_API_KEY:
                request_session.headers.update({"Authorization": f"Token {SCANCODEIO_API_KEY}"})

            projects_api_url = f"{SCANCODEIO_URL}/api/projects/"
            project_name = f"{str(self)}-{time.time_ns()}"
            project_data = {
                "name": project_name,
                "pipeline": ["load_inventory", "purl_sbom", "load_sbom", "find_vulnerabilities"],
                "execute_now": True,
            }
            scan_data = {
                "headers": [{"tool_name": "scanpipe"}],
                "packages": [
                    {
                        "type": self.purl.type,
                        "namespace": self.purl.namespace,
                        "name": self.purl.name,
                        "version": self.purl.version,
                        "qualifiers": "",
                        "subpath": "",
                    }
                ],
            }
            memory_file = BytesIO(json.dumps(scan_data).encode())
            files = {"upload_file": ("dependencies.json", memory_file)}

            response = request_session.post(
                projects_api_url, data=project_data, files=files, timeout=300
            )
            logger.debug("projects_api_url: %s", projects_api_url)
            logger.debug(f"Scancodeio response: {response.text}")

            self.scan_output = response.text
            response_json = response.json()
            self.scancode_project_uuid = response_json["uuid"]
            self.vulns_count = self._get_vulnerabilities_count()
        except (requests.RequestException, ValueError, KeyError, SQLAlchemyError) as e:
            # Sprint 47.2: narrowed from `except Exception`. Sources:
            # * ``request_session.post`` -> requests.RequestException
            # * ``response.json()`` -> ValueError (JSONDecodeError)
            # * ``response_json["uuid"]`` -> KeyError when scancodeio
            #   returns an error payload without ``uuid``
            # * ``_get_vulnerabilities_count`` -> SQLAlchemyError on the
            #   SQL fallback path (already narrows ScancodeioError above).
            self.scan_status = "FAILED"
            self.scan_output = f"Error running scancodeio - Error: {e}"
            logger.error(f"Error running scancodeio - Error: {e}")
        finally:
            if self.scan_status != "FAILED":
                self.scan_status = "SUCCESS"
            s.add(self)
            s.commit()
            memory_file.close()

    @property
    def is_safe(self):
        return self.vulns_count == 0

    @property
    def scanned(self):
        return self.scan_status == "SUCCESS"

    def get_safe_upgrade(self):
        """
        Return the upgrade version if there are any available safe versions above the current version
        """
        available_safe_versions = self.actionable.get_safe_versions()
        current_version = MavenVersion(self.version)
        for version in available_safe_versions:
            if MavenVersion(version.version) >= current_version:
                return version.version
        return None

    @classmethod
    def get_by_purl(cls, session, package_url, version):
        return (
            session.query(cls)
            .filter(cls.package_url == package_url)
            .filter(cls.version == version)
            .one_or_none()
        )

    def get_cves(self, session):
        """
        Return a set of CVE IDs affecting this package version based on
        scanpipe discovered packages linked via scancode_project_uuid.
        """
        if not self.scancode_project_uuid or DiscoveredPackage is None:
            return set()

        discovered_packages = (
            session.query(DiscoveredPackage)
            .filter(DiscoveredPackage.project_id == self.scancode_project_uuid)
            .all()
        )

        cve_set = set()
        for discovered_pkg in discovered_packages:
            vulnerabilities = getattr(discovered_pkg, "affected_by_vulnerabilities", [])
            if not vulnerabilities:
                continue
            for vulnerability in vulnerabilities:
                try:
                    aliases = vulnerability.get("aliases", [])
                    for alias in aliases:
                        if isinstance(alias, str) and alias.upper().startswith("CVE-"):
                            cve_set.add(alias.upper())
                except (AttributeError, TypeError):
                    # Ignore malformed vulnerability entries
                    continue

        return cve_set


class RepositoryActionablePackageAvailableVersion(Base):
    """
    Model representing actionable for a repository and the corresponding version in ActionablePackageAvailableVersion table
    """

    __tablename__ = "repository_actionable_package_versions_association"

    uuid = Column(String(36), nullable=False, unique=True, default=uuid4, primary_key=True)
    # Sprint 34.1: FKs left nullable=True — association rows may be created
    # by partial ingestion paths that fill in linkage incrementally.
    wasp_uuid = Column(
        ForeignKey("libinv.wasps.uuid", onupdate="CASCADE", ondelete="CASCADE"),
        nullable=True,
    )
    actionable_package_version_id = Column(
        ForeignKey(
            "libinv.actionable_package_available_versions.uuid",
            onupdate="CASCADE",
            ondelete="CASCADE",
        ),
        nullable=True,
    )
    repository_id = Column(
        ForeignKey("libinv.repositories.id", onupdate="CASCADE", ondelete="CASCADE"),
        nullable=True,
    )
    environment = Column(String(20), nullable=False)
    # Sprint 34.1: server_default guarantees population — NOT NULL.
    created_at = Column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    # Sprint 37.2: lazy= audit.
    # - wasp: traversed in api/actionable/dashboards.py:86-88 (commit_id, jenkins_url,
    #   created_at). Eagerly loaded via selectinload in Actionable.get_actionable.
    #   Keep select.
    # - available_version: traversed in api/actionable/dashboards.py (extensively) and
    #   cli/actionable.py:214-221 via package.available_version.*. Pre-loaded via the
    #   selectinload chain in get_actionable. Keep select.
    # - repository: never traversed via row.repository in api/cli/scanners (queries
    #   already filter on repository_id; the Repository row is fetched separately
    #   via _common.fetch_repository).
    wasp = relationship("Wasp", back_populates="actionable_versions", lazy="select")
    available_version = relationship(
        "ActionablePackageAvailableVersion",
        back_populates="associated_repositories",
        primaryjoin="RepositoryActionablePackageAvailableVersion.actionable_package_version_id == ActionablePackageAvailableVersion.uuid",
        lazy="select",
    )
    repository = relationship(
        "Repository", back_populates="actionable_versions", lazy="raise_on_sql"
    )

    __table_args__ = (
        # Sprint 33.1/33.2: declare indexes already created by alembic 0002_fk_indexes
        Index(
            "ix_repo_actionable_pkg_versions_assoc_pkg_version_id",
            "actionable_package_version_id",
        ),
        Index(
            "ix_repo_actionable_pkg_versions_assoc_repository_id",
            "repository_id",
        ),
        Index(
            "ix_repo_actionable_pkg_versions_assoc_wasp_uuid",
            "wasp_uuid",
        ),
        # Composite index for hot query path.
        Index(
            "ix_repo_actionable_pkg_versions_repo_env",
            "repository_id",
            "environment",
        ),
        {"schema": "libinv"},
    )
