from flask import render_template
from sqlalchemy import and_
from sqlalchemy import distinct
from sqlalchemy import func
from sqlalchemy import text

from libinv import logger
from libinv.base import Session
from libinv.models import ActionablePackageAvailableVersion
from libinv.models import Repository
from libinv.models import Repository_ActionablePackageAvailableVersion

from libinv.api.actionable import actionable


def _compute_statistics(session):
    """Run the aggregate queries that power /v3/statistics.

    Executes the 14 serial aggregate queries against the supplied session
    and assembles them into the nested ``statistics`` dict consumed by
    ``statistics.html``. The caller owns the session/transaction lifecycle
    (this helper does NOT open or close a session, nor set timeouts).

    Returned dict shape (all counts are non-negative ints; percentages and
    averages are floats):

    ``package_stats``: dict with keys ``total_packages``,
    ``vulnerable_packages``, ``packages_without_vulnerabilities``,
    ``packages_with_epss``, ``vulnerability_percentage``,
    ``epss_coverage_percentage``, ``p0_packages``, ``p1_packages``,
    ``p2_packages``, ``p3_packages``, ``no_epss_packages``.

    ``vulnerability_stats``: dict with keys ``total_vulnerabilities``,
    ``critical_vulnerabilities``, ``high_vulnerabilities``,
    ``medium_vulnerabilities``, ``low_vulnerabilities``,
    ``avg_vulns_per_vulnerable_package``.

    ``repository_stats``: dict with keys ``total_repositories``,
    ``repositories_with_vulnerabilities``,
    ``repositories_without_vulnerabilities``, ``vulnerability_percentage``,
    ``p0_repositories``, ``p1_repositories``, ``p2_repositories``,
    ``p3_repositories``, ``no_epss_repositories``.

    ``environment_stats``: list of {environment, repository_count, package_count}.

    ``pod_stats``: list of {pod, vulnerable_packages, p0, p1, p2, p3}.

    ``organization_stats``: list of {organization, repository_count}.
    """
    package_stats = session.query(
        func.count(ActionablePackageAvailableVersion.uuid).label("total_packages"),
        func.count(ActionablePackageAvailableVersion.uuid)
        .filter(ActionablePackageAvailableVersion.vulns_count > 0)
        .label("vulnerable_packages"),
        func.count(ActionablePackageAvailableVersion.uuid)
        .filter(ActionablePackageAvailableVersion.epss_score.isnot(None))
        .label("packages_with_epss"),
        func.sum(ActionablePackageAvailableVersion.vulns_count).label("total_vulnerabilities"),
    ).first()

    # Calculate EPSS priority distributions — one SQL statement using
    # PG ``COUNT(*) FILTER (WHERE ...)`` aggregates so all five buckets
    # (p0/p1/p2/p3/no_epss) share a single scan of the table.
    bucket_row = session.query(
        func.count(ActionablePackageAvailableVersion.uuid)
        .filter(
            and_(
                ActionablePackageAvailableVersion.epss_score > 0.8,
                ActionablePackageAvailableVersion.vulns_count > 0,
            )
        )
        .label("p0"),
        func.count(ActionablePackageAvailableVersion.uuid)
        .filter(
            and_(
                ActionablePackageAvailableVersion.epss_score > 0.7,
                ActionablePackageAvailableVersion.epss_score <= 0.8,
                ActionablePackageAvailableVersion.vulns_count > 0,
            )
        )
        .label("p1"),
        func.count(ActionablePackageAvailableVersion.uuid)
        .filter(
            and_(
                ActionablePackageAvailableVersion.epss_score > 0.5,
                ActionablePackageAvailableVersion.epss_score <= 0.7,
                ActionablePackageAvailableVersion.vulns_count > 0,
            )
        )
        .label("p2"),
        func.count(ActionablePackageAvailableVersion.uuid)
        .filter(
            and_(
                ActionablePackageAvailableVersion.epss_score <= 0.5,
                ActionablePackageAvailableVersion.epss_score.isnot(None),
                ActionablePackageAvailableVersion.vulns_count > 0,
            )
        )
        .label("p3"),
        func.count(ActionablePackageAvailableVersion.uuid)
        .filter(
            and_(
                ActionablePackageAvailableVersion.epss_score.is_(None),
                ActionablePackageAvailableVersion.vulns_count > 0,
            )
        )
        .label("no_epss"),
    ).one()

    p0_packages = bucket_row.p0 or 0
    p1_packages = bucket_row.p1 or 0
    p2_packages = bucket_row.p2 or 0
    p3_packages = bucket_row.p3 or 0
    no_epss_packages = bucket_row.no_epss or 0

    # Extract values from the aggregated query
    total_packages = package_stats.total_packages or 0
    vulnerable_packages = package_stats.vulnerable_packages or 0
    packages_with_epss = package_stats.packages_with_epss or 0
    total_vulnerabilities = package_stats.total_vulnerabilities or 0

    # For now, skip detailed severity statistics to avoid performance issues
    # TODO: Implement more efficient severity calculation if needed
    critical_vulns = 0
    high_vulns = 0
    medium_vulns = 0
    low_vulns = 0

    # Get repository statistics
    total_repositories = session.query(func.count(distinct(Repository.id))).scalar() or 0

    repositories_with_vulns = (
        session.query(func.count(distinct(Repository.id)))
        .join(
            Repository_ActionablePackageAvailableVersion,
            Repository.id == Repository_ActionablePackageAvailableVersion.repository_id,
        )
        .join(
            ActionablePackageAvailableVersion,
            Repository_ActionablePackageAvailableVersion.actionable_package_version_id
            == ActionablePackageAvailableVersion.uuid,
        )
        .filter(ActionablePackageAvailableVersion.vulns_count > 0)
        .scalar()
        or 0
    )

    repositories_without_vulns = total_repositories - repositories_with_vulns

    # Calculate repository priority distributions
    repo_p0_count = (
        session.query(func.count(distinct(Repository.id)))
        .join(
            Repository_ActionablePackageAvailableVersion,
            Repository.id == Repository_ActionablePackageAvailableVersion.repository_id,
        )
        .join(
            ActionablePackageAvailableVersion,
            Repository_ActionablePackageAvailableVersion.actionable_package_version_id
            == ActionablePackageAvailableVersion.uuid,
        )
        .filter(
            and_(
                ActionablePackageAvailableVersion.epss_score > 0.8,
                ActionablePackageAvailableVersion.vulns_count > 0,
            )
        )
        .scalar()
        or 0
    )

    repo_p1_count = (
        session.query(func.count(distinct(Repository.id)))
        .join(
            Repository_ActionablePackageAvailableVersion,
            Repository.id == Repository_ActionablePackageAvailableVersion.repository_id,
        )
        .join(
            ActionablePackageAvailableVersion,
            Repository_ActionablePackageAvailableVersion.actionable_package_version_id
            == ActionablePackageAvailableVersion.uuid,
        )
        .filter(
            and_(
                ActionablePackageAvailableVersion.epss_score > 0.7,
                ActionablePackageAvailableVersion.epss_score <= 0.8,
                ActionablePackageAvailableVersion.vulns_count > 0,
            )
        )
        .scalar()
        or 0
    )

    repo_p2_count = (
        session.query(func.count(distinct(Repository.id)))
        .join(
            Repository_ActionablePackageAvailableVersion,
            Repository.id == Repository_ActionablePackageAvailableVersion.repository_id,
        )
        .join(
            ActionablePackageAvailableVersion,
            Repository_ActionablePackageAvailableVersion.actionable_package_version_id
            == ActionablePackageAvailableVersion.uuid,
        )
        .filter(
            and_(
                ActionablePackageAvailableVersion.epss_score > 0.5,
                ActionablePackageAvailableVersion.epss_score <= 0.7,
                ActionablePackageAvailableVersion.vulns_count > 0,
            )
        )
        .scalar()
        or 0
    )

    repo_p3_count = (
        session.query(func.count(distinct(Repository.id)))
        .join(
            Repository_ActionablePackageAvailableVersion,
            Repository.id == Repository_ActionablePackageAvailableVersion.repository_id,
        )
        .join(
            ActionablePackageAvailableVersion,
            Repository_ActionablePackageAvailableVersion.actionable_package_version_id
            == ActionablePackageAvailableVersion.uuid,
        )
        .filter(
            and_(
                ActionablePackageAvailableVersion.epss_score <= 0.5,
                ActionablePackageAvailableVersion.epss_score.isnot(None),
                ActionablePackageAvailableVersion.vulns_count > 0,
            )
        )
        .scalar()
        or 0
    )

    repo_no_epss_count = (
        session.query(func.count(distinct(Repository.id)))
        .join(
            Repository_ActionablePackageAvailableVersion,
            Repository.id == Repository_ActionablePackageAvailableVersion.repository_id,
        )
        .join(
            ActionablePackageAvailableVersion,
            Repository_ActionablePackageAvailableVersion.actionable_package_version_id
            == ActionablePackageAvailableVersion.uuid,
        )
        .filter(
            and_(
                ActionablePackageAvailableVersion.epss_score.is_(None),
                ActionablePackageAvailableVersion.vulns_count > 0,
            )
        )
        .scalar()
        or 0
    )

    # Get environment statistics
    env_stats = (
        session.query(
            Repository_ActionablePackageAvailableVersion.environment,
            func.count(
                distinct(Repository_ActionablePackageAvailableVersion.repository_id)
            ).label("repo_count"),
            func.count(
                distinct(
                    Repository_ActionablePackageAvailableVersion.actionable_package_version_id
                )
            ).label("package_count"),
        )
        .group_by(Repository_ActionablePackageAvailableVersion.environment)
        .order_by(Repository_ActionablePackageAvailableVersion.environment)
        .all()
    )

    # Get pod-wise vulnerable packages with EPSS severity buckets - limit to top 20 pods for performance
    pod_stats_query = (
        session.query(
            Repository.pod.label("pod"),
            func.count(distinct(ActionablePackageAvailableVersion.uuid))
            .filter(ActionablePackageAvailableVersion.vulns_count > 0)
            .label("vulnerable_packages"),
            func.count(distinct(ActionablePackageAvailableVersion.uuid))
            .filter(
                and_(
                    ActionablePackageAvailableVersion.vulns_count > 0,
                    ActionablePackageAvailableVersion.epss_score > 0.8,
                )
            )
            .label("p0"),
            func.count(distinct(ActionablePackageAvailableVersion.uuid))
            .filter(
                and_(
                    ActionablePackageAvailableVersion.vulns_count > 0,
                    ActionablePackageAvailableVersion.epss_score > 0.7,
                    ActionablePackageAvailableVersion.epss_score <= 0.8,
                )
            )
            .label("p1"),
            func.count(distinct(ActionablePackageAvailableVersion.uuid))
            .filter(
                and_(
                    ActionablePackageAvailableVersion.vulns_count > 0,
                    ActionablePackageAvailableVersion.epss_score > 0.5,
                    ActionablePackageAvailableVersion.epss_score <= 0.7,
                )
            )
            .label("p2"),
            func.count(distinct(ActionablePackageAvailableVersion.uuid))
            .filter(
                and_(
                    ActionablePackageAvailableVersion.vulns_count > 0,
                    ActionablePackageAvailableVersion.epss_score <= 0.5,
                )
            )
            .label("p3"),
        )
        .join(
            Repository_ActionablePackageAvailableVersion,
            Repository.id == Repository_ActionablePackageAvailableVersion.repository_id,
        )
        .join(
            ActionablePackageAvailableVersion,
            Repository_ActionablePackageAvailableVersion.actionable_package_version_id
            == ActionablePackageAvailableVersion.uuid,
        )
        .filter(Repository.pod.isnot(None))
        .group_by(Repository.pod)
        .order_by(func.count(distinct(ActionablePackageAvailableVersion.uuid)).desc())
        .all()
    )

    # Get organization statistics - simplified for performance
    org_stats = (
        session.query(
            Repository.org,
            func.count(distinct(Repository.id)).label("repo_count"),
        )
        .group_by(Repository.org)
        .order_by(func.count(distinct(Repository.id)).desc())
        .limit(10)
        .all()
    )

    statistics = {
        "package_stats": {
            "total_packages": total_packages,
            "vulnerable_packages": vulnerable_packages,
            "packages_without_vulnerabilities": total_packages - vulnerable_packages,
            "packages_with_epss": packages_with_epss,
            "vulnerability_percentage": round(
                (vulnerable_packages / max(total_packages, 1)) * 100, 1
            ),
            "epss_coverage_percentage": round(
                (packages_with_epss / max(total_packages, 1)) * 100, 1
            ),
            "p0_packages": p0_packages,
            "p1_packages": p1_packages,
            "p2_packages": p2_packages,
            "p3_packages": p3_packages,
            "no_epss_packages": no_epss_packages,
        },
        "vulnerability_stats": {
            "total_vulnerabilities": total_vulnerabilities,
            "critical_vulnerabilities": critical_vulns,
            "high_vulnerabilities": high_vulns,
            "medium_vulnerabilities": medium_vulns,
            "low_vulnerabilities": low_vulns,
            "avg_vulns_per_vulnerable_package": round(
                total_vulnerabilities / max(vulnerable_packages, 1), 2
            ),
        },
        "repository_stats": {
            "total_repositories": total_repositories,
            "repositories_with_vulnerabilities": repositories_with_vulns,
            "repositories_without_vulnerabilities": repositories_without_vulns,
            "vulnerability_percentage": round(
                (repositories_with_vulns / max(total_repositories, 1)) * 100, 1
            ),
            "p0_repositories": repo_p0_count,
            "p1_repositories": repo_p1_count,
            "p2_repositories": repo_p2_count,
            "p3_repositories": repo_p3_count,
            "no_epss_repositories": repo_no_epss_count,
        },
        "environment_stats": [
            {
                "environment": env.environment,
                "repository_count": env.repo_count,
                "package_count": env.package_count,
            }
            for env in env_stats
        ],
        "pod_stats": [
            {
                "pod": row.pod,
                "vulnerable_packages": row.vulnerable_packages,
                "p0": row.p0,
                "p1": row.p1,
                "p2": row.p2,
                "p3": row.p3,
            }
            for row in pod_stats_query
        ],
        "organization_stats": [
            {
                "organization": org.org,
                "repository_count": org.repo_count,
            }
            for org in org_stats
        ],
    }

    return statistics


@actionable.route("/v3/statistics", methods=["GET"])
def statistics_dashboard():
    """
    Display comprehensive statistics about packages, vulnerabilities, and EPSS scores
    """
    try:
        with Session() as session:
            session.execute(text("SET statement_timeout = '30s'"))
            statistics = _compute_statistics(session)
            return render_template("statistics.html", statistics=statistics)

    except Exception as e:
        logger.error(f"Error loading statistics dashboard: {str(e)}")
        # Return a simple error page or redirect to a safe page
        return render_template(
            "statistics.html",
            statistics={
                "package_stats": {"total_packages": 0, "vulnerable_packages": 0},
                "vulnerability_stats": {"total_vulnerabilities": 0},
                "repository_stats": {"total_repositories": 0},
                "environment_stats": [],
                "pod_stats": [],
                "organization_stats": [],
                "error": "Unable to load statistics due to high load. Please try again later.",
            },
        )
