from concurrent.futures import ThreadPoolExecutor
from typing import Any
from typing import Callable
from typing import Dict

from flask import render_template
from sqlalchemy import and_
from sqlalchemy import distinct
from sqlalchemy import func

from libinv import logger
from libinv.base import Session
from libinv.base import session_scope
from libinv.models import ActionablePackageAvailableVersion
from libinv.models import Repository
from libinv.models import RepositoryActionablePackageAvailableVersion

from libinv.api.actionable import actionable


def _compute_package_stats(session) -> Dict[str, Any]:
    """Aggregate package + vulnerability rollups + EPSS bucket counts.

    Emits two aggregates and combines them in Python:

      * The first-row aggregate over ``ActionablePackageAvailableVersion``
        yielding ``total_packages``, ``vulnerable_packages``,
        ``packages_with_epss``, and ``total_vulnerabilities``.

      * The five-bucket P0/P1/P2/P3/no_epss ``COUNT(*) FILTER (WHERE ...)``
        aggregate (one row, five columns).

    Returns a dict with the two top-level keys ``package_stats`` and
    ``vulnerability_stats`` — they're computed together because both depend
    on the same first-row aggregate over the APAV table.
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

    total_packages = package_stats.total_packages or 0
    vulnerable_packages = package_stats.vulnerable_packages or 0
    packages_with_epss = package_stats.packages_with_epss or 0
    total_vulnerabilities = package_stats.total_vulnerabilities or 0

    p0_packages = bucket_row.p0 or 0
    p1_packages = bucket_row.p1 or 0
    p2_packages = bucket_row.p2 or 0
    p3_packages = bucket_row.p3 or 0
    no_epss_packages = bucket_row.no_epss or 0

    return {
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
            # For now, skip detailed severity statistics to avoid performance issues
            # TODO: Implement more efficient severity calculation if needed
            "critical_vulnerabilities": 0,
            "high_vulnerabilities": 0,
            "medium_vulnerabilities": 0,
            "low_vulnerabilities": 0,
            "avg_vulns_per_vulnerable_package": round(
                total_vulnerabilities / max(vulnerable_packages, 1), 2
            ),
        },
    }


def _compute_repository_stats(session) -> Dict[str, Any]:
    """Aggregate repository totals + per-bucket repository counts.

    Emits two statements:
      * ``COUNT(DISTINCT Repository.id)`` for total_repositories.
      * Single filter-aggregate joining Repository → join-table → APAV
        yielding ``with_vulns`` + per-bucket repo counts.

    ``select_from(Repository)`` is required on the filter-aggregate: the
    aggregate columns only reference Repository.id *inside* a
    ``func.count(distinct(...))``, so without an explicit ``select_from``
    SQLAlchemy infers the FROM clause from the columns and the JOIN target
    becomes ambiguous, producing "missing FROM-clause entry for table
    'repositories'" at the database. Sprint 30 surfaced this bug after
    pytest-postgresql gave the integration tests a real DB.
    """
    total_repositories = session.query(func.count(distinct(Repository.id))).scalar() or 0

    repo_bucket_row = (
        session.query(
            func.count(distinct(Repository.id))
            .filter(ActionablePackageAvailableVersion.vulns_count > 0)
            .label("with_vulns"),
            func.count(distinct(Repository.id))
            .filter(
                and_(
                    ActionablePackageAvailableVersion.epss_score > 0.8,
                    ActionablePackageAvailableVersion.vulns_count > 0,
                )
            )
            .label("repo_p0"),
            func.count(distinct(Repository.id))
            .filter(
                and_(
                    ActionablePackageAvailableVersion.epss_score > 0.7,
                    ActionablePackageAvailableVersion.epss_score <= 0.8,
                    ActionablePackageAvailableVersion.vulns_count > 0,
                )
            )
            .label("repo_p1"),
            func.count(distinct(Repository.id))
            .filter(
                and_(
                    ActionablePackageAvailableVersion.epss_score > 0.5,
                    ActionablePackageAvailableVersion.epss_score <= 0.7,
                    ActionablePackageAvailableVersion.vulns_count > 0,
                )
            )
            .label("repo_p2"),
            func.count(distinct(Repository.id))
            .filter(
                and_(
                    ActionablePackageAvailableVersion.epss_score <= 0.5,
                    ActionablePackageAvailableVersion.epss_score.isnot(None),
                    ActionablePackageAvailableVersion.vulns_count > 0,
                )
            )
            .label("repo_p3"),
            func.count(distinct(Repository.id))
            .filter(
                and_(
                    ActionablePackageAvailableVersion.epss_score.is_(None),
                    ActionablePackageAvailableVersion.vulns_count > 0,
                )
            )
            .label("repo_no_epss"),
        )
        .select_from(Repository)
        .join(
            RepositoryActionablePackageAvailableVersion,
            Repository.id == RepositoryActionablePackageAvailableVersion.repository_id,
        )
        .join(
            ActionablePackageAvailableVersion,
            RepositoryActionablePackageAvailableVersion.actionable_package_version_id
            == ActionablePackageAvailableVersion.uuid,
        )
        .one()
    )

    repositories_with_vulns = repo_bucket_row.with_vulns or 0
    repo_p0_count = repo_bucket_row.repo_p0 or 0
    repo_p1_count = repo_bucket_row.repo_p1 or 0
    repo_p2_count = repo_bucket_row.repo_p2 or 0
    repo_p3_count = repo_bucket_row.repo_p3 or 0
    repo_no_epss_count = repo_bucket_row.repo_no_epss or 0

    repositories_without_vulns = total_repositories - repositories_with_vulns

    return {
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
        }
    }


def _compute_environment_stats(session) -> Dict[str, Any]:
    """Aggregate per-environment repo + package counts.

    Single GROUP BY on the join table — already efficient before Sprint 36.
    """
    env_stats = (
        session.query(
            RepositoryActionablePackageAvailableVersion.environment,
            func.count(
                distinct(RepositoryActionablePackageAvailableVersion.repository_id)
            ).label("repo_count"),
            func.count(
                distinct(
                    RepositoryActionablePackageAvailableVersion.actionable_package_version_id
                )
            ).label("package_count"),
        )
        .group_by(RepositoryActionablePackageAvailableVersion.environment)
        .order_by(RepositoryActionablePackageAvailableVersion.environment)
        .all()
    )

    return {
        "environment_stats": [
            {
                "environment": env.environment,
                "repository_count": env.repo_count,
                "package_count": env.package_count,
            }
            for env in env_stats
        ]
    }


def _compute_pod_stats(session) -> Dict[str, Any]:
    """Aggregate per-pod vulnerable-package counts bucketed by EPSS severity.

    Limited to the top-20 pods by vulnerable_packages desc. ``select_from(
    Repository)`` is required for the same reason it is on the repository
    bucket aggregate above (see ``_compute_repository_stats`` docstring).
    """
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
        .select_from(Repository)
        .join(
            RepositoryActionablePackageAvailableVersion,
            Repository.id == RepositoryActionablePackageAvailableVersion.repository_id,
        )
        .join(
            ActionablePackageAvailableVersion,
            RepositoryActionablePackageAvailableVersion.actionable_package_version_id
            == ActionablePackageAvailableVersion.uuid,
        )
        .filter(Repository.pod.isnot(None))
        .group_by(Repository.pod)
        .order_by(func.count(distinct(ActionablePackageAvailableVersion.uuid)).desc())
        .limit(20)
        .all()
    )

    return {
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
        ]
    }


def _compute_organization_stats(session) -> Dict[str, Any]:
    """Aggregate per-org repository counts, top-10 by repo_count desc."""
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

    return {
        "organization_stats": [
            {
                "organization": org.org,
                "repository_count": org.repo_count,
            }
            for org in org_stats
        ]
    }


# Registry of per-group helpers used by the parallel dispatcher. The keys
# are stable labels useful for logging / correlating failures across
# threads; the dispatcher itself doesn't depend on key ordering.
_GROUP_HELPERS: Dict[str, Callable[[Any], Dict[str, Any]]] = {
    "package": _compute_package_stats,
    "repository": _compute_repository_stats,
    "environment": _compute_environment_stats,
    "pod": _compute_pod_stats,
    "organization": _compute_organization_stats,
}


def _compute_statistics(session) -> Dict[str, Any]:
    """Run the aggregate queries that power /v3/statistics.

    Sprint 36.1 decomposed the monolithic implementation into per-group
    helpers (``_compute_<group>_stats``). Sprint 36.2 parallelized the five
    helpers via a ``ThreadPoolExecutor(max_workers=3)`` so the slowest
    aggregate sets the wall-clock latency rather than the *sum* of all five.

    Each worker thread opens its own SQLAlchemy session via
    ``session_scope()`` — SQLAlchemy sessions are not safe to share across
    threads, and a single connection can only run one statement at a time
    anyway.

    The ``session`` argument supplied here is used in two cases:
      * Tests pass a function-scoped session bound to a rolled-back
        connection (see ``tests/integration/conftest.py:db_session``); data
        seeded in that session is INVISIBLE to a thread that opens its own
        session because the outer transaction hasn't committed. We detect
        this and fall back to running every helper serially on the
        caller's session.
      * Production callers (``statistics_dashboard``) pass a session bound
        to the global engine. Worker threads opening their own
        ``session_scope()`` see committed rows fine, so parallelization is
        safe.

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
    use_parallel = _should_use_parallel(session)

    if not use_parallel:
        result: Dict[str, Any] = {}
        for helper in _GROUP_HELPERS.values():
            result.update(helper(session))
        return result

    # Parallel path: fan out helpers across the executor, each with its
    # own session.
    result = {}
    with ThreadPoolExecutor(max_workers=3) as ex:
        futures = {
            name: ex.submit(_run_helper_with_own_session, helper)
            for name, helper in _GROUP_HELPERS.items()
        }
        for name, future in futures.items():
            result.update(future.result())
    return result


def _should_use_parallel(session) -> bool:
    """Return True iff the caller's session is the production scoped session.

    Tests pass a function-scoped Session bound to a transaction-rolled-back
    connection (see ``tests/integration/conftest.py:db_session``). Worker
    threads opening their own ``session_scope()`` cannot see uncommitted
    seeded data in that connection — the parallel path would observe an
    empty DB and break the fixtures.

    Production callers (``statistics_dashboard``) use the module-level
    ``Session()`` bound to the global engine; worker threads opening
    ``session_scope()`` see committed rows fine, so parallelization is
    safe.

    Heuristic: a session whose bind is the GLOBAL engine
    (``libinv.base.engine``) is safe to parallelize away from. Anything
    else is a custom test fixture — run serially.
    """
    try:
        from libinv.base import engine as global_engine

        return session.get_bind() is global_engine
    except Exception:
        # Defensive: if the session is in an odd state, fall back to
        # serial — correctness over latency for an interactive dashboard.
        return False


def _run_helper_with_own_session(helper: Callable[[Any], Dict[str, Any]]) -> Dict[str, Any]:
    """Invoke ``helper`` inside its own ``session_scope()``.

    Worker-thread entry point: each ThreadPoolExecutor task opens a fresh
    SQLAlchemy session (via the scoped session factory), runs its helper,
    and lets ``session_scope()`` commit/rollback + remove the session at
    teardown. The helpers are read-only, so the commit is a no-op — we use
    ``session_scope()`` for its thread-local cleanup discipline, not for
    transaction semantics.
    """
    with session_scope() as s:
        return helper(s)


@actionable.route("/v3/statistics", methods=["GET"])
def statistics_dashboard():
    """
    Display comprehensive statistics about packages, vulnerabilities, and EPSS scores
    """
    try:
        with Session() as session:
            # Sprint 35.2 — statement_timeout is now set globally via the
            # Flask `before_request` hook in `libinv.api.app`, so the
            # per-route SET that used to live here is redundant.
            statistics = _compute_statistics(session)
            return render_template("statistics.html", statistics=statistics)

    except Exception:
        # Log full stack trace server-side; never leak str(e) to the user
        # (a stringified DB error can disclose schema details or credentials).
        logger.exception("statistics_dashboard failed")
        # Preserve the rendered-template UX (the dashboard still displays
        # a friendly error banner via the "error" key) but signal failure
        # with HTTP 500 so callers / monitoring see it as a real error.
        rendered = render_template(
            "statistics.html",
            statistics={
                "package_stats": {"total_packages": 0, "vulnerable_packages": 0},
                "vulnerability_stats": {"total_vulnerabilities": 0},
                "repository_stats": {"total_repositories": 0},
                "environment_stats": [],
                "pod_stats": [],
                "organization_stats": [],
                "error": "An error occurred. Check server logs.",
            },
        )
        return rendered, 500
