from __future__ import annotations

import logging
from collections import defaultdict

import click

from libinv.cli.cli import cli
from libinv.scio_models import DiscoveredPackage
from libinv.services.scancodeio_client import get_default_client

logger = logging.getLogger(__name__)


def _extract_cves_from_vulns(vulns) -> set[str]:
    """Pull uppercased ``CVE-*`` aliases out of a row's affected_by_vulnerabilities JSON.

    Lifted out so both the HTTP and SQL paths share the same parsing /
    error-logging contract.
    """
    result: set[str] = set()
    for vuln in vulns or []:
        try:
            aliases = vuln.get("aliases", [])
            for alias in aliases:
                if alias.startswith("CVE-"):
                    result.add(alias.upper())
        except (AttributeError, TypeError):
            logger.error(f"Error processing vulnerability data: {vuln}")
    return result


def _bulk_load_sql_packages_by_project(
    session, project_uuids: list[str]
) -> dict[str, list]:
    """Sprint 43.3: bulk SQL fetch + group-by-project_id, factored out of the
    legacy SQL path so ``_collect_cves_for_projects`` stays under cc<10.
    """
    by_project: dict[str, list] = defaultdict(list)
    if not project_uuids:
        return by_project
    rows = (
        session.query(DiscoveredPackage)
        .filter(DiscoveredPackage.project_id.in_(project_uuids))
        .all()
    )
    for pkg in rows:
        by_project[pkg.project_id].append(pkg)
    return by_project


def _collect_cves_for_project_http(http_client, project_uuid: str) -> set[str]:
    """Sprint 43.3: HTTP-path single-project fetch, returns CVEs upper-cased."""
    try:
        ids = http_client.list_cve_ids_for_project(project_uuid)
    except Exception as exc:
        logger.error("HTTP CVE fetch failed for %s: %s", project_uuid, exc)
        return set()
    return {cid.upper() for cid in ids}


def _collect_cves_for_project_sql(by_project: dict[str, list], project_uuid: str) -> set[str]:
    """Sprint 43.3: SQL-path single-project fetch from the pre-grouped dict."""
    result: set[str] = set()
    for pkg in by_project.get(project_uuid, []):
        vulns = getattr(pkg, "affected_by_vulnerabilities", []) or []
        result.update(_extract_cves_from_vulns(vulns))
    return result


def _emit_progress(idx: int, total: int, cve_count: int, last_percent: int) -> int:
    """Sprint 43.3: progress-echo at 5% increments. Returns the new
    ``last_percent`` so the caller can thread it across iterations.
    """
    if not total:
        return last_percent
    percent = int((idx + 1) * 100 / total)
    if percent != last_percent and percent % 5 == 0:
        click.echo(
            f"Progress: {percent}% ({idx+1}/{total}) - "
            f"Found {cve_count} unique CVEs so far",
            nl=True,
        )
        return percent
    return last_percent


def _collect_cves_for_projects(
    session,
    project_uuids: list[str],
    verbose: bool,
) -> set[str]:
    """Return uppercased CVE ids referenced by the given scancode projects.

    Uses the HTTP client when ``LIBINV_SCIO_USE_HTTP`` is set; falls back
    to direct SQL queries on ``DiscoveredPackage`` otherwise. The HTTP
    path raises ``ScancodeioError`` on per-project failure; we log and
    skip rather than abort the whole run.

    Sprint 38.1: the SQL path now issues a single bulk ``WHERE project_id
    IN (:ids)`` query and groups results by ``project_id`` for O(1) lookup,
    eliminating the previous N+1 pattern.

    Sprint 43.3: per-project HTTP/SQL fetch and the progress-emitter were
    extracted to helpers so this function's cyclomatic complexity dropped
    from 13 → < 10. Behavior preserved bit-for-bit.
    """
    cve_set: set[str] = set()
    http_client = get_default_client()
    total = len(project_uuids)
    last_percent = -1

    # SQL bulk fetch: one query for the whole input set, grouped in Python.
    # The HTTP path still issues one call per project because each project
    # corresponds to a distinct upstream endpoint.
    by_project = (
        _bulk_load_sql_packages_by_project(session, project_uuids)
        if http_client is None
        else {}
    )

    for idx, project_uuid in enumerate(project_uuids):
        if http_client is not None:
            cve_set.update(_collect_cves_for_project_http(http_client, project_uuid))
        else:
            cve_set.update(_collect_cves_for_project_sql(by_project, project_uuid))

        last_percent = _emit_progress(idx, total, len(cve_set), last_percent)

    return cve_set


@cli.command("epss-update")
@click.option("--cve", "-c", help="Single CVE ID to update")
@click.option("--cves", "-l", help="Comma-separated list of CVE IDs")
@click.option(
    "--file", "-f", type=click.Path(exists=True), help="File containing CVE IDs (one per line)"
)
@click.option("--verbose", "-v", is_flag=True, help="Verbose output")
@click.option(
    "--all-actionable-cves",
    is_flag=True,
    help="Update EPSS for all unique CVEs from actionable packages",
)
def epss_update(
    cve: str | None,
    cves: str | None,
    file: str | None,
    verbose: bool,
    all_actionable_cves: bool,
) -> None:
    """
    Update or insert EPSS scores for CVEs, only fetching from API if not present or stale (>30 days).

    Sprint 43.1: the multi-step workflow lives in
    ``libinv.services.epss.all_actionable_cves`` so it can be unit-tested
    independently of Click. This command is now a thin delegation shell.
    """
    from libinv.services.epss.all_actionable_cves import run_all_actionable_cves

    run_all_actionable_cves(
        cve=cve,
        cves=cves,
        file=file,
        verbose=verbose,
        all_actionable_cves=all_actionable_cves,
    )


@cli.command("calculate-package-epss")
@click.option("--verbose", "-v", is_flag=True, help="Verbose output")
@click.option(
    "--batch-size", default=100, help="Number of packages to process in each batch (default: 100)"
)
def calculate_package_epss(verbose: bool, batch_size: int) -> None:
    """
    Calculate and populate maximum EPSS scores for actionable packages.

    This command:
    1. Gets all packages from actionable_package_available_version with scan_status='SUCCESS'
    2. For each package, extracts CVEs from scanpipe_discoveredpackage using scancode_project_uuid
    3. Calculates the maximum EPSS score from those CVEs using the epss table
    4. Updates the package record with the max EPSS score

    Sprint 43.2: the multi-step workflow lives in
    ``libinv.services.epss.calculate_package_epss`` so it can be
    unit-tested independently of Click. This command is now a thin
    delegation shell.
    """
    from libinv.services.epss.calculate_package_epss import run_calculate_package_epss

    run_calculate_package_epss(verbose=verbose, batch_size=batch_size)
