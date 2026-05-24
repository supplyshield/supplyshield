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
    """
    cve_set: set[str] = set()
    http_client = get_default_client()
    total = len(project_uuids)
    last_percent = -1

    # SQL bulk fetch: one query for the whole input set, grouped in Python.
    # The HTTP path still issues one call per project because each project
    # corresponds to a distinct upstream endpoint.
    by_project: dict[str, list] = defaultdict(list)
    if http_client is None and project_uuids:
        rows = (
            session.query(DiscoveredPackage)
            .filter(DiscoveredPackage.project_id.in_(project_uuids))
            .all()
        )
        for pkg in rows:
            by_project[pkg.project_id].append(pkg)

    for idx, project_uuid in enumerate(project_uuids):
        if http_client is not None:
            # HTTP path: replaces the inner SQL+loop with one call.
            try:
                ids = http_client.list_cve_ids_for_project(project_uuid)
                cve_set.update(cid.upper() for cid in ids)
            except Exception as exc:
                logger.error(
                    "HTTP CVE fetch failed for %s: %s", project_uuid, exc
                )
        else:
            # Legacy SQL path: O(1) lookup into the pre-grouped dict.
            for pkg in by_project.get(project_uuid, []):
                vulns = getattr(pkg, "affected_by_vulnerabilities", []) or []
                cve_set.update(_extract_cves_from_vulns(vulns))

        if total:
            percent = int((idx + 1) * 100 / total)
            if percent != last_percent and percent % 5 == 0:
                click.echo(
                    f"Progress: {percent}% ({idx+1}/{total}) - "
                    f"Found {len(cve_set)} unique CVEs so far",
                    nl=True,
                )
                last_percent = percent

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
