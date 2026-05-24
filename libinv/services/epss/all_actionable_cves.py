"""Sprint 43.1 — ``--all-actionable-cves`` workflow extraction.

Previously, the ``epss-update --all-actionable-cves`` Click command in
``libinv/cli/epss.py`` inlined a multi-page workflow:

1. Open a session.
2. Query every distinct ``scancode_project_uuid`` on
   ``ActionablePackageAvailableVersion``.
3. For each project, collect CVE aliases (via the HTTP client or the
   SQL ``DiscoveredPackage`` table).
4. Deduplicate, validate ``CVE-*`` format, and run ``EPSS.refresh_cves``.
5. Print user-facing progress + summary lines.

That mix of CLI ergonomics, ORM access, and external-client orchestration
made the function hard to unit-test without invoking Click's runner and
a real database. This module exposes the workflow as a top-level
function so it can be exercised directly by tests with mocked
dependencies. The CLI command now reduces to option parsing + a single
call into here.

Behavior is preserved bit-for-bit: every echo line, log line, error
path, and return condition matches the pre-extraction code.
"""

from __future__ import annotations

import logging

import click

from libinv.base import Session
from libinv.models import EPSS
from libinv.models import ActionablePackageAvailableVersion

logger = logging.getLogger(__name__)


def run_all_actionable_cves(
    cve: str | None,
    cves: str | None,
    file: str | None,
    verbose: bool,
    all_actionable_cves: bool,
) -> None:
    """Execute the full ``epss-update`` workflow.

    Parameters mirror the CLI command's options 1:1. The function is
    side-effect-only (it echoes progress and writes EPSS rows via
    ``EPSS.refresh_cves``); it does not return a structured result.

    The ``all_actionable_cves`` flag selects the bulk path; otherwise
    ``cve``/``cves``/``file`` are merged into a single CVE list.
    """
    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # The legacy CLI used a deferred import inside the with-block. The
    # extraction keeps the deferral to preserve import-order semantics
    # (some test environments stub libinv.models lazily).
    from libinv.cli.epss import _collect_cves_for_projects

    cve_list: list[str] = []
    if all_actionable_cves:
        click.echo("Collecting all unique CVEs from actionable packages...")
        with Session() as session:
            # First, get all scancode_project_uuid from actionable_package_available_version
            project_uuids = (
                session.query(ActionablePackageAvailableVersion.scancode_project_uuid)
                .filter(ActionablePackageAvailableVersion.scancode_project_uuid.isnot(None))
                .distinct()
                .all()
            )

            project_uuids = [uuid[0] for uuid in project_uuids if uuid[0]]
            click.echo(f"Found {len(project_uuids)} unique scancode project UUIDs.")

            if not project_uuids:
                click.echo(
                    "No scancode project UUIDs found in actionable_package_available_version."
                )
                return

            # Now fetch CVEs from scanpipe_discoveredpackage (or the HTTP
            # client, if LIBINV_SCIO_USE_HTTP is set) using these project IDs.
            cve_set = _collect_cves_for_projects(
                session=session,
                project_uuids=project_uuids,
                verbose=verbose,
            )

            if not cve_set:
                click.echo(
                    "No CVEs found in scanpipe_discoveredpackage for the given project UUIDs."
                )
                return
            cve_list = list(cve_set)
    else:
        # Collect CVE list from other options
        if cve:
            cve_list.append(cve.strip())
        if cves:
            cve_list.extend([c.strip() for c in cves.split(",") if c.strip()])
        if file:
            try:
                with open(file, "r") as f:
                    file_cves = [line.strip() for line in f if line.strip()]
                    cve_list.extend(file_cves)
            except Exception as e:
                logger.error(f"Error reading file {file}: {e}")
                return
        if not cve_list:
            click.echo(
                "Error: No CVEs provided. Use --cve, --cves, --file, or --all-actionable-cves option."
            )
            logger.warning(
                "Error: No CVEs provided. Use --cve, --cves, --file, or --all-actionable-cves option."
            )
            return
    # Remove duplicates and validate format
    unique_cves = list(set(cve_list))
    valid_cves = [c for c in unique_cves if c.upper().startswith("CVE-")]
    invalid_cves = [c for c in unique_cves if not c.upper().startswith("CVE-")]
    if invalid_cves:
        logger.warning(f"Invalid CVE format(s): {invalid_cves}")
    if not valid_cves:
        click.echo("Error: No valid CVE IDs provided.")
        return
    click.echo(f"Checking EPSS data for {len(valid_cves)} CVEs...")
    logger.warning(f"Checking EPSS data for {len(valid_cves)} CVEs...")
    with Session() as session:
        # Use model method to handle all EPSS refresh logic
        result = EPSS.refresh_cves(session, valid_cves, verbose=verbose, logger=logger)

        click.echo(
            f"Updated/inserted {result['updated']} CVEs. "
            f"Skipped {result['skipped']} (already fresh). "
            f"Failed {result['failed']}."
        )
        logger.warning(
            f"Updated/inserted {result['updated']} CVEs. "
            f"Skipped {result['skipped']} (already fresh). "
            f"Failed {result['failed']}."
        )


__all__ = ("run_all_actionable_cves",)
