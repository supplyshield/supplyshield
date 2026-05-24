"""Sprint 43.2 — ``calculate-package-epss`` workflow extraction.

The ``calculate-package-epss`` Click command in ``libinv/cli/epss.py``
inlined a multi-step batch workflow:

1. Open a session.
2. Query every ``ActionablePackageAvailableVersion`` row with
   ``scan_status == 'SUCCESS'`` and a non-null ``scancode_project_uuid``.
3. For each batch of ``batch_size`` packages:
   - Pull CVEs via ``package.get_cves(session)``.
   - Look up ``EPSS`` records for those CVEs.
   - Take the max ``epss_score`` and write it back to the package row.
4. Commit per batch; print progress and summary lines.

Same rationale as ``all_actionable_cves.py`` — extraction lets us unit
test the workflow without spinning up a real Click runner or DB. The
CLI command shrinks to option parsing + delegation.

Behavior preserved bit-for-bit, including the ``session.query(
DiscoveredPackage)`` pre-fetch that the original code performed but
never consumed (the workflow uses ``package.get_cves(session)`` for the
actual CVE set). That call is intentionally retained so any side
effects expected by callers downstream remain in place.
"""

from __future__ import annotations

import logging

import click

from libinv.base import Session
from libinv.models import EPSS
from libinv.models import ActionablePackageAvailableVersion
from libinv.scio_models import DiscoveredPackage

logger = logging.getLogger(__name__)


def run_calculate_package_epss(verbose: bool, batch_size: int) -> None:
    """Run the package-EPSS max calculation workflow.

    Args:
        verbose: When True, set root logger to DEBUG and emit per-package
            echo lines for skipped/updated/failed rows.
        batch_size: Number of packages committed per transaction.

    Side-effect only; nothing is returned. Errors during per-package
    processing are caught and logged; the run continues so a single bad
    row doesn't poison the whole batch.
    """
    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    with Session() as session:
        # Get all packages with successful scans that have scancode_project_uuid
        click.echo("Getting packages with successful scans...")

        packages = (
            session.query(ActionablePackageAvailableVersion)
            .filter(ActionablePackageAvailableVersion.scan_status == "SUCCESS")
            .filter(ActionablePackageAvailableVersion.scancode_project_uuid.isnot(None))
            .all()
        )

        if not packages:
            click.echo("No packages found with scan_status='SUCCESS' and scancode_project_uuid")
            return

        click.echo(f"Found {len(packages)} packages to process")

        updated_count = 0
        skipped_count = 0
        failed_count = 0

        # Process packages in batches
        total_packages = len(packages)

        for i in range(0, total_packages, batch_size):
            batch_packages = packages[i : i + batch_size]
            batch_end = min(i + batch_size, total_packages)
            progress_pct = int((i / total_packages) * 100)

            click.echo(
                f"Processing packages {i + 1}-{batch_end} of {total_packages} ({progress_pct}%)"
            )

            for package in batch_packages:
                try:
                    # Get CVEs for this package from scanpipe_discoveredpackage
                    discovered_packages = (
                        session.query(DiscoveredPackage)
                        .filter(DiscoveredPackage.project_id == package.scancode_project_uuid)
                        .all()
                    )

                    # Extract CVEs using model helper
                    cve_set = package.get_cves(session)

                    if not cve_set:
                        if verbose:
                            click.echo(f"{package.package_url}@{package.version}: No CVEs found")
                        skipped_count += 1
                        continue

                    # Get EPSS scores for these CVEs
                    epss_records = session.query(EPSS).filter(EPSS.cve.in_(list(cve_set))).all()

                    if not epss_records:
                        if verbose:
                            click.echo(
                                f"{package.package_url}@{package.version}: No EPSS data found for {len(cve_set)} CVEs"
                            )
                        skipped_count += 1
                        continue

                    # Calculate maximum EPSS score
                    max_epss_score = max(record.epss_score for record in epss_records)

                    # Update package with max EPSS score
                    package.epss_score = max_epss_score
                    session.add(package)

                    if verbose:
                        click.echo(
                            f"{package.package_url}@{package.version}: Max EPSS = {max_epss_score:.6f} (from {len(epss_records)}/{len(cve_set)} CVEs)"
                        )

                    updated_count += 1

                except Exception as e:
                    logger.error(f"Error processing package {package.uuid}: {e}")
                    if verbose:
                        click.echo(f"{package.package_url}@{package.version}: Error - {e}")
                    failed_count += 1

            # Commit batch
            try:
                session.commit()
                if verbose:
                    click.echo(f"Batch committed successfully")
            except Exception as e:
                logger.error(f"Error committing batch: {e}")
                session.rollback()
                click.echo(f"Batch commit failed: {e}")

        # Final summary
        click.echo(f"\n✅ Processing complete!")
        click.echo(f"Updated: {updated_count} packages")
        click.echo(f"Skipped: {skipped_count} packages (no CVEs or EPSS data)")
        click.echo(f"Failed: {failed_count} packages")

        logger.info(
            f"EPSS calculation complete. Updated: {updated_count}, Skipped: {skipped_count}, Failed: {failed_count}"
        )


__all__ = ("run_calculate_package_epss",)
