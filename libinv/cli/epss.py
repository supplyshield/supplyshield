import logging

import click
from sqlalchemy import func

from libinv.base import Session
from libinv.cli.cli import cli
from libinv.models import EPSS
from libinv.models import ActionablePackageAvailableVersion
from libinv.scio_models import DiscoveredPackage

logger = logging.getLogger(__name__)


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
def epss_update(cve: str, cves: str, file: str, verbose: bool, all_actionable_cves: bool):
    """
    Update or insert EPSS scores for CVEs, only fetching from API if not present or stale (>30 days).
    """
    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    cve_list = []
    if all_actionable_cves:
        click.echo("Collecting all unique CVEs from actionable packages...")
        with Session() as session:
            # First, get all scancode_project_uuid from actionable_package_available_version
            from libinv.models import ActionablePackageAvailableVersion

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

            # Now fetch CVEs from scanpipe_discoveredpackage using these project IDs
            cve_set = set()
            total = len(project_uuids)
            last_percent = -1

            for idx, project_uuid in enumerate(project_uuids):
                discovered = (
                    session.query(DiscoveredPackage)
                    .filter(DiscoveredPackage.project_id == project_uuid)
                    .all()
                )

                for pkg in discovered:
                    vulns = getattr(pkg, "affected_by_vulnerabilities", [])
                    for vuln in vulns:
                        try:
                            aliases = vuln.get("aliases", [])
                            cve_ids = [alias for alias in aliases if alias.startswith("CVE-")]

                            for cve in cve_ids:
                                cve_set.add(cve.upper())
                        except (AttributeError, TypeError):
                            logger.error(f"Error processing vulnerability data: {vuln}")

                percent = int((idx + 1) * 100 / total)
                if percent != last_percent and percent % 5 == 0:
                    click.echo(
                        f"Progress: {percent}% ({idx+1}/{total}) - Found {len(cve_set)} unique CVEs so far",
                        nl=True,
                    )
                    last_percent = percent

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
    valid_cves = [cve for cve in unique_cves if cve.upper().startswith("CVE-")]
    invalid_cves = [cve for cve in unique_cves if not cve.upper().startswith("CVE-")]
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


@cli.command("calculate-package-epss")
@click.option("--verbose", "-v", is_flag=True, help="Verbose output")
@click.option(
    "--batch-size", default=100, help="Number of packages to process in each batch (default: 100)"
)
def calculate_package_epss(verbose: bool, batch_size: int):
    """
    Calculate and populate maximum EPSS scores for actionable packages.

    This command:
    1. Gets all packages from actionable_package_available_version with scan_status='SUCCESS'
    2. For each package, extracts CVEs from scanpipe_discoveredpackage using scancode_project_uuid
    3. Calculates the maximum EPSS score from those CVEs using the epss table
    4. Updates the package record with the max EPSS score
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
