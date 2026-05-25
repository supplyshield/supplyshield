from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor

import click

from libinv.base import ScopedSession
from libinv.base import session_scope
from libinv.cli.cli import cli
from libinv.models import Actionable
from libinv.models import ActionablePackageAvailableVersion
from libinv.models import Repository

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


@cli.command
def populate_actionable_purl_versions() -> None:
    logger.info(f"[+] Populating actionable purl versions..")

    with session_scope() as session:
        actionable_packages = session.query(Actionable).all()
        logger.info(f"Populating versions for {len(actionable_packages)} packages..")

        for package in actionable_packages:
            # Sprint 48.1: ``session`` is now required (keyword-only). Per-row
            # commits inside the model method may commit this outer
            # session_scope early — pre-existing behavior, not introduced by
            # this migration.
            package.fetch_and_store_versions(session=session)


@cli.command
def scan_versions_in_use() -> None:
    logger.info(f"[+] Scanning versions in use..")

    packages_in_use = ActionablePackageAvailableVersion.get_packages_in_use()
    logger.info(f"Scanning {len(packages_in_use)} packages..")

    def scan_package(package: ActionablePackageAvailableVersion) -> None:
        try:
            if package.vulns_count and package.vulns_count > 0:
                logger.info(
                    f"Skipping {package.package_url} as it already has known vulnerabilities."
                )
                return
            # Sprint 48.1: pass the thread's scoped session explicitly.
            package.scan_and_update_results(session=ScopedSession())
        finally:
            # Worker-thread session isolation (Sprint 0). Do NOT wrap the
            # outer executor in session_scope — that would bind the
            # dispatcher thread's session to the entire executor lifetime.
            ScopedSession.remove()

    # Use ThreadPoolExecutor for concurrent scanning
    # Cap at 4 to avoid SQLAlchemy pool starvation (post-Sprint-35 pool_size=10).
    with ThreadPoolExecutor(max_workers=4) as executor:
        executor.map(scan_package, packages_in_use)


@cli.command
def update_latest_version_tag() -> None:
    logger.info(f"[+] Tagging latest versions..")

    with session_scope() as session:
        actionable_packages = session.query(Actionable).all()
        logger.info(f"Tagging {len(actionable_packages)} packages..")

        for package in actionable_packages:
            package.mark_latest_version()


@cli.command
def scan_latest_versions() -> None:
    """
    Scan the latest version for all actionable package that do not have a known safe version from previous scan.
    Case 1:
        1.2 Vulnerable
        1.3
        1.4 Not Vulnerable
        1.5
        1.6 Latest

        - In this case, we do not scan latest as there is a known safe version available in between.

    Case 2:
        1.2 Not Vulnerable
        1.3
        1.4 Vulnerable
        1.5
        1.6 Vulnerable
        1.7 Latest

        - In this case, we scan 1.7 as there is no known safe version available in between.
    """
    logger.info(f"[+] Scanning latest versions..")

    with session_scope() as session:
        actionable_packages = session.query(Actionable).all()

        for actionable_package in actionable_packages:
            logger.info(f"Scanning latest version for {actionable_package.package_url}..")
            try:
                versions_in_use = actionable_package.get_versions_in_use(session)
                for version in versions_in_use:
                    if not version.scanned:
                        logger.error(
                            f"Version {version.version} for {actionable_package.package_url} not scanned. Skipping."
                        )

                    if version.is_safe:
                        continue

                    if version.get_safe_upgrade() is not None:
                        continue

                    # Sprint 48.1: pass the outer session_scope().
                    latest_package = actionable_package.get_latest(session=session)
                    if latest_package is None:
                        logger.warning(
                            f"No latest version found for {actionable_package.package_url}. Skipping."
                        )
                        continue
                    logger.info(f"Scanning latest version {latest_package.version}")
                    latest_package.scan_and_update_results(session=session)
            except Exception as e:
                logger.error(f"Error scanning latest version for {actionable_package.package_url}: {e}")


@cli.command
def rescan_failed_packages() -> None:
    logger.info(f"[+] Rescanning failed packages..")

    with session_scope() as session:
        scan_failed_packages = ActionablePackageAvailableVersion.get_scan_failed_packages()
        logger.info(f"Rescanning {len(scan_failed_packages)} packages..")
        for package in scan_failed_packages:
            # Sprint 48.1: pass the outer session_scope().
            package.scan_and_update_results(session=session)


@cli.command
def populate_next_safe_versions() -> None:
    logger.info(f"[+] Finding closest safe version..")

    # Fetch the package list under a short-lived session_scope so the
    # dispatcher thread's session is released before workers start. Each
    # worker manages its own scoped session via the finally block below.
    with session_scope() as session:
        actionable_packages = session.query(Actionable).all()
    logger.info(f"Populating next safe version for {len(actionable_packages)} packages..")

    def process_package(package: Actionable) -> None:
        try:
            logger.info(f"Finding safe version for {package.package_url}..")
            # `package` was loaded in the dispatcher's now-closed session.
            # Model methods reach the scoped session via `conn` (per-thread),
            # so reads here use this worker thread's fresh session. Passing
            # the `ScopedSession` proxy preserves original-call semantics —
            # query() is proxied to the per-thread Session.
            versions_used = package.get_versions_in_use(ScopedSession)

            logger.info(f"Found {len(versions_used)} versions in use..")

            for version in versions_used:
                if version.is_safe:
                    logger.info("Version is already safe. Skipping..")
                    continue

                current_safe_upgrade = version.get_safe_upgrade()
                if current_safe_upgrade is None:
                    logger.error(
                        f"No safe upgrade found for {version.version} of {package.package_url}"
                    )
                    continue

                potential_safe_upgrades = package.get_versions_between(
                    version, current_safe_upgrade
                )

                if len(potential_safe_upgrades) < 2:
                    logger.info(
                        f"No other safe upgrades found for {version.version} of {package.package_url}"
                    )
                    continue

                # Sprint 48.1: pass the worker's scoped session.
                package.find_safe_version_in(
                    potential_safe_upgrades, session=ScopedSession()
                )
        finally:
            # Worker-thread session isolation (Sprint 0).
            ScopedSession.remove()

    # Cap at 4 to avoid SQLAlchemy pool starvation (post-Sprint-35 pool_size=10).
    with ThreadPoolExecutor(max_workers=4) as executor:
        executor.map(process_package, actionable_packages)


@cli.command
@click.argument("repository-id", type=int)
@click.argument("environment", type=str)
def get_actionable_for(repository_id: int, environment: str) -> None:
    from prettytable import PrettyTable

    table = PrettyTable()
    table.field_names = ["Current Package", "Current Version", "Suggested Versions"]

    with session_scope() as session:
        repository = session.query(Repository).filter(Repository.id == repository_id).first()
        if repository is None:
            logger.error(f"Repository with id={repository_id} not found.")
            return
        logger.info(f"[+] Getting actionable purls for {repository.name}..")
        actionable_packages = Actionable.get_actionable(session, repository_id, environment)
        for package in actionable_packages:
            if not package.available_version.is_safe:
                table.add_row(
                    [
                        package.available_version.package_url,
                        package.available_version.version,
                        [
                            package.version
                            for package in package.available_version.actionable.get_safe_versions(
                                session=session
                            )
                        ],
                    ]
                )
    click.echo(table)


@cli.command("scan-purl", help="Scan a package url for vulnerabilities")
@click.argument("package-url", type=str)
def scan_package(package_url: str) -> None:
    with session_scope() as session:
        packages = (
            session.query(ActionablePackageAvailableVersion)
            .filter(ActionablePackageAvailableVersion.package_url == package_url)
            .all()
        )
        for package in packages:
            logger.info(f"Scanning {package_url}@{package.version}..")
            # Sprint 48.1: pass the outer session_scope().
            package.scan_and_update_results(session=session)


@cli.command("safe-version", help="Get the safe version for a package url")
@click.argument("version", type=str)
def get_safe_version(package_url: str) -> None:
    with session_scope() as session:
        package = (
            session.query(ActionablePackageAvailableVersion)
            .filter(ActionablePackageAvailableVersion.package_url == package_url)
            .first()
        )
        if package is None:
            logger.error(f"No package found for package_url={package_url}.")
            return
        logger.info(package.get_safe_upgrade())


@cli.command("raise-sca-as-git-issue", help="")
@click.argument("git-url", type=str)
def raise_sca_as_git_issue(git_url: str) -> None:
    with session_scope() as session:
        repo = Repository.get_by_git_url(git_url, session=session)
        if not repo:
            return logger.error(f"Couldn't find {git_url} in database")
        repo.raise_or_update_sca_issues(session=session)
