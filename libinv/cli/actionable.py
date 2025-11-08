import logging
from concurrent.futures import ThreadPoolExecutor

import click

from libinv.base import Session
from libinv.base import conn
from libinv.cli.cli import cli
from libinv.models import Actionable
from libinv.models import ActionablePackageAvailableVersion
from libinv.models import Repository

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


@cli.command
def populate_actionable_purl_versions():
    logger.info(f"[+] Populating actionable purl versions..")

    actionable_packages = conn.query(Actionable).all()
    logger.info(f"Populating versions for {len(actionable_packages)} packages..")

    for package in actionable_packages:
        package.fetch_and_store_versions()


@cli.command
def scan_versions_in_use():
    logger.info(f"[+] Scanning versions in use..")

    packages_in_use = ActionablePackageAvailableVersion.get_packages_in_use()
    logger.info(f"Scanning {len(packages_in_use)} packages..")

    def scan_package(package):
        if package.vulns_count and package.vulns_count > 0:
            logger.info(f"Skipping {package.package_url} as it already has known vulnerabilities.")
            return
        package.scan_and_update_results()

    # Use ThreadPoolExecutor for concurrent scanning
    with ThreadPoolExecutor() as executor:
        executor.map(scan_package, packages_in_use)


@cli.command
def update_latest_version_tag():
    logger.info(f"[+] Tagging latest versions..")

    actionable_packages = conn.query(Actionable).all()
    logger.info(f"Tagging {len(actionable_packages)} packages..")

    for package in actionable_packages:
        package.mark_latest_version()


@cli.command
def scan_latest_versions():
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
    actionable_packages = conn.query(Actionable).all()

    for actionable_package in actionable_packages:
        logger.info(f"Scanning latest version for {actionable_package.package_url}..")
        try:
            versions_in_use = actionable_package.get_versions_in_use(conn)
            for version in versions_in_use:
                if not version.scanned:
                    logger.error(
                        f"Version {version.version} for {actionable_package.package_url} not scanned. Skipping."
                    )

                if version.is_safe:
                    continue

                if version.get_safe_upgrade() is not None:
                    continue

                latest_package = actionable_package.get_latest()
                logger.info(f"Scanning latest version {latest_package.version}")
                latest_package.scan_and_update_results()
        except Exception as e:
            logger.error(f"Error scanning latest version for {actionable_package.package_url}: {e}")


@cli.command
def rescan_failed_packages():
    logger.info(f"[+] Rescanning failed packages..")

    scan_failed_packages = ActionablePackageAvailableVersion.get_scan_failed_packages()
    logger.info(f"Rescanning {len(scan_failed_packages)} packages..")
    for package in scan_failed_packages:
        package.scan_and_update_results()


@cli.command
def populate_next_safe_versions():
    logger.info(f"[+] Finding closest safe version..")

    actionable_packages = conn.query(Actionable).all()
    logger.info(f"Populating next safe version for {len(actionable_packages)} packages..")

    def process_package(package):
        logger.info(f"Finding safe version for {package.package_url}..")
        versions_used = package.get_versions_in_use(conn)

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

            potential_safe_upgrades = package.get_versions_between(version, current_safe_upgrade)

            if len(potential_safe_upgrades) < 2:
                logger.info(
                    f"No other safe upgrades found for {version.version} of {package.package_url}"
                )
                continue

            package.find_safe_version_in(potential_safe_upgrades)

    with ThreadPoolExecutor() as executor:
        executor.map(process_package, actionable_packages)


@cli.command
@click.argument("repository-id", type=int)
@click.argument("environment", type=str)
def get_actionable_for(repository_id, environment):
    from prettytable import PrettyTable

    table = PrettyTable()
    table.field_names = ["Current Package", "Current Version", "Suggested Versions"]

    repository = conn.query(Repository).filter(Repository.id == repository_id).first()
    logger.info(f"[+] Getting actionable purls for {repository.name}..")
    with Session() as session:
        actionable_packages = Actionable.get_actionable(session, repository_id, environment)
        for package in actionable_packages:
            if not package.available_version.is_safe:
                table.add_row(
                    [
                        package.available_version.package_url,
                        package.available_version.version,
                        [
                            package.version
                            for package in package.available_version.actionable.get_safe_versions()
                        ],
                    ]
                )
    print(table)


@cli.command("scan-purl", help="Scan a package url for vulnerabilities")
@click.argument("package-url", type=str)
def scan_package(package_url):
    packages = (
        conn.query(ActionablePackageAvailableVersion)
        .filter(ActionablePackageAvailableVersion.package_url == package_url)
        .all()
    )
    for package in packages:
        logger.info(f"Scanning {package_url}@{package.version}..")
        package.scan_and_update_results()


@cli.command("safe-version", help="Get the safe version for a package url")
@click.argument("version", type=str)
def get_safe_version(package_url):
    packages = (
        conn.query(ActionablePackageAvailableVersion)
        .filter(ActionablePackageAvailableVersion.package_url == package_url)
        .first()
    )
    for package in packages:
        logger.info(package.get_safe_upgrade())


@cli.command("raise-sca-as-git-issue", help="")
@click.argument("git-url", type=str)
def raise_sca_as_git_issue(git_url):
    repo = Repository.get_by_git_url(git_url)
    if not repo:
        return logger.error(f"Couldn't find {git_url} in database")
    repo.raise_or_update_sca_issues()
