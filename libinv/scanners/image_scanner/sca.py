import datetime
import json

from sqlalchemy.exc import IntegrityError
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session as OrmSession
from sqlalchemy.orm import selectinload
from tqdm import tqdm
from tqdm.contrib.logging import logging_redirect_tqdm

from libinv.env import GRYPE_BIN
from libinv.helpers import retry_on_exception
from libinv.helpers import subprocess_run
from libinv.models import Image
from libinv.models import ImagePackageAssociation
from libinv.models import Package
from libinv.models import Vulnerability
from libinv.models import VulnerabilityFixVersion
from libinv.models import VulnerabilityPackageAssociation
from libinv.models import VulnerabilityRelatedCve
from libinv.scanners.image_scanner.exceptions import SCADependencyException
from libinv.scanners.image_scanner.logger import logger


def generate_sca_from_sbom(sbom_filename: str):
    logger.info("Generating SCA")
    sca = subprocess_run([GRYPE_BIN, "-q", sbom_filename, "-o", "json"]).stdout
    sca_filename = "sca.json"
    with open(sca_filename, "w") as f:
        f.write(sca)
    logger.info(f"{sca_filename} created")
    return sca_filename


@retry_on_exception(SCADependencyException)
@retry_on_exception(IntegrityError)
@retry_on_exception(OperationalError, count=6)
def parse_sca_with_image(session: OrmSession, sca_filename: str, image: Image):
    with open(sca_filename, "r", encoding="UTF-8") as sca_file:
        sca_json = json.load(sca_file)
    matches = sca_json["matches"]

    ts0 = datetime.datetime.now()
    image_filter = {
        "id": image.id,
        "name": image.name,
        "account_id": image.account_id,
        "platform": image.platform,
    }
    image = (
        session.query(Image)
        .options(
            selectinload(Image.packages)
            .selectinload(ImagePackageAssociation.package)
            .selectinload(Package.vulnerabilities)
            .selectinload(VulnerabilityPackageAssociation.vulnerability)
        )
        .filter_by(**image_filter)
        .one_or_none()
    )
    if not image:
        raise SCADependencyException(f"Image not found with filter: {image_filter}")

    for match in tqdm(matches):
        try:
            vuln, db_updated = process_sca_match_for_image(
                session=session, image=image, match=match
            )
        except SCADependencyException:
            # TODO: Handle this properly. This might happen when another instance of libinv
            # altered this particular package so that it no longer exists in db but is present
            # in sca.json
            raise
        except IntegrityError:
            # This happens when two libinv instances picked the same image
            session.rollback()
            raise
        except OperationalError:
            # This happens when there's a deadlock
            session.rollback()
            raise

        with logging_redirect_tqdm():
            if db_updated:
                logger.debug(f"Updated: {image} for vuln {vuln}")
            else:
                logger.debug(f"Existing: {image} already has {vuln}")

    try:
        logger.debug("Committing")
        session.commit()
        ts1 = datetime.datetime.now()
        logger.debug(f"in db {ts1 - ts0}")
        logger.info("SCA: pushing to DB done")
    except OperationalError:
        # This happens when there's a deadlock
        session.rollback()
        raise
    except IntegrityError:
        # This happens when two libinv instances picked the same image
        session.rollback()
        raise


def process_sca_match_for_image(session: OrmSession, image, match):
    artifact = match["artifact"]
    if artifact["purl"]:
        package_filter = {"purl": artifact["purl"]}
    else:
        package_filter = {
            "name": artifact["name"],
            "version": artifact["version"],
            "language": artifact["language"],
        }
    # Avoid database call
    # This does mean that we need to do lookup in python
    # Which would be faster as we've already selectload while fetching image
    # package = filter_model_collection(image.packages, package_filter)[0]
    # This is not working currently
    package = session.query(Package).filter_by(**package_filter).one_or_none()
    if not package:
        raise SCADependencyException(f"Package not found in image: {package_filter}")

    vuln = match["vulnerability"]
    fix_version_list = [v for v in vuln["fix"]["versions"] if v]
    fix = ",".join(fix_version_list)
    related_cve_ids = [v["id"] for v in match.get("relatedVulnerabilities") if v.get("id")]
    cvss_list = extract_first_nvd_cvss(match)
    if cvss_list:
        cvss = cvss_list[0]
    else:
        cvss = None

    # This is efficient because .get uses identity map by default
    vulnerability = session.get(Vulnerability, vuln["id"])
    if not vulnerability:
        vulnerability = Vulnerability(id=vuln["id"])
        session.add(vulnerability)

    vulnerability.set_description(vuln.get("description"))
    vulnerability.severity = vuln.get("severity")
    # Sprint 46.2: keep the legacy comma-separated column populated for
    # readers that have not yet migrated to ``.related_cves``; the new
    # relational table is the canonical source going forward.
    vulnerability.related = ",".join(related_cve_ids)
    _sync_vulnerability_related_cves(session, vulnerability, related_cve_ids)
    if cvss:
        vulnerability.nvd_cvss_base_score = cvss["metrics"]["baseScore"]
        vulnerability.nvd_cvss_exploitability_score = cvss["metrics"]["exploitabilityScore"]
        vulnerability.nvd_cvss_impact_score = cvss["metrics"]["impactScore"]

    association = session.get(
        VulnerabilityPackageAssociation,
        {
            "package_id": package.id,
            "vulnerability_id": vulnerability.id,
        },
    )
    if not association:
        association = VulnerabilityPackageAssociation(
            package_id=package.id, vulnerability_id=vulnerability.id
        )
        session.add(association)
    # Sprint 46.1: keep the legacy comma-separated column populated for
    # readers that have not yet migrated to ``.fix_versions``; the new
    # relational table is the canonical source going forward.
    association.fix = fix
    _sync_vulnerability_fix_versions(session, association, fix_version_list)

    if session.is_modified(association) or session.is_modified(vulnerability) or session.new:
        return vulnerability, True

    return vulnerability, False


def _sync_vulnerability_fix_versions(session, association, fix_version_list):
    """Sprint 46.1: replace ``association.fix_versions`` with the given list.

    Existing rows whose ``fix_version`` matches the new payload are
    kept; others are removed. New tokens are inserted. The UNIQUE
    constraint on (vulnerability_id, package_id, fix_version) guards
    against duplicates.
    """
    desired = {v.strip() for v in fix_version_list if v and v.strip()}
    existing = {row.fix_version: row for row in association.fix_versions}

    for stale in set(existing) - desired:
        association.fix_versions.remove(existing[stale])
    for new_version in desired - set(existing):
        association.fix_versions.append(
            VulnerabilityFixVersion(
                vulnerability_id=association.vulnerability_id,
                package_id=association.package_id,
                fix_version=new_version,
            )
        )


def _sync_vulnerability_related_cves(session, vulnerability, related_cve_ids):
    """Sprint 46.2: replace ``vulnerability.related_cves`` with the given ids.

    Same idempotent-replace strategy as ``_sync_vulnerability_fix_versions``.
    """
    desired = {cve.strip() for cve in related_cve_ids if cve and cve.strip()}
    existing = {row.related_cve_id: row for row in vulnerability.related_cves}

    for stale in set(existing) - desired:
        vulnerability.related_cves.remove(existing[stale])
    for new_cve in desired - set(existing):
        vulnerability.related_cves.append(
            VulnerabilityRelatedCve(related_cve_id=new_cve)
        )


def extract_first_nvd_cvss(match: dict):
    vuln = match["vulnerability"]
    vuln_id = vuln["id"]
    if "nvd.nist.gov" in vuln.get("dataSource"):
        return vuln["cvss"]

    related = match["relatedVulnerabilities"]
    for vuln in related:
        if "nvd.nist.gov" in vuln.get("dataSource") and vuln.get("id") == vuln_id:
            return vuln["cvss"]
