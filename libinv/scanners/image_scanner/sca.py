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
from libinv.models import VulnerabilityPackageAssociation
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
        print("[+] SCA: pushing to DB done")
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
    fix = ",".join(vuln["fix"]["versions"])
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

    vulnerability.set_desciption(vuln.get("description"))
    vulnerability.severity = vuln.get("severity")
    vulnerability.related = ",".join(v["id"] for v in match.get("relatedVulnerabilities"))
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
    association.fix = fix

    if session.is_modified(association) or session.is_modified(vulnerability) or session.new:
        return vulnerability, True

    return vulnerability, False


def extract_first_nvd_cvss(match: dict):
    vuln = match["vulnerability"]
    vuln_id = vuln["id"]
    if "nvd.nist.gov" in vuln.get("dataSource"):
        return vuln["cvss"]

    related = match["relatedVulnerabilities"]
    for vuln in related:
        if "nvd.nist.gov" in vuln.get("dataSource") and vuln.get("id") == vuln_id:
            return vuln["cvss"]
