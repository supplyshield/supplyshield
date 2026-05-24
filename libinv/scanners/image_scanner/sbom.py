import datetime
import json

from sqlalchemy.exc import IntegrityError
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session as OrmSession
from sqlalchemy.orm import selectinload
from tqdm import tqdm
from tqdm.contrib.logging import logging_redirect_tqdm

from libinv.env import SYFT_BIN
from libinv.helpers import retry_on_exception
from libinv.helpers import subprocess_run
from libinv.models import MAX_LENGTH_LICENSE
from libinv.models import Image
from libinv.models import ImagePackageAssociation
from libinv.models import License
from libinv.models import Package
from libinv.models import PackageLicenseAssociation
from libinv.models import get_or_create
from libinv.scanners.image_scanner.image_tarball import ImageTarBall
from libinv.scanners.image_scanner.logger import logger


def generate_sbom_for_image_tar(image_tar: ImageTarBall):
    logger.info("Generating SBOM")
    outfile = "sbom.json"
    subprocess_run(
        [
            SYFT_BIN,
            "-q",
            image_tar.filename,
            "-o",
            f"json={outfile}",
        ],
    )
    logger.info(f"{outfile} created")
    return outfile


@retry_on_exception(IntegrityError)
@retry_on_exception(OperationalError, count=6)
def parse_sbom_with_image_tar(
    session: OrmSession, sbom_filename: str, image_tar: ImageTarBall, account_id: str
) -> Image:
    with open(sbom_filename, "r", encoding="UTF-8") as sbom_file:
        sbom_json = json.load(sbom_file)
    backend_tech = "NA"
    artifacts = sbom_json["artifacts"]

    try:
        ts0 = datetime.datetime.now()
        image, _ = get_or_create(
            session,
            Image,
            name=image_tar.name,
            backend_tech=backend_tech,
            account_id=account_id,
            platform=image_tar.platform,
            digest=image_tar.digest,
            tag=image_tar.tag,
        )
        session.commit()
        image = (
            session.query(Image)
            .options(
                selectinload(Image.packages, ImagePackageAssociation.package, Package.licenses)
            )
            .filter_by(id=image.id)
            .one_or_none()
        )

        for artifact in tqdm(artifacts):
            package, db_updated = process_sbom_artifact_for_image(
                session=session, image=image, artifact=artifact
            )

            with logging_redirect_tqdm():
                if db_updated:
                    logger.debug(f"Updated: {image} with package {package}")
                else:
                    logger.debug(f"Existing: {image} already has {package}")

        logger.debug("Committing")
        session.commit()
        ts1 = datetime.datetime.now()
        logger.debug(f"in db {ts1 - ts0}")
        logger.info("SBOM: pushing to DB done")

    except OperationalError:
        # This happens when there's a deadlock
        session.rollback()
        raise
    except IntegrityError:
        # This happens when two libinv instances picked the same image
        session.rollback()
        raise
    return image


def process_sbom_artifact_for_image(session: OrmSession, image, artifact):
    modified = False

    package_filter = {
        "name": artifact["name"],
        "version": artifact["version"],
        "language": artifact["language"],
        "purl": artifact["purl"],
    }

    package, _ = get_or_create(session, Package, **package_filter)
    association = session.get(
        ImagePackageAssociation, {"image_id": image.id, "package_id": package.id}
    )
    if not association:
        association = ImagePackageAssociation(image_id=image.id, package_id=package.id)
        modified = True
    if artifact["metadataType"] == "JavaMetadata":
        if association.pkg_metadata != artifact["metadata"]["virtualPath"]:
            association.pkg_metadata = artifact["metadata"]["virtualPath"]
            modified = True

    image.packages.append(association)

    license_texts = artifact["licenses"]
    license_texts = filter(is_valid_license, license_texts)
    for license_name in license_texts:
        # Syft gives out long license names often, db needs to cope up with that
        license_name = license_name[:MAX_LENGTH_LICENSE]
        license_filter = {"name": license_name}
        license, _ = get_or_create(session, License, **license_filter)
        association = session.get(
            PackageLicenseAssociation, {"license_id": license.id, "package_id": package.id}
        )
        if not association:
            association = PackageLicenseAssociation(license_id=license.id, package_id=package.id)
            modified = True
        package.licenses.append(association)
        # try:
        #     license = filter_model_collection(package.licenses, license_filter)[0]
        # except IndexError:
        #     license = License(**license_filter)
        # package.licenses.append(license)

    if session.is_modified(package) or session.is_modified(image) or session.new or modified:
        return package, True

    return package, False


def is_valid_license(license_text: str):
    license_text = license_text.lower()
    if license_text in ["and", "or"]:
        return False
    return True
