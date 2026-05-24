import os

import boto3

from libinv.api.metrics import scan_failures_total
from libinv.api.metrics import scan_invocations_total
from libinv.base import session_scope
from libinv.helpers import get_boto3_client
from libinv.scanners.image_scanner.base_image import detect_and_update_base_image
from libinv.scanners.image_scanner.base_image import save_layer_information_for_image
from libinv.scanners.image_scanner.image_index import AWSImageIndex
from libinv.scanners.image_scanner.image_index import DockerHubImageIndex
from libinv.scanners.image_scanner.image_index import ImageIndex
from libinv.scanners.image_scanner.image_index import ORGSREImageIndex
from libinv.scanners.image_scanner.logger import logger
from libinv.scanners.image_scanner.sbom import generate_sbom_for_image_tar
from libinv.scanners.image_scanner.sbom import parse_sbom_with_image_tar
from libinv.scanners.image_scanner.sca import generate_sca_from_sbom
from libinv.scanners.image_scanner.sca import parse_sca_with_image


def delete(filename):
    os.remove(filename)
    logger.info(f"{filename} removed")


def scan_orgsre_image(image_name, image_tag):
    # Some sort of login
    # FIXME: Supplying name and tag as name is a temporary hack
    # it is needed because orgsre can have many ACTIVE images under same name
    # but different tags. This is not the case with ECR images, where only one tag is
    # active at a time, so we can freely update tag in the database and keep only
    # one tag at all times.
    image_index = ORGSREImageIndex(name=f"{image_name}:{image_tag}", tag=None)
    return scan_image_index(image_index, "orgsre")


def scan_dockerhub_image(image_name, image_tag):
    image_index = DockerHubImageIndex(name=image_name, tag=image_tag)
    return scan_image_index(image_index, "dockerhub")


def scan_ecr_image(image_name, image_digest, account_id, credentials=None):
    sts_client = boto3.client("sts")
    if not credentials:
        credentials = sts_client.assume_role(
            RoleArn=f"arn:aws:iam::{account_id}:role/libinv-cross-account-access-role",
            RoleSessionName="AssumeRoleSession1",
        )["Credentials"]
    client = get_boto3_client(
        type="ecr",
        aws_access_key_id=credentials["AccessKeyId"],
        aws_secret_access_key=credentials["SecretAccessKey"],
        aws_session_token=credentials["SessionToken"],
    )
    if client:
        logger.debug("[+] Authenticated to AWS ECR")
    image_index = AWSImageIndex(
        boto3_ecr_client=client, account_id=account_id, name=image_name, digest=image_digest
    )
    return scan_image_index(image_index, account_id)


def scan_image_index(image_index: ImageIndex, account_id: str):
    # Sprint 25: count one invocation per top-level image scan. Increment
    # BEFORE the work so crashes still register. All three public entry
    # points (scan_orgsre_image / scan_dockerhub_image / scan_ecr_image)
    # funnel here, so this is the single chokepoint — no double-counting.
    scan_invocations_total.labels(type="image").inc()
    try:
        for image_tar in image_index.pull_images_if_not_exist():
            logger.info(
                "Processing %s, Size: %s, Fresh: %s",
                image_tar,
                image_tar.size,
                image_tar.freshly_pulled,
            )
            sbom_filename = generate_sbom_for_image_tar(image_tar)
            with session_scope() as session:
                # Yeah, this is weird. We'll move to something better
                # Idea is to create unit files (let's say ricks/generate_sbom.py)
                # with ricks.generate_sbom as worker:
                #  with ricks.generate_sca() as sca:
                #    ricks.parse_sca()
                #  ...
                image = parse_sbom_with_image_tar(
                    session=session,
                    sbom_filename=sbom_filename,
                    image_tar=image_tar,
                    account_id=account_id,
                )
                save_layer_information_for_image(session=session, image=image, image_tar=image_tar)
                detect_and_update_base_image(session=session, image=image)
                sca_filename = generate_sca_from_sbom(sbom_filename)
                parse_sca_with_image(session=session, sca_filename=sca_filename, image=image)
            delete(sbom_filename)
            delete(sca_filename)
            delete(image_tar.filename)
    except Exception as exc:
        scan_failures_total.labels(
            type="image",
            error_class=type(exc).__name__,
        ).inc()
        raise
