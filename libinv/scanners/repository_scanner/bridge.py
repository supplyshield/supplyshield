import json

from libinv.api.metrics import scan_invocations_total
from libinv.base import conn
from libinv.models import Account
from libinv.models import Image
from libinv.models import update_safely
from libinv.scanners.repository_scanner import Wasp
from libinv.scanners.repository_scanner.exceptions import BridgeError
from libinv.scanners.repository_scanner.logger import logger


def connect(
    wasp: Wasp,
    account_id: str,
    image_name: str,
    image_digest: str,
    image_platform: str,
    session=None,
):
    s = session or conn
    commit = wasp.commit
    tag = wasp.tag

    image = None
    existing_images = s.query(Image).filter(
        Image.name == image_name,
        Image.account_id == account_id,
        Image.digest == image_digest,
        Image.platform == image_platform,
    )

    # If images already exist, check if tag or commit already contains relatable info
    for existing_image in existing_images:
        if existing_image.tag == commit[:10] or existing_image.commit == commit:
            image = existing_image
            break
        if existing_image.tag == tag:
            image = existing_image
            break

    if not image:
        if existing_images.count() > 1:
            raise BridgeError(
                "Many similar existing images present but none of them contain a tag "
                f"matching the commit: {commit}.\n"
                f"Looked for {image_name} {account_id} {image_digest} {image_platform}"
            )
        if existing_images.count() == 1:
            image = existing_images[0]
        else:
            image = Image(
                name=image_name,
                account_id=account_id,
                digest=image_digest,
                platform=image_platform,
            )
            s.add(image)
            s.commit()
            logger.debug(f"[*] Created image: {image}")

    # FIXME: sometimes different commits will trigger same image because of
    # empty commits, rebases etc. Think about an elegant solution for this
    # update_safely(session=s, model=image, attr="commit", value=commit)
    image.commit = commit

    repository = wasp.repository
    if repository:
        update_safely(session=s, model=image, attr="repository", value=repository)
        logger.info(f"[+] {image} bridged to {repository}")
    else:
        logger.error(f"[!] Wasp {wasp} gave an invalid repository for {image}")

    image.wasp = wasp
    s.commit()
    logger.info(f"[+] Wasp {wasp} ate ecr image ({image})")


def connect_using_queue_message_agreement(wasp: Wasp, session=None):
    """
    Connect repository to its ECR image using data in wasp.

    ``session`` is threaded through so the SQS handler in libinv.main can
    open one session_scope per message; ``connect()`` still commits
    per-image atomically inside the loop, preserving the original
    failure semantics.
    """
    # Sprint 25: count one invocation per SQS bridge message. Increment
    # BEFORE parsing so a malformed message still surfaces in the metric.
    scan_invocations_total.labels(type="repository_bridge").inc()
    s = session or conn
    message = json.loads(wasp.raw_message)

    for ecr_image in message["ecr_image"]:
        if ecr_image["type"] == "ImageIndex":
            # FIXME: Handle this properly
            continue

        account_id, _, _ = ecr_image["name"].partition(".")
        _, _, image_name = ecr_image["name"].rpartition("/")
        platform = f"{ecr_image['platform']['os']}/{ecr_image['platform']['architecture']}"
        Account.ensure_exists(
            account_id=account_id,
            name=message["aws_environment"],
            session=s,
        )
        connect(
            wasp=wasp,
            account_id=account_id,
            image_name=image_name,
            image_digest=ecr_image["digest"],
            image_platform=platform,
            session=s,
        )
