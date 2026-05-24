import json
import logging
import subprocess

from libinv.env import IMAGE_SCAN_ENABLED
from libinv.helpers import send_to_slack
from libinv.helpers import upload_to_s3
from libinv.scanners.image_scanner import scan_ecr_image
from libinv.scanners.image_scanner import scan_orgsre_image
from libinv.scanners.repository_scanner import Wasp
from libinv.scanners.repository_scanner import connect_using_queue_message_agreement
from libinv.scanners.repository_scanner import run_cdxgen_scan
from libinv.scanners.repository_scanner import run_scancodeio
from libinv.scanners.repository_scanner.sast import semgrep
from libinv.sqs import delete_message

logger = logging.getLogger("libinv.main")


def process_message(message_metadata):
    return process_sqs_message(message_metadata)


def process_sqs_message(message_metadata: dict):
    logger.debug(f"Received message: \n {message_metadata}")
    message_body = message_metadata["Body"]

    receipt_handle = message_metadata.get("ReceiptHandle")
    if receipt_handle:
        try:
            from libinv.sqs import change_message_visibility
            change_message_visibility(receipt_handle, 1800)
            logger.debug("Extended SQS visibility to 1800s")
        except Exception as exc:
            logger.warning("Failed to extend SQS visibility: %s", exc)

    message = json.loads(message_body)

    message_type = message.get("type", "").casefold()
    if message_type:  # New feature. Handling of messages based on types
        if message_type == "bridge":
            with Wasp.eat_caterpillar_message(message) as wasp:
                try:
                    repository_dir = wasp.repo_dir

                    connect_using_queue_message_agreement(wasp)

                    cdx_file = run_cdxgen_scan(wasp)
                    cdx_s3_object_name = str(cdx_file.relative_to(wasp.cwd))
                    upload_to_s3(file_name=str(cdx_file), object_name=cdx_s3_object_name)

                    run_scancodeio(wasp, cdx_s3_object_name)
                    delete_message(message_metadata["ReceiptHandle"])

                    semgrep.run_cicd(wasp, repository_dir)

                except subprocess.TimeoutExpired as exc:
                    logger.error("Timed out!", message)
                    wasp.throw(f"Timed out: {exc}")
                    return

    elif IMAGE_SCAN_ENABLED:  # Legacy way of handling
        image_name = message["detail"]["repository-name"]
        image_digest = message["detail"]["image-digest"]
        image_tag = message["detail"]["image-tag"]
        account_id = message["account"]

        if not image_name or not (image_digest or image_tag):
            txt = ":warning: Image name and (digest or tag) combination cannot be empty. Ignoring message:"
            txt += "```"
            txt += json.dumps(message)
            txt += "```\n"
            send_to_slack(txt)
        else:
            if message.get("golden_retriever_image"):
                scan_orgsre_image(image_name=image_name, image_tag=image_tag)
            else:
                scan_ecr_image(
                    image_name=image_name,
                    image_digest=image_digest,
                    account_id=account_id,
                    # Uncomment for local run
                    # credentials=get_credentials_from_aws_okta(),
                )
        delete_message(message_metadata["ReceiptHandle"])


if __name__ == "__main__":
    from libinv.cli.cli import cli

    cli()
