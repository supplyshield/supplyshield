import json

import requests

from libinv.env import SCANCODE_PIPELINES
from libinv.env import SCANCODEIO_API_KEY
from libinv.env import SCANCODEIO_URL
from libinv.helpers import create_presigned_url_s3
from libinv.models import Wasp
from libinv.scanners.repository_scanner.logger import logger

# Configure the following variables to your needs
EXECUTE_NOW = True


def run(
    wasp: Wasp,
    cdx_s3_object_name: str,
    scancode_url: str = SCANCODEIO_URL,
    additional_pipelines=None,
):
    if additional_pipelines is None:
        additional_pipelines = []
    logger.debug("Starting scancode io scan")
    cdx_url = create_presigned_url_s3(cdx_s3_object_name)
    input_urls = [cdx_url]
    session = requests.Session()

    name = cdx_s3_object_name
    ignore_suffix = ".sbom.cdx.json"
    if name.endswith(ignore_suffix):
        name = name[: -len(ignore_suffix)]

    if SCANCODEIO_API_KEY:
        session.headers.update({"Authorization": f"Token {SCANCODEIO_API_KEY}"})

    projects_api_url = f"{scancode_url}/api/projects/"
    project_data = {
        "name": name,
        "input_urls": input_urls,
        "pipeline": SCANCODE_PIPELINES + additional_pipelines,
        "execute_now": EXECUTE_NOW,
    }

    try:
        response = session.post(projects_api_url, json=project_data, timeout=300)
        response.raise_for_status()
    except requests.RequestException as exc:
        logger.error("ScancodeIO project creation failed: %s", exc)
        raise
    try:
        response_json = response.json()
    except json.decoder.JSONDecodeError as exc:
        wasp.throw(f"ScancodeIO error: Status: {response.status_code}: {exc}")
        return

    logger.debug("ScancodeIO output: ")
    logger.debug(response_json)

    name = response_json.get("name")
    if name:
        url = f"{SCANCODEIO_URL}/project/?search={name}"
        logger.info(f"[+] ScancodeIO task: {url}")
