import logging

import requests
from sqlalchemy.exc import MultipleResultsFound
from tqdm import tqdm

from libinv import Repository
from libinv import Session
from libinv.cli.cli import cli
from libinv.env import GIT_ORG
from libinv.env import GIT_PROVIDER
from libinv.env import SERVICE_METADATA_URL
from libinv.helpers import explode_git_url
from libinv.models import get_or_create

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def metapod_services():
    try:
        resp = requests.get(SERVICE_METADATA_URL, timeout=15)
        resp.raise_for_status()
        return resp.json().get("details", [])
    except requests.RequestException as exc:
        logger.error("Failed to fetch metapod services: %s", exc)
        return []


def process_metapod_service(metapod_service):
    repo_url = metapod_service.get("repository_url")
    if not repo_url:
        return {
            "name": metapod_service["name"],
            "provider": GIT_PROVIDER,
            "org": GIT_ORG,
            "subpod": metapod_service["subpod"]["name"],
            "pod": metapod_service["subpod"]["pod"]["name"],
        }

    url_parts = explode_git_url(repo_url)

    return {
        "name": metapod_service["name"],
        "provider": url_parts["provider"],
        "org": url_parts["org"],
        "subpod": metapod_service["subpod"]["name"],
        "pod": metapod_service["subpod"]["pod"]["name"],
    }


@cli.command()
def import_and_improve_from_metapod():
    services = metapod_services()
    processed_services = []

    for service in services:
        processed = process_metapod_service(service)
        if processed:
            processed_services.append(processed)

    logger.info(f"Processing {len(processed_services)} services")

    with Session() as session:
        for service in tqdm(processed_services):
            try:
                repository, _ = get_or_create(
                    session=session,
                    model=Repository,
                    name=service["name"],
                    provider=service["provider"],
                    org=service["org"],
                )
                repository.pod = service["pod"]
                repository.subpod = service["subpod"]
                session.commit()
            except MultipleResultsFound as e:
                logger.info(f"Found duplicate repo {service['name']}: skipping")
