from __future__ import annotations

import click

from libinv import scan_ecr_image
from libinv.cli.cli import cli
from libinv.helpers import get_credentials_from_aws_okta


@cli.command()
@click.argument("image_name")
@click.argument("image_digest")
def scan_stage_ecr_image(image_name: str, image_digest: str) -> None:
    credentials = get_credentials_from_aws_okta(profile="stage")  # for local
    scan_ecr_image(
        image_name=image_name,
        image_digest=image_digest,
        account_id="280690977678",
        credentials=credentials,
    )
