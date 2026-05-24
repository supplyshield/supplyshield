from __future__ import annotations

import click

from libinv import Session
from libinv.cli.cli import cli
from libinv.models import Image
from libinv.models import get_base_image_of


@cli.group()
def query() -> None:
    """
    Various query subcommands for libinv database
    """
    pass


@query.command()
@click.option("--tech-only", is_flag=True)
@click.option("--sre-only", is_flag=True)
@click.argument("image_id", type=click.INT)
def sbom(tech_only: bool, sre_only: bool, image_id: int) -> None:
    session = Session()
    image = Image.get_by_id(session, image_id)
    base = get_base_image_of(image)

    sre_packages = set(base.packages)
    all_packages = set(image.packages)
    tech_packages = all_packages - sre_packages

    if tech_only:
        click.echo(list(map(lambda x: (x.package_id), tech_packages)))
    elif sre_only:
        click.echo(list(map(lambda x: (x.package_id), sre_packages)))
    else:
        click.echo(list(map(lambda x: (x.package_id), all_packages)))
