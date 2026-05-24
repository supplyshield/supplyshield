from __future__ import annotations

import logging
import sys

import click

from libinv.logger import CustomFormatter
from libinv.logger import color_handler


@click.group()
@click.option("--verbose", is_flag=True, default=False)
@click.option("--debug", is_flag=True, default=False)
@click.option("--color", is_flag=True, default=False)
@click.pass_context
def cli(ctx: click.Context, verbose: bool, debug: bool, color: bool) -> None:
    ctx.obj = {"slack_logging": True}
    if verbose:
        click.echo("Verbose mode is on")
        setup_verbose_logging()
    if debug:
        click.echo("Debug mode is on: Verbose and no slack")
        setup_verbose_logging()
        ctx.obj["slack_logging"] = False
    if color or sys.stdout.isatty():
        setup_color_logging()


def setup_verbose_logging() -> None:
    logging.basicConfig(level=logging.WARNING)
    logging.getLogger("libinv").setLevel(logging.DEBUG)


def setup_color_logging() -> None:
    color_handler.setFormatter(CustomFormatter())
    logger = logging.getLogger("libinv")
    logger.propagate = False
    logger.addHandler(color_handler)
