from __future__ import annotations

import click

from libinv.cli.cli import cli
from libinv.main import process_message as _process_message


@cli.command()
@click.argument("message")
def process_message(message: str) -> None:
    message_metadata = {"Body": message, "ReceiptHandle": ""}
    _process_message(message_metadata)
