from __future__ import annotations

from datetime import datetime
from datetime import timezone

import click

from libinv import Session
from libinv.cli.cli import cli
from libinv.models import DeploymentCheckpoint


@cli.command()
@click.option("--get", "-g", "get", is_flag=True)
@click.option("--set", "-s", "checkpoint_time", help="One of the values from --list or NOW")
@click.option("--list", "-l", "list_", is_flag=True)
def checkpoint(get: bool, checkpoint_time: str | None, list_: bool) -> None:
    """
    Get or set checkpoints for latest images table
    Updates latest images table on setting a new checkpoint
    """
    with Session() as session:
        if get:
            active_checkpoint = DeploymentCheckpoint.get(session)
            print(active_checkpoint)

        elif checkpoint_time:
            if checkpoint_time == "NOW":
                checkpoint_time = datetime.now(timezone.utc)
            else:
                checkpoint_time = datetime.strptime(checkpoint_time, "%Y-%m-%d %H:%M:%S")
            DeploymentCheckpoint.set(session=session, checkpoint=checkpoint_time)

        else:
            for checkpoint in DeploymentCheckpoint.list(session):
                if checkpoint.active:
                    print("* ", end="")
                else:
                    print("  ", end="")
                print(checkpoint)
