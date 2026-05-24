from __future__ import annotations

from libinv.cli.cli import cli
from libinv.jira_integration import connect


@cli.command()
def secbugs_connect() -> None:
    """
    Connect Jira SECBUGS
    """
    connect()
