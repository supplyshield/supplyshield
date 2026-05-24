import json
import logging
import signal
import traceback

import click

from libinv import poll
from libinv import process_message
from libinv.cli.cli import cli
from libinv.helpers import send_to_slack

logger = logging.getLogger(__name__)

_shutdown_requested = False


def _request_shutdown(signum, frame):
    global _shutdown_requested
    _shutdown_requested = True
    logger.warning("Shutdown signal %s received; will exit after current batch.", signum)


@cli.command()
@click.option("--slack/--no-slack", is_flag=True, default=True)
@click.pass_context
def daemon(ctx, slack):
    """Poll messages from sqs queue and populate libinv database."""
    click.echo("starting service")
    if not ctx.obj["slack_logging"]:
        click.echo("Overriding slack logs. Disabled")
        slack = False

    signal.signal(signal.SIGTERM, _request_shutdown)
    signal.signal(signal.SIGINT, _request_shutdown)

    while not _shutdown_requested:
        click.echo("polling for new messages")
        try:
            messages = poll()
        except Exception:
            logger.exception("Failed to poll SQS; sleeping briefly before retry")
            continue

        for message in messages:
            if _shutdown_requested:
                logger.info("Shutdown requested; stopping after in-flight messages.")
                break
            try:
                process_message(message)
            except Exception:
                logger.exception("Error processing message")
                if slack:
                    _notify_slack(message)
                # Continue to next message; do NOT return.

    click.echo("daemon exited cleanly")


def _notify_slack(message):
    try:
        body = json.dumps(message)
    except Exception:
        body = repr(message)
    chunk_size = 3900
    send_to_slack(":alert: *Error while handling message:*\n```" + body[:chunk_size] + "```\n")
    trace = traceback.format_exc()
    send_to_slack("*Stack trace:*\n```" + trace[:chunk_size] + "```")
    for start in range(chunk_size, len(trace), chunk_size):
        send_to_slack("```" + trace[start : start + chunk_size] + "```")
