import json
import traceback

import click

from libinv import process_message, passthrough_message
from libinv.cli.cli import cli
from libinv.helpers import send_to_slack
from libinv.sqs import receive_messages, get_queue_url, delete_message
from libinv.env import PRIORITY_SQS_QUEUE_NAME, SQS_QUEUE_NAME


def send_error_to_slack(message, queue_type=""):
    """
    Send error message and stack trace to Slack

    Args:
        message: The SQS message that caused the error
        queue_type: Optional string to identify which queue (e.g., "from priority queue")
    """
    queue_label = f" {queue_type}" if queue_type else ""
    txt = f":alert: *Error while handling message{queue_label}:*\n"
    txt += "```"
    txt += json.dumps(message)
    txt += "```\n"
    send_to_slack(txt)

    trace = traceback.format_exc()
    chunk_size = 3900
    txt = "*Stack trace:*\n"
    txt += "```"
    txt += trace[0:chunk_size]
    txt += "```"
    send_to_slack(txt)

    if trace:
        for start in range(chunk_size, len(trace), chunk_size):
            txt = "```"
            txt += trace[start : start + chunk_size]
            txt += "```"
            send_to_slack(txt)


@cli.command()
@click.option("--slack/--no-slack", is_flag=True, default=True)
@click.pass_context
def daemon(ctx, slack=True):
    """
    Poll messages from sqs queue and populate libinv database
    """
    click.echo("starting service")
    if not ctx.obj["slack_logging"]:
        click.echo("Overriding slack logs. Disabled")
        slack = False

    priority_queue_url = get_queue_url(PRIORITY_SQS_QUEUE_NAME)
    main_queue_url = get_queue_url(SQS_QUEUE_NAME)

    while True:
        click.echo("polling for new messages")

        # Poll one message from main queue (armada)
        main_messages = receive_messages(main_queue_url, count=1)

        # Poll messages from priority queue
        priority_messages = receive_messages(priority_queue_url, count=10)

        # Process one message from main queue if available
        if main_messages:
            for message in main_messages:
                try:
                    message['_QueueUrl'] = main_queue_url
                    click.echo(f"Processing message from main queue: {message.get('MessageId')}")
                    passthrough = passthrough_message(message)
                    if not passthrough:
                        click.echo("Passthrough message failed")
                    process_message(message)
                    # Delete message after successful processing
                    delete_message(message["ReceiptHandle"], main_queue_url)
                    click.echo(f"Successfully processed and deleted message: {message.get('MessageId')}")
                except Exception:
                    if not slack:
                        raise

                    send_error_to_slack(message)
                    click.echo("Error sent to slack. Exiting")
                    return

        # Process ALL messages from priority queue if any exist
        while priority_messages:
            for message in priority_messages:
                try:
                    message['_QueueUrl'] = priority_queue_url
                    click.echo(f"Processing message from priority queue: {message.get('MessageId')}")
                    passthrough = passthrough_message(message)
                    if not passthrough:
                        click.echo("Passthrough message failed")
                    process_message(message)
                    # Delete message after successful processing
                    delete_message(message["ReceiptHandle"], priority_queue_url)
                    click.echo(f"Successfully processed and deleted message: {message.get('MessageId')}")
                except Exception:
                    # Always delete priority queue messages even on failure to prevent retry loops
                    delete_message(message["ReceiptHandle"], priority_queue_url)
                    click.echo(f"Error processing priority queue message, but deleted: {message.get('MessageId')}")

                    if not slack:
                        raise

                    send_error_to_slack(message, "from priority queue")
                    click.echo("Error sent to slack. Exiting")
                    return

            # Check if there are more messages in priority queue
            priority_messages = receive_messages(priority_queue_url, count=10)
