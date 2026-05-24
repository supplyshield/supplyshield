import boto3

from libinv.env import AWS_REGION
from libinv.env import SQS_QUEUE_NAME


def get_queue_url():
    sqs_client = boto3.client("sqs", region_name=AWS_REGION)
    response = sqs_client.get_queue_url(
        QueueName=SQS_QUEUE_NAME,
    )
    return response["QueueUrl"]


def receive_messages(queue_url: str, count=1):
    sqs_client = boto3.client("sqs", region_name=AWS_REGION)
    response = sqs_client.receive_message(
        QueueUrl=queue_url,
        MaxNumberOfMessages=count,
        WaitTimeSeconds=20,
    )
    messages = response.get("Messages", [])
    return messages


def delete_message(receipt_handle):
    sqs_client = boto3.client("sqs", region_name=AWS_REGION)
    response = sqs_client.delete_message(
        QueueUrl=get_queue_url(),
        ReceiptHandle=receipt_handle,
    )
    return response


def change_message_visibility(receipt_handle: str, visibility_timeout_seconds: int = 1800):
    sqs_client = boto3.client("sqs", region_name=AWS_REGION)
    return sqs_client.change_message_visibility(
        QueueUrl=get_queue_url(),
        ReceiptHandle=receipt_handle,
        VisibilityTimeout=visibility_timeout_seconds,
    )


def poll():
    messages = []
    while not messages:
        messages = receive_messages(get_queue_url(), count=10)
    return messages
