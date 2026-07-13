import boto3

from libinv.env import AWS_REGION
from libinv.env import SQS_QUEUE_NAME


def get_queue_url(queue_url):
    sqs_client = boto3.client("sqs", region_name=AWS_REGION)
    response = sqs_client.get_queue_url(
        QueueName=queue_url,
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


def delete_message(receipt_handle, queue_url=None):
    sqs_client = boto3.client("sqs", region_name=AWS_REGION)
    # Default to main queue if not specified
    if queue_url is None:
        queue_url = get_queue_url(SQS_QUEUE_NAME)

    response = sqs_client.delete_message(
        QueueUrl=queue_url,
        ReceiptHandle=receipt_handle,
    )
    return response


def send_message(queue_url: str, message: str):
    sqs_client = boto3.client("sqs", region_name=AWS_REGION)
    response = sqs_client.send_message(
        QueueUrl=queue_url,
        MessageBody=message,
    )
    return response


def poll():
    messages = []
    while not messages:
        messages = receive_messages(get_queue_url(SQS_QUEUE_NAME), count=10)
    return messages
