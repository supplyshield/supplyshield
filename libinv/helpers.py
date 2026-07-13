import json
import logging
import os
import subprocess
from time import sleep
from typing import List

import boto3
import requests
from botocore.exceptions import ClientError

from libinv.env import AWS_REGION
from libinv.env import S3_BUCKET_NAME
from libinv.env import SLACK_URL
from libinv.exceptions import RetryFailedException
from libinv.exceptions import SubprocessError
from libinv.sqs import delete_message

logger = logging.getLogger("libinv.helpers")


def send_to_slack(data: str):
    payload = {"text": str(data)}
    requests.post(SLACK_URL, data=json.dumps(payload))
    return


def retry_on_exception(exception: Exception, count=3, delay=5):
    def decorator(func):
        def wrapper(*args, **kwargs):
            raised_exc = RetryFailedException()
            for times in range(count):
                try:
                    return func(*args, **kwargs)
                except exception as exc:
                    raised_exc = exc
                    print(f"[{times}]: {func.__name__} raised {exc}", end="")
                    if times < count - 1:
                        print(f", retrying after {delay} seconds.")
                        sleep(delay)
                    else:
                        print()
            print("Enough retries. Function call is irrecoverable")
            raise RetryFailedException from raised_exc

        return wrapper

    return decorator


def subprocess_run(args: List[str], **kwargs):
    try:
        return subprocess.run(
            args=args,
            shell=False,
            check=True,
            capture_output=True,
            text=True,
            timeout=300,
            **kwargs,
        )
    except subprocess.CalledProcessError as exc:
        raise SubprocessError(exc.stderr) from exc


def get_credentials_from_aws_okta(profile="stage"):
    env = subprocess_run(["aws-okta", "env", profile]).stdout.split("\n")
    creds = {}
    for stmt in env:
        key, _, value = stmt.partition("=")
        key = key.replace("export ", "")
        key = key.strip()
        creds[key] = value
    credentials = {
        "AccessKeyId": creds["AWS_ACCESS_KEY_ID"],
        "SecretAccessKey": creds["AWS_SECRET_ACCESS_KEY"],
        "SessionToken": creds["AWS_SESSION_TOKEN"],
    }
    return credentials


def case_insensitive_dict(dct: dict):
    new_dct = {}
    for k, v in dct.items():
        if isinstance(k, str):
            k = k.casefold()
        if isinstance(v, str):
            v = v.casefold()
        new_dct[k] = v
    return new_dct


def upload_to_s3(file_name, bucket=S3_BUCKET_NAME, object_name=None):
    """Upload a file to an S3 bucket

    :param file_name: File to upload
    :param bucket: Bucket to upload to
    :param object_name: S3 object name. If not specified then file_name is used
    :return: object name if file was uploaded, else False
    """

    logger.debug(f"Uploading to s3: {file_name}")

    # If S3 object_name was not specified, use file_name
    if object_name is None:
        object_name = os.path.basename(file_name)

    # Upload the file
    s3_client = get_boto3_client("s3")
    try:
        s3_client.upload_file(file_name, bucket, object_name)
    except ClientError as e:
        logger.error(e)
        return False

    # TODO: Use this after s3 support in scio is implemented
    # s3_url = f"s3://{S3_BUCKET_NAME}/{object_name}"
    # return s3_url
    logger.debug(f"Uploaded to s3: {file_name}")
    return object_name


def create_presigned_url_s3(object_name, bucket_name=S3_BUCKET_NAME, expiration=3600):
    """Generate a presigned URL to share an S3 object

    :param object_name: string
    :param bucket_name: string
    :param expiration: Time in seconds for the presigned URL to remain valid
    :return: Presigned URL as string. If error, returns None.
    """

    # Generate a presigned URL for the S3 object
    s3_client = get_boto3_client("s3", endpoint_url=f"https://s3.{AWS_REGION}.amazonaws.com")
    try:
        response = s3_client.generate_presigned_url(
            "get_object", Params={"Bucket": bucket_name, "Key": object_name}, ExpiresIn=expiration
        )
    except ClientError as e:
        logging.error(e)
        return None

    # The response contains the presigned URL
    return response


def get_boto3_client(type, **kwargs):
    client = boto3.client(type, region_name=AWS_REGION, **kwargs)
    # NOTE: Sometimes you'll need endpoint_url=https://s3.ap-south-1.amazonaws.com
    return client


# thanks to HanSooloo https://stackoverflow.com/a/23726462/2251364
def entry_logger(fn):
    from functools import wraps

    @wraps(fn)
    def wrapper(*args, **kwargs):
        log = logging.getLogger(fn.__name__)
        log.info("About to run %s" % fn.__name__)

        out = fn(*args, **kwargs)

        log.info("Done running %s" % fn.__name__)
        # Return the return value
        return out

    return wrapper


def delete_message_where_repository_url_contains(token: str, message_metadata: dict):
    logger.debug(f"Received message: \n {message_metadata}")
    message_body = message_metadata["Body"]

    # FIXME TMPFIX
    message_body = message_body.replace('"[', "[").replace(']"', "]")
    logger.warn("Applied temp fix")

    message = json.loads(message_body)
    message_type = message.get("type", "").casefold()
    if message_type:  # Temp deletion
        if message_type == "bridge":
            repository_url = message["repository"]["url"]
            if token in repository_url:
                delete_message(message_metadata["ReceiptHandle"], message_metadata.get("_QueueUrl"))
                logger.info("[*] Deleted message with url: {message['repository_url']}")
    return


def explode_git_url(url: str):
    """
    >>> explode_git_url("git@github.com:gitorg/100ft-web.git")
    {'provider': 'github.com', 'org': 'gitorg', 'name': '100ft-web'}
    >>> explode_git_url("https://bitbucket.org/gitorg/libinv")
    {'provider': 'bitbucket.org', 'org': 'gitorg', 'name': 'libinv'}
    """
    ssh_prefix = "git@"
    if url.startswith(ssh_prefix):
        provider, _, full_name = url[len(ssh_prefix) :].partition(
            ":"
        )  # [bug], full_name will not exist if above if statement is false

    https_prefix = "https://"
    if url.startswith(https_prefix):
        provider, _, full_name = url[len(https_prefix) :].partition("/")

    org, _, name = full_name.partition("/")
    git_suffix = ".git"
    if name.endswith(git_suffix):
        name = name[: -len(git_suffix)]

    return {"provider": provider, "org": org, "name": name}
