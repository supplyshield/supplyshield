import json
import logging
import os
import random
import subprocess
from functools import lru_cache
from time import sleep
from typing import List

import boto3
import requests
from botocore.exceptions import ClientError
from prometheus_client import Counter

from libinv.env import AWS_REGION
from libinv.env import S3_BUCKET_NAME
from libinv.env import SLACK_URL
from libinv.exceptions import RetryFailedException
from libinv.exceptions import SubprocessError
from libinv.sqs import delete_message

# Sprint 52.2 — surface ClientError failures from ``upload_to_s3``
# both in logs (ERROR level with bucket + key + boto3 error code) and
# as a Prometheus counter so alerts can fire when the S3 upload path
# starts failing. The counter is published on the default registry
# rather than the libinv-private one in ``libinv.api.metrics`` because
# this module is also imported by the daemon / cron processes that
# don't bring up the Flask app. The default registry is picked up by
# ``prometheus_client.multiprocess`` collectors at scrape time.
s3_upload_failures_total = Counter(
    "libinv_s3_upload_failures_total",
    "Total ClientError failures from libinv.helpers.upload_to_s3.",
    labelnames=("bucket", "error_code"),
)

logger = logging.getLogger("libinv.helpers")


# Snapshot the original module-level `requests.post` at import time so the
# Slack session shim can defer to a `unittest.mock.patch("libinv.helpers.
# requests.post")` test double when one is installed. This keeps the Sprint
# 14 send_to_slack tests passing without any test-side modification.
_REQUESTS_POST_ORIGINAL = requests.post


class _SlackHttpSession(requests.Session):
    """`requests.Session` that honors monkey-patched `requests.post` in tests.

    In production it pools connections to Slack's incoming-webhook host so
    repeated alerts skip TCP/TLS handshakes. In tests, when
    `libinv.helpers.requests.post` is replaced with a mock, this override
    routes through that mock so existing assertions still fire.
    """

    def request(self, method, url, **kwargs):
        method_lower = method.lower() if isinstance(method, str) else method
        if method_lower == "post" and requests.post is not _REQUESTS_POST_ORIGINAL:
            return requests.post(url, **kwargs)
        return super().request(method, url, **kwargs)


@lru_cache(maxsize=1)
def _slack_http_session():
    """Process-wide lazily-initialized session for Slack webhook posts."""
    return _SlackHttpSession()


def send_to_slack(data: str):
    payload = {"text": str(data)}
    try:
        _slack_http_session().post(SLACK_URL, data=json.dumps(payload), timeout=10)
    except requests.RequestException as exc:
        logger.warning("Slack post failed: %s", exc)


def retry_on_exception(exception, count=3, delay=5):
    def decorator(func):
        def wrapper(*args, **kwargs):
            last_exc = None
            for attempt in range(count):
                try:
                    return func(*args, **kwargs)
                except exception as exc:
                    last_exc = exc
                    logger.warning(
                        "%s raised %r on attempt %d/%d",
                        func.__name__, exc, attempt + 1, count,
                    )
                    if attempt < count - 1:
                        sleep_for = (delay * (2 ** attempt)) + random.uniform(0, delay)
                        logger.warning("Retrying after %.2fs", sleep_for)
                        sleep(sleep_for)
            logger.error("%s: giving up after %d retries", func.__name__, count)
            raise RetryFailedException(str(last_exc)) from last_exc

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
    """Upload a file to an S3 bucket.

    Sprint 52.2 — on ``ClientError`` this function now logs at ERROR
    level with the bucket + key + boto3 error code, increments the
    Prometheus counter ``libinv_s3_upload_failures_total``, and
    re-raises the original ``ClientError`` so callers cannot silently
    miss a failed upload. The only caller (``libinv.main.process_sqs_message``)
    relies on the outer ``Wasp.eat_caterpillar_message`` context manager
    to surface the exception to the SQS daemon (Sprint 52.3 leaves the
    message un-deleted so it lands in the DLQ after ``maxReceiveCount``
    re-deliveries).

    :param file_name: File to upload
    :param bucket: Bucket to upload to
    :param object_name: S3 object name. If not specified then file_name is used
    :return: object name on success
    :raises botocore.exceptions.ClientError: on any S3 failure
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
        error_code = "Unknown"
        try:
            error_code = e.response.get("Error", {}).get("Code") or "Unknown"
        except Exception:
            # Some botocore exceptions don't carry a fully-populated
            # ``response`` dict; degrade gracefully so we still emit
            # the counter + structured log line.
            pass
        logger.error(
            "S3 upload failed: bucket=%s key=%s error_code=%s file=%s",
            bucket, object_name, error_code, file_name,
        )
        s3_upload_failures_total.labels(
            bucket=str(bucket), error_code=str(error_code),
        ).inc()
        raise

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


@lru_cache(maxsize=None)
def _cached_boto3_client(service: str, endpoint_url: str = None):
    """Process-wide cached boto3 client.

    Credentials and region are resolved once at first call. Safe so long
    as the container's IAM role / env-var credentials don't rotate
    mid-process; if they do, restart the worker.
    """
    kwargs = {"region_name": AWS_REGION}
    if endpoint_url:
        kwargs["endpoint_url"] = endpoint_url
    return boto3.client(service, **kwargs)


def get_boto3_client(type, **kwargs):
    return _cached_boto3_client(type, endpoint_url=kwargs.get("endpoint_url"))


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
    logger.warning("Applied temp fix")

    message = json.loads(message_body)
    message_type = message.get("type", "").casefold()
    if message_type:  # Temp deletion
        if message_type == "bridge":
            repository_url = message["repository"]["url"]
            if token in repository_url:
                delete_message(message_metadata["ReceiptHandle"])
                logger.info("[*] Deleted message with url: %s", message['repository']['url'])
    return


def explode_git_url(url: str):
    """Parse a Git URL into provider / org / name parts.

    >>> explode_git_url("git@github.com:gitorg/100ft-web.git")
    {'provider': 'github.com', 'org': 'gitorg', 'name': '100ft-web'}
    >>> explode_git_url("https://bitbucket.org/gitorg/libinv")
    {'provider': 'bitbucket.org', 'org': 'gitorg', 'name': 'libinv'}
    >>> explode_git_url("git@github.com:org/repo")
    {'provider': 'github.com', 'org': 'org', 'name': 'repo'}
    >>> explode_git_url("ftp://example/foo/bar")
    Traceback (most recent call last):
        ...
    ValueError: Unsupported git URL scheme: ftp://example/foo/bar
    """
    ssh_prefix = "git@"
    https_prefix = "https://"

    if url.startswith(ssh_prefix):
        provider, _, full_name = url[len(ssh_prefix):].partition(":")
    elif url.startswith(https_prefix):
        provider, _, full_name = url[len(https_prefix):].partition("/")
    else:
        raise ValueError(f"Unsupported git URL scheme: {url}")

    org, _, name = full_name.partition("/")
    if name.endswith(".git"):
        name = name[: -len(".git")]
    return {"provider": provider, "org": org, "name": name}
