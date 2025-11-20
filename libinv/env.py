import base64
import json
import os
from pathlib import Path

from dotenv import load_dotenv


load_dotenv()

HOME_DIR = os.getenv("HOME_DIR", default=str(Path.home()))


SYFT_BIN = os.getenv("SYFT_BIN", default="etc/third_party/syft")
GRYPE_BIN = os.getenv("GRYPE_BIN", default="etc/third_party/grype")
CRANE_BIN = os.getenv("CRANE_BIN", default="etc/third_party/crane")
CDXGEN_BIN = os.getenv("CDXGEN_BIN", default="etc/third_party/node_modules/.bin/cdxgen")
NPM_CONFIG_PREFIX = os.getenv("NPM_CONFIG_PREFIX", default="etc/third_party/node_modules")
API_DOCS_FOLDER = os.getenv("API_DOCS_FOLDER", default="/app/docs/_build/html")

AWS_REGION = os.getenv("AWS_DEFAULT_REGION")
SQS_QUEUE_NAME = os.getenv("SQS_QUEUE_NAME")
S3_BUCKET_NAME = os.getenv("S3_BUCKET_NAME")

GIT_SSH_KEY = os.getenv("GIT_SSH_KEY")
GIT_PROVIDER = os.getenv("GIT_PROVIDER")
GIT_ORG = os.getenv("GIT_ORG")

SLACK_URL = os.getenv("SLACK_URL")
SERVICE_METADATA_URL = os.getenv("SERVICE_METADATA_URL")

GO_PRIVATE = os.getenv("GO_PRIVATE")
SCANCODEIO_URL = os.getenv("SCANCODEIO_URL")
SCANCODEIO_API_KEY = os.getenv("SCANCODEIO_API_KEY")
SCANCODE_PIPELINES = ["load_sbom", "find_vulnerabilities", "find_actionables"]

JIRA_URL = os.getenv("JIRA_URL")
JIRA_USER = os.getenv("JIRA_USER")
JIRA_TOKEN = os.getenv("JIRA_TOKEN")

EXCLUDED_REPOS = os.getenv("EXCLUDED_REPOS", default=[])

DB_HOSTNAME = os.getenv("DB_HOSTNAME")
DB_NAME = os.getenv("DB_NAME", default="scancodeio")
DB_USERNAME = os.getenv("DB_USERNAME")
DB_PASSWORD = os.getenv("DB_PASSWORD")
DB_STRING = f"postgresql://{DB_USERNAME}:{DB_PASSWORD}@{DB_HOSTNAME}/{DB_NAME}"

IMAGE_SCAN_ENABLED = os.getenv("IMAGE_SCAN_ENABLED", default=False)

def _load_json_env(var_name, default="{}"):
    raw = os.getenv(var_name)
    if not raw:
        return json.loads(default)
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return json.loads(default)


JAVA_HOME = _load_json_env("JAVA_HOME")
BASE_IMAGE_JAVA_VERSION_MAPPING = _load_json_env("BASE_IMAGE_JAVA_VERSION_MAPPING")

LIBINV_TEMP_DIR = os.getenv("LIBINV_TEMP_DIR", default=f"{HOME_DIR}/scans")

GITHUB_APP_APP_ID = os.getenv("GITHUB_APP_APP_ID")
GITHUB_APP_INSTALLATION_ID = os.getenv("GITHUB_APP_INSTALLATION_ID")
GITHUB_APP_PRIVATE_KEY_FILE = os.getenv(
    "GITHUB_APP_PRIVATE_KEY_FILE", default=f"/{HOME_DIR}/.github_app.pem"
)

BITBUCKET_APP_TOKEN = os.getenv("BITBUCKET_APP_TOKEN")
LIBINV_SERVER = os.getenv("LIBINV_WEB_URL")
PURLDB_API_URL = os.getenv("PURLDB_API_URL", "")
JOBS = json.loads(os.getenv("JOBS", "{}"))