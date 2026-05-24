import base64
import json
import os
from pathlib import Path

from dotenv import load_dotenv


load_dotenv()


def _parse_bool(value, default: bool) -> bool:
    """Parse a stringy env-var value into a bool.

    Treats {"1","true","yes","on","y"} (case-insensitive) as True;
    {"0","false","no","off","n",""} as False. Unrecognized values
    raise ValueError (fail-loudly during boot, not silently True).
    """
    if value is None:
        return default
    s = str(value).strip().lower()
    if s in {"1", "true", "yes", "on", "y"}:
        return True
    if s in {"0", "false", "no", "off", "n", ""}:
        return False
    raise ValueError(
        f"Cannot parse {value!r} as bool; "
        "expected one of 1/0, true/false, yes/no, on/off."
    )


def _parse_csv(value, default: list[str] | None = None) -> list[str]:
    """Parse a comma-separated env-var value into a list of stripped strings.

    Empty / unset → returns ``default or []``. Whitespace-only items are
    dropped.
    """
    if value is None or value == "":
        return list(default or [])
    return [item.strip() for item in str(value).split(",") if item.strip()]

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

EXCLUDED_REPOS = _parse_csv(os.getenv("EXCLUDED_REPOS"), default=[])

LIBINV_API_TOKEN = os.getenv("LIBINV_API_TOKEN")

DB_HOSTNAME = os.getenv("DB_HOSTNAME")
DB_NAME = os.getenv("DB_NAME", default="scancodeio")
DB_USERNAME = os.getenv("DB_USERNAME")
DB_PASSWORD = os.getenv("DB_PASSWORD")
DB_STRING = f"postgresql://{DB_USERNAME}:{DB_PASSWORD}@{DB_HOSTNAME}/{DB_NAME}"

IMAGE_SCAN_ENABLED = _parse_bool(os.getenv("IMAGE_SCAN_ENABLED"), default=False)

# Sprint 48.2 — when true, skip the SQLAlchemy reflection in
# ``libinv/scio_models.py`` at import time and replace ``ScanpipeProject`` /
# ``DiscoveredPackage`` with raise-on-access stubs. Callers must use the
# HTTP client exposed by ``libinv.services.scancodeio.get_default_client``
# instead. Any accidental SQL access to scio_models in HTTP mode surfaces
# loud (``RuntimeError``) rather than silently hitting the legacy reflection
# path.
LIBINV_SCIO_USE_HTTP = _parse_bool(os.getenv("LIBINV_SCIO_USE_HTTP"), default=False)

# Sprint 37.1 — when true, register a SQLAlchemy `Mapper.after_configured`
# hook that flips every `relationship()` to `lazy="raise_on_sql"`. This
# turns any implicit attribute access that would issue a query into an
# `InvalidRequestError`, surfacing N+1 patterns during dev/CI. Default
# is intentionally False: production code paths that rely on implicit
# loading would otherwise break.
LIBINV_STRICT_LAZY = _parse_bool(os.getenv("LIBINV_STRICT_LAZY"), default=False)

# Sprint 46.3 — retention horizon (days) for EPSS rows. The
# ``prune_stale_epss_rows`` helper deletes any ``EPSS`` row whose
# ``epss_date`` is older than ``max(epss_date) - retention_days`` after
# each ``EPSS.refresh_cves`` run, preventing the table from growing
# unbounded as the EPSS feed appends new dated rows daily.
LIBINV_EPSS_RETENTION_DAYS = int(os.getenv("LIBINV_EPSS_RETENTION_DAYS", "90"))

JAVA_HOME = json.loads(os.getenv("JAVA_HOME", "{}"))
BASE_IMAGE_JAVA_VERSION_MAPPING = json.loads(os.getenv("BASE_IMAGE_JAVA_VERSION_MAPPING", "{}"))

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


