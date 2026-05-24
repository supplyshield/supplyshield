"""Unit tests for libinv.scanners.image_scanner.ecr (Sprint 0-1 hardening).

DB-free, network-free. We bypass the `attrs` post-init (which performs
real boto3 calls and a `crane.registry_login`) by instantiating with
`__new__` and assigning the attributes the methods under test consume.

Sprint 0-1 fixes verified here:

* `get_ecr_creds` uses `removeprefix("https://")` instead of `lstrip`.
  The old `lstrip` was buggy: `"https://stage.amazonaws.com".lstrip("https://")`
  returns `"tage.amazonaws.com"` because `lstrip` treats its argument as a
  character set, not a literal prefix.
* `auth()` writes `~/.docker/config.json` with mode 0600.
* `auth()` writes valid JSON (Sprint 0 replaced a fragile string-concat
  with `json.dumps`).
* `auth()` uses `urlparse(...).netloc` to strip schemes before computing
  the auths key.
"""

import base64
import json
import os
import stat
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


def _make_client_with_token(proxy_endpoint="https://account.dkr.ecr.region.amazonaws.com",
                            user="user", password="pass"):
    """Build an `EcrClient` without running `__attrs_post_init__`.

    `__attrs_post_init__` calls `boto3_ecr_client.get_authorization_token()`
    and `crane.registry_login(**creds)`. We skip both by using `__new__`
    and setting only the attribute `get_ecr_creds` reads.
    """
    from libinv.scanners.image_scanner.ecr import EcrClient

    client = EcrClient.__new__(EcrClient)
    token_value = base64.b64encode(f"{user}:{password}".encode()).decode()
    client.authorization_token = {
        "authorizationData": [
            {"authorizationToken": token_value, "proxyEndpoint": proxy_endpoint}
        ]
    }
    return client


# ---------------------------------------------------------------------------
# get_ecr_creds
# ---------------------------------------------------------------------------
def test_get_ecr_creds_strips_https_scheme():
    """Standard ECR endpoint: 'https://acct.dkr.ecr.region.amazonaws.com'
    should yield a registry without the scheme."""
    client = _make_client_with_token(
        proxy_endpoint="https://account.dkr.ecr.region.amazonaws.com"
    )
    creds = client.get_ecr_creds()
    assert creds["registry"] == "account.dkr.ecr.region.amazonaws.com"
    assert creds["username"] == "user"
    assert creds["password"] == "pass"


def test_get_ecr_creds_lstrip_regression_for_endpoint_starting_with_s_or_t():
    """Regression: `"https://stage.amazonaws.com".lstrip("https://")` yields
    `"tage.amazonaws.com"` (the 's' is also stripped because lstrip operates
    on a character set). `removeprefix` strips the literal prefix only.
    """
    client = _make_client_with_token(proxy_endpoint="https://stage.amazonaws.com")
    creds = client.get_ecr_creds()
    assert creds["registry"] == "stage.amazonaws.com"
    # Belt-and-braces: ensure we are NOT in the broken state.
    assert creds["registry"] != "tage.amazonaws.com"


def test_get_ecr_creds_with_endpoint_that_has_no_scheme():
    """If the endpoint already has no scheme, `removeprefix` leaves it
    unchanged (the old `lstrip` would still mangle it)."""
    client = _make_client_with_token(proxy_endpoint="ttps-prefix.example.com")
    creds = client.get_ecr_creds()
    assert creds["registry"] == "ttps-prefix.example.com"


# ---------------------------------------------------------------------------
# auth() — file mode + JSON validity
# ---------------------------------------------------------------------------
@pytest.fixture
def home_in_tmp(tmp_path, monkeypatch):
    """Redirect `Path.home()` and the `HOME` env var into a tmp dir.

    `auth()` calls `Path.home()` for the docker-dir location, so we
    monkeypatch the class method to return our tmp path. We also set
    `HOME` for defense-in-depth in case anything reads it.
    """
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    return tmp_path


def test_auth_writes_docker_config_with_mode_0600(home_in_tmp):
    """The Docker config file must be created with permission bits 0o600."""
    client = _make_client_with_token(
        proxy_endpoint="https://account.dkr.ecr.region.amazonaws.com",
        user="user",
        password="pw",
    )

    client.auth()

    config_path = home_in_tmp / ".docker" / "config.json"
    assert config_path.exists()
    mode_bits = stat.S_IMODE(os.stat(config_path).st_mode)
    assert mode_bits == 0o600, f"expected 0o600, got {oct(mode_bits)}"


def test_auth_writes_valid_json(home_in_tmp):
    """Sprint 0 replaced a fragile string-concat with json.dumps. Verify
    the file is parseable JSON."""
    client = _make_client_with_token(
        proxy_endpoint="https://account.dkr.ecr.region.amazonaws.com",
        user="user",
        password="pw",
    )

    client.auth()

    config_path = home_in_tmp / ".docker" / "config.json"
    data = json.loads(config_path.read_text())
    assert "auths" in data
    # The registry has the scheme stripped both by `get_ecr_creds` and by
    # urlparse(...).netloc in `auth()`.
    assert "account.dkr.ecr.region.amazonaws.com" in data["auths"]
    auth_entry = data["auths"]["account.dkr.ecr.region.amazonaws.com"]
    assert auth_entry == {"username": "user", "password": "pw"}


def test_auth_uses_urlparse_netloc_to_strip_scheme(home_in_tmp):
    """When the registry value still carries `https://` (or any scheme),
    `urlparse(...).netloc` must strip it before computing the auths key.

    `EcrClient` is an attrs-slotted class so we patch the unbound method on
    the class rather than the instance.
    """
    from libinv.scanners.image_scanner.ecr import EcrClient

    client = _make_client_with_token(
        proxy_endpoint="https://stage.amazonaws.com",
        user="u",
        password="p",
    )
    # Force the post-removeprefix registry to STILL contain a scheme so we
    # can exercise the urlparse path inside `auth()` directly.
    fake_creds = {
        "username": "u",
        "password": "p",
        "registry": "https://stage.amazonaws.com",
    }
    with patch.object(EcrClient, "get_ecr_creds", return_value=fake_creds):
        client.auth()

    config_path = home_in_tmp / ".docker" / "config.json"
    data = json.loads(config_path.read_text())
    # The auths key MUST be the netloc, not include the scheme.
    assert "stage.amazonaws.com" in data["auths"]
    assert "https://stage.amazonaws.com" not in data["auths"]


def test_auth_creates_docker_directory_if_missing(home_in_tmp):
    """`os.makedirs(..., exist_ok=True)` should create `~/.docker` if absent."""
    docker_dir = home_in_tmp / ".docker"
    assert not docker_dir.exists()

    client = _make_client_with_token(
        proxy_endpoint="https://account.dkr.ecr.region.amazonaws.com"
    )
    client.auth()

    assert docker_dir.is_dir()


def test_auth_rewrites_file_preserving_mode(home_in_tmp):
    """Calling auth() twice keeps the file at 0o600 (no widening on rewrite)."""
    client = _make_client_with_token(
        proxy_endpoint="https://account.dkr.ecr.region.amazonaws.com"
    )
    client.auth()
    client.auth()

    config_path = home_in_tmp / ".docker" / "config.json"
    mode_bits = stat.S_IMODE(os.stat(config_path).st_mode)
    assert mode_bits == 0o600
