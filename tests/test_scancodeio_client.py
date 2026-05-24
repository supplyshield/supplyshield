"""DB-free unit tests for the scancodeio HTTP client (Sprint 15).

Sprint 14 created the client interface with stub methods raising
``NotImplementedError``. Sprint 15 wires each stub to a real HTTP call
against the scancode.io REST API. These tests pin:

  * Endpoint shape for every wired method (URL + timeout + query params).
  * DRF pagination handling for the packages endpoint (follow ``next``).
  * The ``is_vulnerable=yes`` filter is sent only when requested.
  * Client-side aggregation correctness (severities, total counts, CVEs).
  * Error mapping (404 -> ScancodeioNotFound, 5xx logs + raises).
  * ``get_default_client`` opt-in via ``LIBINV_SCIO_USE_HTTP``.

All requests are mocked at the ``_session`` level so the tests run without
a real scancode.io server or any database.
"""

from __future__ import annotations

from unittest.mock import MagicMock
from unittest.mock import patch

import pytest
import requests

from libinv.services.scancodeio_client import ScancodeioClient
from libinv.services.scancodeio_client import ScancodeioError
from libinv.services.scancodeio_client import ScancodeioNotFound
from libinv.services.scancodeio_client import _classify_severity
from libinv.services.scancodeio_client import get_default_client


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _mock_response(json_data, status_code: int = 200):
    """Build a minimal mock ``requests.Response``-like object.

    ``raise_for_status`` raises an ``HTTPError`` for 4xx/5xx, otherwise is
    a no-op, matching the real requests behaviour the client relies on.
    """
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = json_data
    resp.text = str(json_data)
    if status_code >= 400:
        err = requests.exceptions.HTTPError(f"HTTP {status_code}")
        err.response = resp
        resp.raise_for_status.side_effect = err
    else:
        resp.raise_for_status.return_value = None
    return resp


def _make_client() -> ScancodeioClient:
    return ScancodeioClient(
        base_url="http://scio.test",
        api_key="secret-token",
        timeout=42,
    )


# ---------------------------------------------------------------------------
# Authorization header
# ---------------------------------------------------------------------------


def test_authorization_header_uses_token_scheme():
    """scancodeio's DRF TokenAuthentication expects ``Token <key>``."""
    client = ScancodeioClient("http://scio.test", api_key="abc123")
    assert client._session.headers.get("Authorization") == "Token abc123"


def test_no_authorization_header_when_api_key_missing():
    client = ScancodeioClient("http://scio.test", api_key=None)
    assert "Authorization" not in client._session.headers


# ---------------------------------------------------------------------------
# get_project
# ---------------------------------------------------------------------------


def test_get_project_calls_endpoint():
    client = _make_client()
    payload = {"uuid": "abc", "name": "demo"}
    with patch.object(
        client._session, "get", return_value=_mock_response(payload)
    ) as mock_get:
        result = client.get_project("abc")

    assert result == payload
    mock_get.assert_called_once()
    args, kwargs = mock_get.call_args
    # URL is first positional arg.
    assert args[0] == "http://scio.test/api/projects/abc/"
    # timeout must be propagated from the client.
    assert kwargs["timeout"] == 42


# ---------------------------------------------------------------------------
# list_discovered_packages / iter_discovered_packages
# ---------------------------------------------------------------------------


def test_list_discovered_packages_paginates():
    """Two pages should be flattened into one list, following ``next``."""
    client = _make_client()
    page1 = {
        "results": [{"purl": "pkg:npm/a@1"}, {"purl": "pkg:npm/b@2"}],
        "next": "http://scio.test/api/projects/p/packages/?page=2",
    }
    page2 = {
        "results": [{"purl": "pkg:npm/c@3"}],
        "next": None,
    }
    responses = [_mock_response(page1), _mock_response(page2)]
    with patch.object(client._session, "get", side_effect=responses) as mock_get:
        result = client.list_discovered_packages("p")

    assert [p["purl"] for p in result] == [
        "pkg:npm/a@1",
        "pkg:npm/b@2",
        "pkg:npm/c@3",
    ]
    assert mock_get.call_count == 2

    # First call carries the initial params; the second uses the absolute
    # ``next`` URL with params=None to avoid duplicating page_size.
    first_args, first_kwargs = mock_get.call_args_list[0]
    assert first_args[0] == "http://scio.test/api/projects/p/packages/"
    assert first_kwargs["params"] == {"page_size": 1000}
    assert first_kwargs["timeout"] == 42

    second_args, second_kwargs = mock_get.call_args_list[1]
    assert second_args[0] == page1["next"]
    assert second_kwargs["params"] is None


def test_list_discovered_packages_only_vulnerable_filter():
    """``only_vulnerable=True`` must send ``is_vulnerable=yes``."""
    client = _make_client()
    with patch.object(
        client._session,
        "get",
        return_value=_mock_response({"results": [], "next": None}),
    ) as mock_get:
        client.list_discovered_packages("p", only_vulnerable=True)

    _, kwargs = mock_get.call_args
    assert kwargs["params"] == {"page_size": 1000, "is_vulnerable": "yes"}


def test_list_discovered_packages_without_filter_omits_is_vulnerable():
    client = _make_client()
    with patch.object(
        client._session,
        "get",
        return_value=_mock_response({"results": [], "next": None}),
    ) as mock_get:
        client.list_discovered_packages("p", only_vulnerable=False)

    _, kwargs = mock_get.call_args
    assert "is_vulnerable" not in kwargs["params"]


def test_iter_discovered_packages_yields_per_item():
    """Generator variant must yield each result without materialising
    the full list."""
    client = _make_client()
    page = {
        "results": [{"purl": f"pkg:x/p@{i}"} for i in range(3)],
        "next": None,
    }
    with patch.object(
        client._session, "get", return_value=_mock_response(page)
    ):
        items = list(client.iter_discovered_packages("p"))

    assert [p["purl"] for p in items] == ["pkg:x/p@0", "pkg:x/p@1", "pkg:x/p@2"]


# ---------------------------------------------------------------------------
# get_severity_counts
# ---------------------------------------------------------------------------


def test_get_severity_counts_aggregates_locally():
    """Mirror the SQL CTE's bucket assignment in pure Python."""
    client = _make_client()
    packages = {
        "results": [
            {"affected_by_vulnerabilities": [{"severity": "CRITICAL"}]},
            {"affected_by_vulnerabilities": [{"severity": "CRITICAL"}]},
            {"affected_by_vulnerabilities": [{"severity": "HIGH"}]},
            {"affected_by_vulnerabilities": [{"severity": "MODERATE"}]},
            {"affected_by_vulnerabilities": [{"severity": "MEDIUM"}]},
            {"affected_by_vulnerabilities": [{"severity": "LOW"}]},
            {"affected_by_vulnerabilities": [{"severity": "NONE-OF-THE-ABOVE"}]},
            # Empty list must not be counted.
            {"affected_by_vulnerabilities": []},
            # Missing key must not be counted.
            {},
        ],
        "next": None,
    }
    with patch.object(
        client._session, "get", return_value=_mock_response(packages)
    ):
        result = client.get_severity_counts("p")

    counts = {row["severity_level"]: row["count"] for row in result}
    assert counts == {
        "critical": 2,
        "high": 1,
        "medium": 2,  # MODERATE and MEDIUM both bucket to medium
        "low": 1,
        "unknown": 1,
    }
    # Bucket order must match the SQL CTE's ORDER BY.
    assert [row["severity_level"] for row in result] == [
        "critical",
        "high",
        "medium",
        "low",
        "unknown",
    ]


def test_get_severity_counts_all_zero_when_no_packages():
    client = _make_client()
    with patch.object(
        client._session,
        "get",
        return_value=_mock_response({"results": [], "next": None}),
    ):
        result = client.get_severity_counts("p")

    assert all(row["count"] == 0 for row in result)
    assert {row["severity_level"] for row in result} == {
        "critical",
        "high",
        "medium",
        "low",
        "unknown",
    }


def test_classify_severity_precedence():
    """If multiple severities present, the highest wins (CRITICAL > HIGH > ...)."""
    assert _classify_severity(
        [{"severity": "HIGH"}, {"severity": "CRITICAL"}]
    ) == "critical"
    assert _classify_severity([{"severity": "MODERATE"}]) == "medium"
    assert _classify_severity([{"severity": "weird"}]) == "unknown"


# ---------------------------------------------------------------------------
# get_vulnerability_count
# ---------------------------------------------------------------------------


def test_get_vulnerability_count_sums_lengths():
    client = _make_client()
    packages = {
        "results": [
            {"affected_by_vulnerabilities": [{"id": 1}, {"id": 2}]},
            {"affected_by_vulnerabilities": [{"id": 3}]},
            {"affected_by_vulnerabilities": []},
            {},  # missing key still counts as 0
        ],
        "next": None,
    }
    with patch.object(
        client._session, "get", return_value=_mock_response(packages)
    ):
        assert client.get_vulnerability_count("p") == 3


# ---------------------------------------------------------------------------
# list_cve_ids_for_project
# ---------------------------------------------------------------------------


def test_list_cve_ids_dedupes_and_filters_non_cve_aliases():
    client = _make_client()
    packages = {
        "results": [
            {
                "affected_by_vulnerabilities": [
                    {"aliases": ["CVE-2021-1234", "GHSA-aaaa"]},
                    {"aliases": ["CVE-2022-5555"]},
                ],
            },
            {
                # Duplicate CVE-2021-1234 should be de-duped.
                "affected_by_vulnerabilities": [
                    {"aliases": ["CVE-2021-1234", "OSV-1"]}
                ],
            },
            # Edge: missing aliases.
            {"affected_by_vulnerabilities": [{}]},
        ],
        "next": None,
    }
    with patch.object(
        client._session, "get", return_value=_mock_response(packages)
    ):
        cves = client.list_cve_ids_for_project("p")

    assert cves == ["CVE-2021-1234", "CVE-2022-5555"]


# ---------------------------------------------------------------------------
# Error mapping
# ---------------------------------------------------------------------------


def test_404_raises_scancodeio_not_found():
    client = _make_client()
    resp = _mock_response({"detail": "Not found."}, status_code=404)
    with patch.object(client._session, "get", return_value=resp):
        with pytest.raises(ScancodeioNotFound):
            client.get_project("missing")


def test_5xx_logs_and_raises(caplog):
    client = _make_client()
    resp = _mock_response({"detail": "boom"}, status_code=500)
    with patch.object(client._session, "get", return_value=resp):
        with caplog.at_level("ERROR"):
            with pytest.raises(ScancodeioError):
                client.get_project("p")

    assert any("500" in rec.message for rec in caplog.records)


def test_connection_error_wraps_as_scancodeio_error():
    client = _make_client()
    with patch.object(
        client._session,
        "get",
        side_effect=requests.exceptions.ConnectionError("refused"),
    ):
        with pytest.raises(ScancodeioError) as excinfo:
            client.get_project("p")
    # The URL must appear in the wrapper message for debuggability.
    assert "/api/projects/p/" in str(excinfo.value)


# ---------------------------------------------------------------------------
# list_projects_for_wasp deliberately remains NotImplementedError
# ---------------------------------------------------------------------------


def test_list_projects_for_wasp_still_not_implemented():
    """``wasp_uuid_id`` is not in the upstream ProjectFilterSet; the method
    must NOT silently call an unfiltered endpoint."""
    client = _make_client()
    with pytest.raises(NotImplementedError):
        client.list_projects_for_wasp("any-uuid")


# ---------------------------------------------------------------------------
# get_default_client
# ---------------------------------------------------------------------------


def test_get_default_client_returns_none_when_flag_unset(monkeypatch):
    monkeypatch.delenv("LIBINV_SCIO_USE_HTTP", raising=False)
    assert get_default_client() is None


def test_get_default_client_returns_none_when_flag_falsy(monkeypatch):
    monkeypatch.setenv("LIBINV_SCIO_USE_HTTP", "false")
    assert get_default_client() is None


def test_get_default_client_returns_client_when_flag_set(monkeypatch):
    monkeypatch.setenv("LIBINV_SCIO_USE_HTTP", "true")
    # Patch the lazy import targets so we don't depend on real env config.
    import libinv.env

    monkeypatch.setattr(libinv.env, "SCANCODEIO_URL", "http://scio.test", raising=False)
    monkeypatch.setattr(
        libinv.env, "SCANCODEIO_API_KEY", "token-xyz", raising=False
    )

    client = get_default_client()
    assert isinstance(client, ScancodeioClient)
    assert client._base_url == "http://scio.test"
    assert client._session.headers.get("Authorization") == "Token token-xyz"


def test_get_default_client_returns_none_when_url_empty(monkeypatch):
    """Even if the opt-in flag is set, an empty SCANCODEIO_URL must
    fall back to the SQL reflection path (and log)."""
    monkeypatch.setenv("LIBINV_SCIO_USE_HTTP", "true")
    import libinv.env

    monkeypatch.setattr(libinv.env, "SCANCODEIO_URL", "", raising=False)
    monkeypatch.setattr(libinv.env, "SCANCODEIO_API_KEY", None, raising=False)
    assert get_default_client() is None
