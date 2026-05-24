"""Sprint 21 - verifies cli/epss.py routes through ScancodeioClient
when LIBINV_SCIO_USE_HTTP is set.

The test exercises the extracted ``_collect_cves_for_projects`` helper
directly so neither a real database nor a Click runner is required. The
helper is the single branch point between the legacy SQL reflection path
and the new HTTP client path; verifying both branches here pins the
contract enforced by the feature flag.
"""

from __future__ import annotations

from unittest.mock import MagicMock
from unittest.mock import patch

import pytest


@pytest.fixture
def http_flag(monkeypatch):
    """Enable the HTTP code path via env vars."""
    monkeypatch.setenv("LIBINV_SCIO_USE_HTTP", "true")
    monkeypatch.setenv("SCANCODEIO_URL", "http://scancodeio.local")
    yield


def test_cli_epss_uses_http_client_when_flag_set(http_flag):
    """When the env flag is on, the loop calls
    ``ScancodeioClient.list_cve_ids_for_project`` instead of the SQL path."""
    fake_client = MagicMock()
    fake_client.list_cve_ids_for_project.return_value = [
        "CVE-2024-0001",
        "CVE-2024-0002",
    ]
    with patch("libinv.cli.epss.get_default_client", return_value=fake_client):
        # Call the helper directly (NOT via Click) so we don't need a real
        # DB to exercise the branch.
        from libinv.cli.epss import _collect_cves_for_projects

        cves = _collect_cves_for_projects(
            session=MagicMock(),
            project_uuids=["uuid-1", "uuid-2"],
            verbose=False,
        )

    fake_client.list_cve_ids_for_project.assert_any_call("uuid-1")
    fake_client.list_cve_ids_for_project.assert_any_call("uuid-2")
    assert cves == {"CVE-2024-0001", "CVE-2024-0002"}


def test_cli_epss_falls_back_to_sql_when_flag_unset():
    """Without the flag, ``get_default_client`` returns ``None``; SQL path
    is used and GHSA aliases are filtered out.

    Sprint 38.1: the SQL path now issues a single bulk ``WHERE project_id
    IN (:ids)`` query and groups results by ``project_id`` in Python. The
    mock must return a package whose ``project_id`` matches the input so
    the grouping step finds it.
    """
    fake_session = MagicMock()
    fake_pkg = MagicMock()
    fake_pkg.project_id = "uuid-1"
    fake_pkg.affected_by_vulnerabilities = [
        {"aliases": ["CVE-2024-9999", "GHSA-xxxx"]},
    ]
    fake_session.query.return_value.filter.return_value.all.return_value = [
        fake_pkg
    ]
    with patch("libinv.cli.epss.get_default_client", return_value=None):
        from libinv.cli.epss import _collect_cves_for_projects

        cves = _collect_cves_for_projects(
            session=fake_session,
            project_uuids=["uuid-1"],
            verbose=False,
        )

    assert cves == {"CVE-2024-9999"}  # GHSA filtered out
