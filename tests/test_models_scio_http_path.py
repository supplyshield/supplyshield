"""Verifies models._get_vulnerabilities_count uses ScancodeioClient
when LIBINV_SCIO_USE_HTTP is set."""

import logging
from unittest.mock import MagicMock, patch


class _Apav:
    """Lightweight stand-in exposing only the attributes the method touches.

    Avoids instantiating the real SQLAlchemy mapped class (whose attribute
    descriptors require an active session/state) so this stays a pure unit
    test of the method's branching logic.
    """

    scancode_project_uuid = None

    def __init__(self, scancode_project_uuid):
        self.scancode_project_uuid = scancode_project_uuid


def test_get_vulnerabilities_count_uses_http_when_flag_set():
    """When the env flag is on, the method calls the HTTP client."""
    from libinv.models import ActionablePackageAvailableVersion

    fake_client = MagicMock()
    fake_client.get_vulnerability_count.return_value = 42

    apav = _Apav("uuid-1")

    with patch(
        "libinv.services.scancodeio_client.get_default_client",
        return_value=fake_client,
    ):
        result = ActionablePackageAvailableVersion._get_vulnerabilities_count(apav)

    fake_client.get_vulnerability_count.assert_called_once_with("uuid-1")
    assert result == 42


def test_get_vulnerabilities_count_falls_back_on_http_error(caplog):
    """HTTP failure -> log warning + try SQL."""
    from libinv.models import ActionablePackageAvailableVersion

    fake_client = MagicMock()
    fake_client.get_vulnerability_count.side_effect = RuntimeError("SCIO is down")

    apav = _Apav("uuid-1")

    # Patch DiscoveredPackage to None so SQL path returns 0 quickly
    caplog.set_level(logging.WARNING, logger="libinv.models")
    with patch(
        "libinv.services.scancodeio_client.get_default_client",
        return_value=fake_client,
    ), patch("libinv.models.DiscoveredPackage", None):
        result = ActionablePackageAvailableVersion._get_vulnerabilities_count(apav)

    assert result == 0
    assert "SCIO HTTP get_vulnerability_count failed" in caplog.text


def test_get_vulnerabilities_count_returns_0_when_no_project_uuid():
    """No scancode_project_uuid -> 0, no HTTP call."""
    from libinv.models import ActionablePackageAvailableVersion

    apav = _Apav(None)

    fake_client = MagicMock()
    with patch(
        "libinv.services.scancodeio_client.get_default_client",
        return_value=fake_client,
    ):
        result = ActionablePackageAvailableVersion._get_vulnerabilities_count(apav)
        assert result == 0

    fake_client.get_vulnerability_count.assert_not_called()
