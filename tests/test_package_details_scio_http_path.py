"""Verifies ``libinv/api/actionable/package_details.py`` routes through
``ScancodeioClient.list_discovered_packages`` when ``LIBINV_SCIO_USE_HTTP``
is set, and falls back to the SQL path otherwise (or on HTTP failure).

The route accepts ``package_url`` and ``version`` query params. To exercise
the HTTP branch we need an ``ActionablePackageAvailableVersion`` row with a
non-null ``scancode_project_uuid`` -- everything else (Session, render
template) is mocked so the test never touches a real DB.
"""

from __future__ import annotations

from unittest.mock import MagicMock
from unittest.mock import patch

import pytest

from libinv.api.app import app as real_app


# ---------------------------------------------------------------------------
# Local fixtures (kept self-contained so we do not depend on import order
# from tests/test_api_routes.py).
# ---------------------------------------------------------------------------
def _session_cm(session_mock):
    """Wrap ``session_mock`` so ``with Session() as s`` yields it."""
    cm = MagicMock()
    cm.__enter__ = MagicMock(return_value=session_mock)
    cm.__exit__ = MagicMock(return_value=False)
    return cm


def _make_session_factory(session_mock):
    return MagicMock(return_value=_session_cm(session_mock))


@pytest.fixture
def client():
    real_app.config["TESTING"] = True
    real_app.url_map.strict_slashes = False
    with real_app.test_client() as c:
        yield c


def _fake_session_with_actionable_package():
    """Build a session mock that returns a stub ``ActionablePackageAvailableVersion``.

    The route calls ``session.query(...).filter(...).filter(...).first()``
    twice (once outside the ``with Session()`` block, once inside if the
    first lookup missed). Returning the same stub package from both keeps
    the CVE-extraction branch live so we can assert the HTTP client was
    called.
    """
    fake_pkg = MagicMock()
    fake_pkg.scancode_project_uuid = "proj-uuid-1"
    fake_pkg.uuid = "ap-uuid-1"
    fake_pkg.parsed_purl = MagicMock(type="pypi", namespace=None, name="foo")

    fake_session = MagicMock()
    chain = fake_session.query.return_value.filter.return_value.filter.return_value
    chain.first.return_value = fake_pkg

    # Anything else queried (EPSS, Repository_* join) returns empty lists
    # so the route renders cleanly.
    fake_session.query.return_value.filter.return_value.all.return_value = []
    join_chain = fake_session.query.return_value.join.return_value
    join_chain.filter.return_value.all.return_value = []
    return fake_session


def test_http_path_used_when_client_available(client):
    """When ``get_default_client`` returns a real client, the route MUST
    call ``list_discovered_packages`` instead of running the SQL query."""
    fake_client = MagicMock()
    fake_client.list_discovered_packages.return_value = [
        {
            "name": "foo",
            "version": "1.0",
            "affected_by_vulnerabilities": [
                {"aliases": ["CVE-2024-0001"]},
            ],
        },
    ]
    fake_session = _fake_session_with_actionable_package()

    with patch(
        "libinv.api.actionable.package_details.Session",
        _make_session_factory(fake_session),
    ), patch(
        "libinv.api.actionable.package_details.get_default_client",
        return_value=fake_client,
    ), patch(
        "libinv.api.actionable.package_details.render_template",
        return_value="ok",
    ):
        resp = client.get(
            "/actionable/v3/package-details?package_url=pkg:pypi/foo&version=1.0"
        )

    # Status can be 200 (renders) or any handled error; what matters is the
    # HTTP client was consulted and the SQL DiscoveredPackage path skipped.
    assert resp.status_code in {200, 400, 404, 500}
    fake_client.list_discovered_packages.assert_called_once_with("proj-uuid-1")


def test_sql_path_when_client_unavailable(client):
    """Without the flag (``get_default_client`` returns ``None``) the route
    falls back to ``session.query(DiscoveredPackage)`` -- legacy behaviour."""
    fake_session = _fake_session_with_actionable_package()

    with patch(
        "libinv.api.actionable.package_details.Session",
        _make_session_factory(fake_session),
    ), patch(
        "libinv.api.actionable.package_details.get_default_client",
        return_value=None,
    ), patch(
        "libinv.api.actionable.package_details.render_template",
        return_value="ok",
    ):
        resp = client.get(
            "/actionable/v3/package-details?package_url=pkg:pypi/foo&version=1.0"
        )

    assert resp.status_code in {200, 400, 404, 500}
    # The SQL path must have been exercised: the DiscoveredPackage query
    # uses ``.filter(...).all()`` (not the ``.filter(...).filter(...).first()``
    # chain used for ActionablePackageAvailableVersion). Asserting ``.all()``
    # was hit on the single-filter chain is a clean proxy.
    fake_session.query.return_value.filter.return_value.all.assert_called()


def test_http_failure_falls_back_to_sql(client):
    """If ``list_discovered_packages`` raises, the route must log a warning
    and continue with the SQL path so the response is still produced."""
    fake_client = MagicMock()
    fake_client.list_discovered_packages.side_effect = RuntimeError("boom")
    fake_session = _fake_session_with_actionable_package()

    with patch(
        "libinv.api.actionable.package_details.Session",
        _make_session_factory(fake_session),
    ), patch(
        "libinv.api.actionable.package_details.get_default_client",
        return_value=fake_client,
    ), patch(
        "libinv.api.actionable.package_details.render_template",
        return_value="ok",
    ):
        resp = client.get(
            "/actionable/v3/package-details?package_url=pkg:pypi/foo&version=1.0"
        )

    # HTTP was tried, then SQL fallback executed.
    fake_client.list_discovered_packages.assert_called_once()
    fake_session.query.return_value.filter.return_value.all.assert_called()
    assert resp.status_code in {200, 400, 404, 500}
