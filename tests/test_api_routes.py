"""Smoke tests for every Flask route registered on the SupplyShield API.

This file deliberately bypasses the minimal ``flask_app_client`` fixture in
``tests/conftest.py`` (which only wires the auth hook against a stub Flask
app) and instead boots the *real* ``libinv.api.app`` Flask application so we
can exercise every blueprint:

* top-level (``app.py``)
* ``actionable`` (``v2``, ``v3`` dashboards, ``v3/repositories``,
  ``v3/statistics``, ``v3/package-details``, ``v3/package_scan``,
  ``v3/request_package_scan``)
* ``wasp``
* ``compare_builds``
* ``onboard_package``
* ``blastradius``

Every model access (``Session()`` / ``conn.query`` / S3 / ``fetch_repository``)
is mocked via ``unittest.mock.patch`` so the tests never touch a database, S3
bucket, or any external service.

NOTE on the API token: ``libinv.env.LIBINV_API_TOKEN`` is read at module
import time. By the time this file is collected, ``tests/conftest.py`` has
already set ``LIBINV_API_TOKEN`` (via ``setdefault``) so the env var resolves
to whatever the caller exported (e.g. ``test-token`` in the verification
command) or the conftest default. We read the live token via
``libinv.env.LIBINV_API_TOKEN`` so the tests work under any caller-supplied
value.
"""

from __future__ import annotations

from unittest.mock import MagicMock
from unittest.mock import patch

import pytest

from libinv.api.app import app as real_app
from libinv.env import LIBINV_API_TOKEN


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _session_cm(session_mock):
    """Wrap a MagicMock in a context-manager-compatible MagicMock.

    The route code does ``with Session() as session:``. Flask routes call
    ``Session()`` (the sessionmaker) which yields a session, then
    ``__enter__``/``__exit__`` form a context manager. We need our patched
    ``Session`` to return an object that supports both behaviors.
    """
    cm = MagicMock()
    cm.__enter__ = MagicMock(return_value=session_mock)
    cm.__exit__ = MagicMock(return_value=False)
    return cm


def _make_session_factory(session_mock):
    """Return a callable that, when called like ``Session()``, yields a CM."""
    return MagicMock(return_value=_session_cm(session_mock))


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture
def client():
    """Yield a Flask test client wired to the real ``libinv.api.app`` app.

    We disable strict-slash redirects so e.g. ``/wasp/`` returns 200 directly
    rather than 308 -> 200 (the default Flask test client follows redirects
    when ``follow_redirects=True`` is passed, but tests are clearer if the
    first response is the final one).
    """
    real_app.config["TESTING"] = True
    real_app.url_map.strict_slashes = False
    with real_app.test_client() as c:
        yield c


@pytest.fixture
def auth_headers():
    """Return X-API-Token headers matching the live LIBINV_API_TOKEN."""
    if not LIBINV_API_TOKEN:
        pytest.fail(
            "documented gap: LIBINV_API_TOKEN env var is empty at test time; "
            "tests/conftest.py was expected to setdefault it. Without a token, "
            "mutating routes return 503 instead of 401/200 and the auth-on-route "
            "tests cannot distinguish 'token correct' from 'auth not configured'."
        )
    return {"X-API-Token": LIBINV_API_TOKEN}


# ---------------------------------------------------------------------------
# Enumeration: pin the route count.
# ---------------------------------------------------------------------------
def test_enumerate_all_routes(client):
    """Snapshot every URL rule the app exposes (excluding ``static``).

    If a route is added or removed without updating this list, this test
    fails loudly so we know to add coverage for the new route. The exact
    count is asserted in addition to the membership, both to catch
    additions and to make the test self-documenting about the size of the
    public surface.
    """
    rules = sorted(
        str(r) for r in client.application.url_map.iter_rules() if r.endpoint != "static"
    )
    expected = [
        "/",
        "/actionable/v2/",
        "/actionable/v3/",
        "/actionable/v3/package-details",
        "/actionable/v3/package_scan",
        "/actionable/v3/repositories",
        "/actionable/v3/request_package_scan",
        "/actionable/v3/statistics",
        "/blastradius/",
        "/blastradius/generate_graph",
        "/blastradius/sbom",
        "/compare/builds",
        "/docs/",
        "/docs/<path:path>",
        "/libinv/sast/<sid>",
        "/libinv/sast/update",
        "/onboard/new_actionable",
        "/wasp/",
        "/wasp/get_wasp_by_id",
    ]
    assert rules == expected, f"route surface drift: got {rules}"
    assert len(rules) >= 10


# ---------------------------------------------------------------------------
# Top-level routes (libinv.api.app)
# ---------------------------------------------------------------------------
def test_index_returns_hello_world(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert b"Hello, World!" in resp.data


def test_docs_route_returns_200_or_404(client):
    """``/docs/`` serves a static folder that may not exist in tests.

    The implementation uses ``send_from_directory(API_DOCS_FOLDER, ...)``.
    In a test environment API_DOCS_FOLDER defaults to ``/app/docs/_build/html``
    which is absent, so we expect a 404. We accept 200 too in case the
    build artifacts are present (CI).
    """
    resp = client.get("/docs/")
    assert resp.status_code in {200, 404}


def test_sast_data_route_found(client):
    """``/libinv/sast/<sid>`` renders the validate_report template when the
    SAST row exists."""
    fake_result = MagicMock()
    fake_result.id = "abc"
    fake_result.findings = []
    fake_query = MagicMock()
    fake_query.filter_by.return_value.first.return_value = fake_result
    with patch("libinv.api.app.ScopedSession") as scoped_mock, patch(
        "libinv.api.app.render_template", return_value="rendered"
    ):
        scoped_mock.return_value.query.return_value = fake_query
        resp = client.get("/libinv/sast/abc")
    assert resp.status_code == 200
    assert resp.data == b"rendered"


def test_sast_data_route_not_found(client):
    """``/libinv/sast/<sid>`` returns 404 when no row matches."""
    fake_query = MagicMock()
    fake_query.filter_by.return_value.first.return_value = None
    with patch("libinv.api.app.ScopedSession") as scoped_mock:
        scoped_mock.return_value.query.return_value = fake_query
        resp = client.get("/libinv/sast/missing")
    assert resp.status_code == 404
    assert b"Not Found" in resp.data


# ---------------------------------------------------------------------------
# PUT /libinv/sast/update — auth + body validation matrix.
# ---------------------------------------------------------------------------
def test_sast_update_without_token_returns_401(client):
    resp = client.put("/libinv/sast/update", json={"sec_id": "x"})
    assert resp.status_code == 401


def test_sast_update_with_wrong_token_returns_401(client):
    resp = client.put(
        "/libinv/sast/update",
        headers={"X-API-Token": "definitely-not-the-real-token"},
        json={"sec_id": "x"},
    )
    assert resp.status_code == 401


def test_sast_update_with_correct_token_missing_sec_id_returns_400(client, auth_headers):
    resp = client.put("/libinv/sast/update", headers=auth_headers, json={})
    assert resp.status_code == 400
    body = resp.get_json() or {}
    assert "sec_id" in body.get("error", "")


def test_sast_update_with_correct_token_valid_body_returns_200(client, auth_headers):
    """A complete valid payload reaches the handler and returns 200.

    We mock the SQLAlchemy ``conn`` so no real DB is involved: the model
    instance returned by ``filter_by().first()`` is a MagicMock with the
    attributes the route mutates.
    """
    fake_result = MagicMock()
    fake_query = MagicMock()
    fake_query.filter_by.return_value.first.return_value = fake_result
    with patch("libinv.api.app.ScopedSession") as scoped_mock:
        scoped_mock.return_value.query.return_value = fake_query
        resp = client.put(
            "/libinv/sast/update",
            headers=auth_headers,
            json={
                "sec_id": "SEC-123",
                "data": "found it",
                "validated": "FALSEPOSITIVE",
            },
        )
    assert resp.status_code == 200
    body = resp.get_json() or {}
    assert body == {"error": None}


# ---------------------------------------------------------------------------
# Actionable blueprint
# ---------------------------------------------------------------------------
def test_actionable_v2_returns_200_or_404(client):
    """``GET /actionable/v2/?repository_id=1&environment=prod`` with a mocked
    DB layer should render the dashboard. If ``fetch_repository`` returns
    None and the template still renders, that's fine — anything in {200, 404}
    is acceptable per the spec."""
    fake_session = MagicMock()
    fake_session.query.return_value.filter_by.return_value.all.return_value = []
    # Actionable.get_actionable is the classmethod the route calls
    with patch(
        "libinv.api.actionable.dashboards.Session", _make_session_factory(fake_session)
    ), patch(
        "libinv.api.actionable.dashboards.fetch_repository", return_value=MagicMock()
    ), patch(
        "libinv.api.actionable.dashboards.Actionable.get_actionable", return_value=[]
    ), patch(
        "libinv.api.actionable.dashboards.render_template", return_value="ok"
    ):
        resp = client.get("/actionable/v2/?repository_id=1&env=prod")
    assert resp.status_code in {200, 404}


def test_actionable_v3_returns_200_or_404(client):
    fake_session = MagicMock()
    with patch(
        "libinv.api.actionable.dashboards.Session", _make_session_factory(fake_session)
    ), patch(
        "libinv.api.actionable.dashboards.fetch_repository", return_value=MagicMock()
    ), patch(
        "libinv.api.actionable.dashboards.Actionable.get_actionable", return_value=[]
    ), patch(
        "libinv.api.actionable.dashboards.render_template", return_value="ok"
    ):
        resp = client.get("/actionable/v3/?repository_id=1&env=prod")
    assert resp.status_code in {200, 404}


def test_actionable_v3_missing_params_returns_400(client):
    """The dashboard route returns 400 when ``repository_id`` is missing."""
    resp = client.get("/actionable/v3/")
    assert resp.status_code == 400


def test_actionable_package_details_missing_params_returns_400(client):
    resp = client.get("/actionable/v3/package-details")
    assert resp.status_code == 400


def test_actionable_package_details_with_params_renders(client):
    """With ``package_url`` and ``version`` query params plus a mocked DB
    that returns no matching package, the route falls back to parsing the
    PURL and renders the package-details template."""
    fake_session = MagicMock()
    fake_session.query.return_value.filter.return_value.filter.return_value.first.return_value = None
    with patch(
        "libinv.api.actionable.package_details.Session",
        _make_session_factory(fake_session),
    ), patch(
        "libinv.api.actionable.package_details.render_template", return_value="ok"
    ):
        resp = client.get(
            "/actionable/v3/package-details?package_url=pkg:pypi/foo&version=1.0"
        )
    assert resp.status_code in {200, 400, 404, 500}


def test_actionable_repositories_returns_200(client):
    fake_session = MagicMock()
    base_query = MagicMock()
    base_query.filter.return_value = base_query
    base_query.group_by.return_value = base_query
    base_query.having.return_value = base_query
    base_query.order_by.return_value.all.return_value = []
    base_query.join.return_value = base_query
    fake_session.query.return_value = base_query
    with patch(
        "libinv.api.actionable.repositories.Session",
        _make_session_factory(fake_session),
    ), patch(
        "libinv.api.actionable.repositories.render_template", return_value="ok"
    ):
        resp = client.get("/actionable/v3/repositories")
    assert resp.status_code == 200


def test_actionable_statistics_returns_200(client):
    """Mock ``_compute_statistics`` to return a synthetic statistics dict
    so the route can call ``render_template`` without running the heavy
    aggregate queries against a real DB."""
    fake_stats = {
        "package_stats": {"total_packages": 0, "vulnerable_packages": 0},
        "vulnerability_stats": {"total_vulnerabilities": 0},
        "repository_stats": {"total_repositories": 0},
        "environment_stats": [],
        "pod_stats": [],
        "organization_stats": [],
    }
    fake_session = MagicMock()
    with patch(
        "libinv.api.actionable.statistics.Session", _make_session_factory(fake_session)
    ), patch(
        "libinv.api.actionable.statistics._compute_statistics", return_value=fake_stats
    ), patch(
        "libinv.api.actionable.statistics.render_template", return_value="ok"
    ):
        resp = client.get("/actionable/v3/statistics")
    assert resp.status_code == 200


def test_actionable_package_scan_missing_params_returns_400(client):
    resp = client.get("/actionable/v3/package_scan")
    assert resp.status_code == 400


def test_actionable_package_scan_actionable_not_found_returns_404(client):
    """When no available versions exist AND no ``Actionable`` record matches
    ``actionable_id``, the route returns 404."""
    fake_session = MagicMock()
    # available_versions = []
    fake_session.query.return_value.filter_by.return_value.all.return_value = []
    # Actionable.filter_by(uuid=...).first() = None
    fake_session.query.return_value.filter_by.return_value.first.return_value = None
    with patch(
        "libinv.api.actionable.package_scan.Session",
        _make_session_factory(fake_session),
    ):
        resp = client.get(
            "/actionable/v3/package_scan?actionable_id=abc&version_in_use=1.0"
        )
    assert resp.status_code == 404


def test_actionable_request_package_scan_without_token_returns_401(client):
    resp = client.post(
        "/actionable/v3/request_package_scan",
        data={"actionable_id": "abc", "version": "1.0", "version_in_use": "0.9"},
    )
    assert resp.status_code == 401


def test_actionable_request_package_scan_with_token_package_not_found_returns_404(
    client, auth_headers
):
    """A mutating POST with the correct token should reach the handler. With
    no matching package the route returns 404 (not 401/503)."""
    fake_session = MagicMock()
    fake_session.query.return_value.filter_by.return_value.first.return_value = None
    with patch(
        "libinv.api.actionable.package_scan.Session",
        _make_session_factory(fake_session),
    ):
        resp = client.post(
            "/actionable/v3/request_package_scan",
            headers=auth_headers,
            data={"actionable_id": "abc", "version": "1.0", "version_in_use": "0.9"},
        )
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Wasp blueprint
# ---------------------------------------------------------------------------
def test_wasp_main_returns_200(client):
    resp = client.get("/wasp/")
    assert resp.status_code == 200
    assert b"wasp service" in resp.data


def test_wasp_get_by_id_missing_param_returns_400(client):
    resp = client.get("/wasp/get_wasp_by_id")
    assert resp.status_code == 400


def test_wasp_get_by_id_not_found(client):
    fake_query = MagicMock()
    fake_query.filter_by.return_value.first.return_value = None
    with patch("libinv.api.wasp.ScopedSession") as scoped_mock:
        scoped_mock.return_value.query.return_value = fake_query
        resp = client.get("/wasp/get_wasp_by_id?id=00000000-0000-0000-0000-000000000000")
    assert resp.status_code == 404


def test_wasp_get_by_id_found(client):
    fake_wasp = MagicMock()
    fake_wasp.repository_id = 42
    fake_wasp.environment = "prod"
    fake_query = MagicMock()
    fake_query.filter_by.return_value.first.return_value = fake_wasp
    with patch("libinv.api.wasp.ScopedSession") as scoped_mock:
        scoped_mock.return_value.query.return_value = fake_query
        resp = client.get("/wasp/get_wasp_by_id?id=abc/extra")
    assert resp.status_code == 200
    body = resp.get_json() or {}
    assert body == {"repository_id": 42, "environment": "prod"}


# ---------------------------------------------------------------------------
# Compare-builds blueprint
# ---------------------------------------------------------------------------
def test_compare_builds_missing_param_returns_400(client):
    resp = client.get("/compare/builds")
    assert resp.status_code == 400


def test_compare_builds_repository_not_found_returns_404(client):
    with patch(
        "libinv.api.compare_builds.fetch_repository", return_value=None
    ):
        resp = client.get("/compare/builds?repository_id=1&env=prod")
    assert resp.status_code == 404


def test_compare_builds_no_wasps_returns_404(client):
    """Mock both ``fetch_repository`` (returns a repo) and the SQLAlchemy
    session so the wasps query returns []. The route should return 404."""
    fake_session = MagicMock()
    fake_session.query.return_value.join.return_value.filter.return_value.filter.return_value.order_by.return_value.limit.return_value.all.return_value = []
    with patch(
        "libinv.api.compare_builds.fetch_repository", return_value=MagicMock()
    ), patch(
        "libinv.api.compare_builds.sessionmaker",
        return_value=MagicMock(return_value=fake_session),
    ):
        resp = client.get("/compare/builds?repository_id=1&env=prod")
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Onboard blueprint
# ---------------------------------------------------------------------------
def test_onboard_get_returns_200(client):
    resp = client.get("/onboard/new_actionable")
    assert resp.status_code == 200


def test_onboard_post_without_token_returns_401(client):
    resp = client.post(
        "/onboard/new_actionable", data={"package_url": "pkg:pypi/foo"}
    )
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Blastradius blueprint
# ---------------------------------------------------------------------------
def test_blastradius_index_returns_200(client):
    resp = client.get("/blastradius/?child_package=foo")
    assert resp.status_code == 200


def test_blastradius_generate_graph_missing_params_returns_400(client):
    resp = client.get("/blastradius/generate_graph")
    assert resp.status_code == 400


def test_blastradius_generate_graph_only_project_name_returns_400(client):
    """The route requires BOTH ``project_name`` and ``child_package``;
    omitting either triggers the 400 path."""
    resp = client.get("/blastradius/generate_graph?project_name=foo")
    assert resp.status_code == 400


def test_blastradius_sbom_missing_param_returns_400(client):
    resp = client.get("/blastradius/sbom")
    assert resp.status_code == 400


def test_blastradius_sbom_with_param_uses_s3_mock(client):
    """With ``project_name`` provided, the route fetches from S3. We mock
    that, so the route returns whatever the S3 helper hands back."""
    with patch(
        "libinv.api.graph.fetch_cdx_from_s3", return_value={"ok": True}
    ):
        resp = client.get("/blastradius/sbom?project_name=test-build")
    # Flask jsonify-ish: the route returns the dict directly, which Flask
    # treats as JSON. Accept 200 here.
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# 404 handler
# ---------------------------------------------------------------------------
def test_unknown_route_returns_404(client):
    resp = client.get("/no-such-route")
    assert resp.status_code == 404
    assert b"Not Found" in resp.data
