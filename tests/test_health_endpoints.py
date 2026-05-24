"""Sprint 23 — /healthz + /readyz probes."""

from unittest.mock import patch

import pytest
from sqlalchemy.exc import OperationalError


@pytest.fixture
def client():
    from libinv.api.app import app
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


def test_healthz_always_returns_200(client):
    resp = client.get("/healthz")
    assert resp.status_code == 200
    body = resp.get_json()
    assert body == {"status": "ok"}


def test_readyz_returns_200_when_db_ok(client):
    """When engine.connect().execute("SELECT 1") succeeds, status is 'ready'."""
    with patch("libinv.api.health.engine") as engine_mock:
        # Make engine.connect() return a context manager whose .execute works
        conn_cm = engine_mock.connect.return_value
        conn_cm.__enter__ = lambda self_: conn_cm
        conn_cm.__exit__ = lambda self_, et, ev, tb: False
        resp = client.get("/readyz")
    assert resp.status_code == 200
    body = resp.get_json()
    assert body == {"status": "ready", "db": "ok"}


def test_readyz_returns_503_when_db_unavailable(client):
    """When the DB connection raises, status is 'not_ready'."""
    with patch("libinv.api.health.engine") as engine_mock:
        engine_mock.connect.side_effect = OperationalError(
            "SELECT 1", {}, Exception("no db")
        )
        resp = client.get("/readyz")
    assert resp.status_code == 503
    body = resp.get_json()
    assert body == {"status": "not_ready", "db": "error"}


def test_healthz_no_auth_required(client):
    """/healthz GET works without X-API-Token header."""
    resp = client.get("/healthz")
    assert resp.status_code == 200
