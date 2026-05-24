"""Sprint 24 — /metrics endpoint tests."""

import pytest

from libinv.api.app import app


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


def test_metrics_endpoint_returns_prometheus_text(client):
    resp = client.get("/metrics")
    assert resp.status_code == 200
    assert resp.content_type.startswith("text/plain")
    body = resp.data.decode("utf-8")
    assert "libinv_up 1.0" in body
    assert "libinv_http_requests_total" in body


def test_metrics_endpoint_records_requests(client):
    client.get("/healthz")  # triggers a request
    resp = client.get("/metrics")
    body = resp.data.decode("utf-8")
    # The healthz request should appear in the counter labels
    assert 'endpoint="health.healthz"' in body or 'endpoint="<unknown>"' in body


def test_metrics_endpoint_no_auth_required(client):
    resp = client.get("/metrics")
    assert resp.status_code == 200
