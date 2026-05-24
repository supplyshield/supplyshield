"""Prometheus /metrics endpoint + request-instrumentation hooks.

Wire up via:
    from libinv.api.metrics import register_metrics
    register_metrics(app)

The ``/metrics`` route is intentionally **unauthenticated**: Prometheus
scrapers do not carry the ``X-API-Token`` header used elsewhere in the
SupplyShield API, and the global auth hook in ``libinv.api.auth`` already
allows all GET requests through (it only guards mutating verbs). Keep
this route GET-only so it remains exempt from the auth check.
"""

from __future__ import annotations

import time

from flask import Flask
from flask import Response
from flask import g
from flask import request
from prometheus_client import CONTENT_TYPE_LATEST
from prometheus_client import CollectorRegistry
from prometheus_client import Counter
from prometheus_client import Gauge
from prometheus_client import Histogram
from prometheus_client import generate_latest

# A dedicated registry keeps libinv metrics isolated from the default
# global one (avoids cross-test contamination and lets us swap in a fresh
# registry if we ever need to).
_registry = CollectorRegistry()

http_requests_total = Counter(
    "libinv_http_requests_total",
    "Total HTTP requests handled by the libinv Flask app.",
    labelnames=("method", "endpoint", "status"),
    registry=_registry,
)
http_request_duration_seconds = Histogram(
    "libinv_http_request_duration_seconds",
    "HTTP request handler duration in seconds.",
    labelnames=("method", "endpoint"),
    registry=_registry,
)
scan_invocations_total = Counter(
    "libinv_scan_invocations_total",
    "Total scan invocations triggered through libinv.",
    labelnames=("type",),
    registry=_registry,
)
up = Gauge(
    "libinv_up",
    "1 if libinv's Flask app is reachable.",
    registry=_registry,
)
up.set(1)


def _before():
    g._metrics_start = time.perf_counter()


def _after(response):
    elapsed = time.perf_counter() - getattr(g, "_metrics_start", time.perf_counter())
    endpoint = request.endpoint or "<unknown>"
    method = request.method
    status = str(response.status_code)
    http_requests_total.labels(method=method, endpoint=endpoint, status=status).inc()
    http_request_duration_seconds.labels(method=method, endpoint=endpoint).observe(elapsed)
    return response


def _metrics_route() -> Response:
    return Response(generate_latest(_registry), mimetype=CONTENT_TYPE_LATEST)


def register_metrics(app: Flask) -> None:
    """Install /metrics + before/after hooks on ``app``.

    The /metrics route is GET-only and therefore exempt from the global
    auth hook (which only guards mutating methods). Do not change that
    without also updating ``libinv.api.auth``.
    """
    app.before_request(_before)
    app.after_request(_after)
    app.add_url_rule("/metrics", view_func=_metrics_route, methods=["GET"])
