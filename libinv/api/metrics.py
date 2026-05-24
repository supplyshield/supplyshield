"""Prometheus /metrics endpoint + request-instrumentation hooks.

Wire up via:
    from libinv.api.metrics import register_metrics
    register_metrics(app)

The ``/metrics`` route is GET-only and skips the SupplyShield
``X-API-Token`` global auth path. When ``LIBINV_METRICS_TOKEN`` is set
in the environment, the route additionally requires
``Authorization: Bearer <token>`` and returns 401 on mismatch (Sprint
51.2). When unset, the route stays open (Sprint 24 baseline). The
compare uses ``hmac.compare_digest`` to avoid timing side-channels.
"""

from __future__ import annotations

import hmac
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

from libinv.env import LIBINV_METRICS_TOKEN

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
scan_failures_total = Counter(
    "libinv_scan_failures_total",
    "Total scan failures (exceptions raised in scan entry points).",
    labelnames=("type", "error_class"),
    registry=_registry,
)
# Sprint 27: scan-duration histogram. Buckets span seconds (cdxgen on
# small repos) to ~1h (scancodeio on large monorepos), so we use explicit
# buckets covering 3 orders of magnitude instead of the prometheus
# default (which tops out at ~10s).
SCAN_DURATION_BUCKETS = (
    1, 5, 10, 30, 60, 120, 300, 600, 1200, 1800, 3600, float("inf"),
)
scan_duration_seconds = Histogram(
    "libinv_scan_duration_seconds",
    "Wall-clock time of scan invocations.",
    labelnames=("type",),
    buckets=SCAN_DURATION_BUCKETS,
    registry=_registry,
)
# Sprint 28: per-finding SAST counter. Incremented once per SARIF result
# AFTER it is persisted by ``SarifResult.add_sarif_result_to_db`` (whether
# the persistence path was insert OR update). Severity is normalized to a
# bounded set so prometheus cardinality stays predictable even when an
# upstream tool emits non-standard ``level`` strings.
sast_findings_total = Counter(
    "libinv_sast_findings_total",
    "Total SAST findings persisted by SarifResult.",
    labelnames=("severity", "tool"),
    registry=_registry,
)
# Sprint 52.3 — SQS poison-message visibility. Incremented in
# ``libinv/cli/daemon.py`` whenever ``process_message`` raises. The
# ``reason`` label carries the exception class name (bounded set —
# ``RuntimeError``, ``TimeoutExpired``, ``ConnectionError``, etc.) so
# Prometheus cardinality stays predictable. Pair with the queue's
# RedrivePolicy (``maxReceiveCount=5`` in docs/deployment.rst) so a
# spike in this counter correlates with messages landing in the DLQ.
sqs_messages_failed_total = Counter(
    "libinv_sqs_messages_failed_total",
    "Total SQS messages that raised in process_message (poison candidates).",
    labelnames=("reason",),
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


def _bearer_token_from_header() -> str:
    """Return the bearer token in the Authorization header, or ``""``.

    Accepts both ``Bearer <token>`` and ``bearer <token>``; any other
    auth scheme (Basic, Token, etc.) yields the empty string so it
    cannot collide with the expected scheme.
    """
    raw = request.headers.get("Authorization", "")
    scheme, _, value = raw.partition(" ")
    if scheme.lower() != "bearer":
        return ""
    return value.strip()


def _metrics_route() -> Response:
    # Sprint 51.2 — opt-in Bearer-token auth. If ``LIBINV_METRICS_TOKEN``
    # is unset we keep the Sprint 24 contract (open endpoint). When set,
    # require a matching ``Authorization: Bearer <token>`` header and
    # use ``hmac.compare_digest`` to avoid timing side-channels.
    if LIBINV_METRICS_TOKEN:
        presented = _bearer_token_from_header()
        if not presented or not hmac.compare_digest(presented, LIBINV_METRICS_TOKEN):
            return Response("Unauthorized", status=401, mimetype="text/plain")
    return Response(generate_latest(_registry), mimetype=CONTENT_TYPE_LATEST)


def register_metrics(app: Flask) -> None:
    """Install /metrics + before/after hooks on ``app``.

    The /metrics route is GET-only and therefore exempt from the global
    ``X-API-Token`` auth hook (which only guards mutating methods). When
    ``LIBINV_METRICS_TOKEN`` is set in the environment, the route
    enforces its own ``Authorization: Bearer`` check (Sprint 51.2).
    """
    app.before_request(_before)
    app.after_request(_after)
    app.add_url_rule("/metrics", view_func=_metrics_route, methods=["GET"])
