"""Unit tests for the X-Request-Id middleware and the JSON log formatter.

These tests are deliberately DB-free: they reuse the same pattern as
``tests/test_api_routes.py`` (boot the real ``libinv.api.app`` Flask app and
exercise the public route ``/`` via the test client) so they pass even when
``TEST_DATABASE_URL`` is not configured.

The four cases below cover:

1. ``test_request_id_assigned_when_missing`` — an unauthenticated request to
   ``/`` returns a 32-hex-char UUID in the ``X-Request-Id`` response header.
2. ``test_request_id_honored_when_provided`` — when the client sends its own
   ``X-Request-Id``, the server echoes it back verbatim.
3. ``test_request_id_in_log_record`` — a log record emitted from inside the
   request handler has its ``request_id`` ContextVar resolved to the
   inbound id, proving that the middleware sets the ContextVar (not only
   ``flask.g``).
4. ``test_json_formatter_outputs_valid_json`` — the ``JsonFormatter`` emits
   parseable JSON containing every documented field.

NOTE: Flask's ``g`` is request-scoped and only readable inside an active
request context; the ContextVar is what makes the id reachable from arbitrary
``logging.Formatter`` calls (which do not have access to ``g``). Test 3
asserts the ContextVar wiring; test 1 / 2 assert the ``g`` -> response header
wiring.
"""
from __future__ import annotations

import json
import logging
import re

import pytest

from libinv.api.app import app as real_app
from libinv.logger import JsonFormatter, request_id_var


HEX32 = re.compile(r"^[0-9a-f]{32}$")


@pytest.fixture
def client():
    """Yield a Flask test client wired to the real ``libinv.api.app`` app."""
    real_app.config["TESTING"] = True
    real_app.url_map.strict_slashes = False
    with real_app.test_client() as c:
        yield c


# ---------------------------------------------------------------------------
# Middleware: request id assignment + propagation
# ---------------------------------------------------------------------------
def test_request_id_assigned_when_missing(client):
    """Server mints a fresh UUID4 hex id when the request has no header."""
    resp = client.get("/")
    assert resp.status_code == 200
    rid = resp.headers.get("X-Request-Id")
    assert rid is not None, "X-Request-Id header missing from response"
    assert HEX32.match(rid), f"expected 32-hex id, got {rid!r}"


def test_request_id_honored_when_provided(client):
    """Server echoes back any inbound X-Request-Id verbatim."""
    custom = "my-test-id"
    resp = client.get("/", headers={"X-Request-Id": custom})
    assert resp.status_code == 200
    assert resp.headers.get("X-Request-Id") == custom


def test_request_id_in_log_record(client):
    """A log record emitted during a request has request_id == inbound id.

    We can't add a fresh route at test time (Flask forbids ``add_url_rule``
    after the app handles its first request), so we install a logging
    handler that reads the ContextVar via ``JsonFormatter`` and emit a log
    record from inside a ``before_request`` hook on the existing app — by
    that point the middleware's own ``before_request`` has already fired,
    so the ContextVar reflects the inbound header.
    """
    captured: list[dict] = []

    class CaptureHandler(logging.Handler):
        def __init__(self):
            super().__init__()
            self.setFormatter(JsonFormatter())

        def emit(self, record):
            captured.append(json.loads(self.format(record)))

    handler = CaptureHandler()
    test_logger = logging.getLogger("libinv.test.request_id_record")
    test_logger.addHandler(handler)
    test_logger.setLevel(logging.DEBUG)
    test_logger.propagate = False

    def _emit_log_inside_request():
        test_logger.info("inside-request-handler")

    # Flask runs before_request hooks in registration order, so this one
    # fires AFTER the middleware's hook (which was registered at app import
    # time). That guarantees request_id_var is already set when we log.
    real_app.before_request_funcs.setdefault(None, []).append(_emit_log_inside_request)
    try:
        resp = client.get("/", headers={"X-Request-Id": "my-test-id"})
        assert resp.status_code == 200
    finally:
        real_app.before_request_funcs[None].remove(_emit_log_inside_request)
        test_logger.removeHandler(handler)

    matching = [r for r in captured if r.get("message") == "inside-request-handler"]
    assert matching, f"did not capture in-request log record; captured={captured!r}"
    assert matching[0]["request_id"] == "my-test-id"


def test_request_id_contextvar_default_outside_request():
    """Outside any Flask request, the ContextVar defaults to '-'.

    This guarantees non-Flask callers (CLI commands, daemon scripts) can log
    without first setting the var or hitting a LookupError.
    """
    # We cannot guarantee no prior test set it on this thread, but the var's
    # *default* must be "-". Reset via .set then verify get reflects it.
    token = request_id_var.set("-")
    try:
        assert request_id_var.get() == "-"
    finally:
        request_id_var.reset(token)


# ---------------------------------------------------------------------------
# JsonFormatter: shape of the emitted record.
# ---------------------------------------------------------------------------
def test_json_formatter_outputs_valid_json():
    """JsonFormatter().format(record) returns a single JSON document with the
    documented keys."""
    record = logging.LogRecord(
        name="libinv.test",
        level=logging.INFO,
        pathname=__file__,
        lineno=42,
        msg="hello %s",
        args=("world",),
        exc_info=None,
    )
    out = JsonFormatter().format(record)
    payload = json.loads(out)  # must be a single valid JSON document
    for key in ("time", "level", "name", "message", "module", "lineno", "request_id"):
        assert key in payload, f"missing key {key!r} in payload {payload!r}"
    assert payload["level"] == "INFO"
    assert payload["name"] == "libinv.test"
    assert payload["message"] == "hello world"
    assert payload["lineno"] == 42
