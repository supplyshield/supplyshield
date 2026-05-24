"""Per-request UUIDs threaded through to every log record.

This module installs a Flask before/after request pair that:

* Reads the inbound ``X-Request-Id`` header, or mints a fresh UUID if missing.
* Stores the id on Flask's request-scoped ``g`` (for handler code).
* Sets the same id on the module-level ``request_id_var`` ContextVar so
  ``JsonFormatter`` (and any other logger that introspects the ContextVar)
  emits it on every record produced inside the request.
* Echoes the id back on the response's ``X-Request-Id`` header so callers
  can correlate logs across services.

Flask's ``g`` is per-request but only readable from handler code; the
ContextVar is what makes the id available from arbitrary library callers
(including logging.Formatter.format) within the same request context.
"""
from __future__ import annotations

import uuid

from flask import Flask, g, request

from libinv.logger import request_id_var


def register_request_id(app: Flask) -> None:
    """Install before_request + after_request hooks that propagate X-Request-Id."""

    @app.before_request
    def _set_request_id() -> None:
        rid = request.headers.get("X-Request-Id") or uuid.uuid4().hex
        g.request_id = rid
        request_id_var.set(rid)

    @app.after_request
    def _emit_request_id(response):
        rid = getattr(g, "request_id", None)
        if rid:
            response.headers["X-Request-Id"] = rid
        return response
