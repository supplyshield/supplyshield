"""Liveness / readiness probe endpoints.

Designed for Kubernetes / Docker healthchecks. Both endpoints return
JSON. /healthz is always 200 (process-liveness only). /readyz also
verifies the DB connection.
"""

from __future__ import annotations

import logging

from flask import Blueprint
from flask import jsonify
from sqlalchemy import text

from libinv.base import engine

logger = logging.getLogger(__name__)

health = Blueprint("health", __name__)


@health.route("/healthz", methods=["GET"])
def healthz():
    """Process is up — does not check downstream dependencies."""
    return jsonify({"status": "ok"}), 200


@health.route("/readyz", methods=["GET"])
def readyz():
    """Process is ready to serve traffic — verifies DB connection."""
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return jsonify({"status": "ready", "db": "ok"}), 200
    except Exception as exc:
        logger.warning("Readiness check failed: %s", exc)
        return jsonify({"status": "not_ready", "db": "error"}), 503
