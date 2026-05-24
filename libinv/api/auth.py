"""
Token-based auth for SupplyShield API mutating routes.

Configured via the LIBINV_API_TOKEN env var.

Behavior:
- If LIBINV_API_TOKEN is set, any request whose method is PUT/POST/PATCH/DELETE
  must present a matching X-API-Token header (case-insensitive header name).
- If LIBINV_API_TOKEN is unset, mutating requests are refused with HTTP 503
  ("auth not configured") so the deployment fails closed.
- GET/HEAD/OPTIONS are unaffected.
"""

import hmac
import logging

from flask import Flask
from flask import jsonify
from flask import request

from libinv.env import LIBINV_API_TOKEN

logger = logging.getLogger(__name__)

MUTATING_METHODS = {"PUT", "POST", "PATCH", "DELETE"}


def _auth_before_request():
    if request.method not in MUTATING_METHODS:
        return None

    if not LIBINV_API_TOKEN:
        logger.error(
            "Refusing %s %s: LIBINV_API_TOKEN is not configured.",
            request.method,
            request.path,
        )
        return (
            jsonify({"error": "auth not configured on server"}),
            503,
        )

    presented = request.headers.get("X-API-Token", "")
    if not hmac.compare_digest(presented, LIBINV_API_TOKEN):
        logger.warning(
            "Rejected %s %s: bad or missing X-API-Token", request.method, request.path
        )
        return jsonify({"error": "unauthorized"}), 401

    return None


def register_global_auth(app: Flask) -> None:
    """Install the auth check as a before_request hook."""
    app.before_request(_auth_before_request)
    if LIBINV_API_TOKEN:
        logger.info("API auth: enabled (token configured)")
    else:
        logger.warning(
            "API auth: LIBINV_API_TOKEN is not set; mutating requests will be refused 503."
        )
