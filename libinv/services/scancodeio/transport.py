"""
Low-level HTTP transport plumbing for the ScanCode.io REST client.

Sprint 42.2: extracted from ``scancodeio/__init__.py`` to isolate the
``requests.Session`` lifecycle and the ``_request_json`` helper from the
higher-level ``ScancodeioClient`` facade. Keeping transport concerns in a
dedicated module makes it easier to add retry/backoff or alternate
transports (e.g. a recording session for tests) without touching the
endpoint methods.

Exposed symbols are re-exported from ``libinv.services.scancodeio``'s
``__init__.py`` so existing call-sites (and the
``libinv/services/scancodeio_client.py`` shim) keep working unchanged.
"""

from __future__ import annotations

import logging
from typing import Any
from typing import Dict
from typing import Optional

import requests

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class ScancodeioError(Exception):
    """Base error for all scancodeio HTTP client failures."""


class ScancodeioNotFound(ScancodeioError):
    """Raised on HTTP 404 from the scancodeio REST API."""


# ---------------------------------------------------------------------------
# Session construction
# ---------------------------------------------------------------------------


def build_session(api_key: Optional[str] = None) -> requests.Session:
    """Construct a ``requests.Session`` pre-configured for scancodeio.

    scancodeio uses DRF TokenAuthentication; the header format is exactly
    ``Authorization: Token <key>`` (see
    ``scancode.io/scancodeio/settings.py`` REST_FRAMEWORK config).
    """
    session = requests.Session()
    if api_key:
        session.headers["Authorization"] = f"Token {api_key}"
    return session


# ---------------------------------------------------------------------------
# Request helper
# ---------------------------------------------------------------------------


def _request_json(
    session: requests.Session,
    url: str,
    timeout: int,
    params: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """GET ``url`` and return parsed JSON, mapping HTTP failures to typed
    exceptions.

    - 404 -> ``ScancodeioNotFound`` (callers may want to treat missing
      projects differently than other failures).
    - 5xx -> log + re-raise as ``ScancodeioError``.
    - Connection errors / timeouts -> wrap as ``ScancodeioError`` with the
      request URL in the message for debuggability.

    Sprint 42.2: the return annotation is ``Dict[str, Any]`` (the parsed
    JSON object). Endpoint methods that need a narrower TypedDict shape
    use ``typing.cast`` at the call-site -- mypy can't narrow JSON shape
    on its own.
    """
    try:
        resp = session.get(url, params=params, timeout=timeout)
    except requests.exceptions.RequestException as exc:
        # Connection refused, DNS failure, timeout, etc. -- wrap with
        # context so the caller doesn't have to guess which call failed.
        raise ScancodeioError(
            f"scancodeio request failed for {url}: {exc}"
        ) from exc

    if resp.status_code == 404:
        raise ScancodeioNotFound(
            f"scancodeio resource not found: {url}"
        )

    if 500 <= resp.status_code < 600:
        logger.error(
            "scancodeio server error %s for %s: %s",
            resp.status_code,
            url,
            resp.text[:500],
        )
        # raise_for_status produces a clear chained traceback; wrap so
        # callers can catch a single base class.
        try:
            resp.raise_for_status()
        except requests.exceptions.HTTPError as exc:
            raise ScancodeioError(
                f"scancodeio {resp.status_code} for {url}"
            ) from exc

    resp.raise_for_status()
    data: Dict[str, Any] = resp.json()
    return data


__all__ = [
    "ScancodeioError",
    "ScancodeioNotFound",
    "build_session",
    "_request_json",
]
