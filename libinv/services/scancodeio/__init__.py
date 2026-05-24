"""
HTTP client for ScanCode.io's REST API.

Replaces the SQL-reflection coupling in ``libinv/scio_models.py`` with a
typed, versioned HTTP contract. Sprint 15 wires each stub to the real
scancodeio REST endpoints (verified against the vendored
``scancode.io/scanpipe/api/views.py`` submodule).

Endpoint map (verified against ``scancode.io/scanpipe/api/views.py``
``ProjectViewSet`` and ``scancode.io/scanpipe/filters.py``):

- ``GET /api/projects/<uuid>/``                  -> project metadata
- ``GET /api/projects/<uuid>/packages/``         -> list discovered packages
                                                   (paginated DRF response;
                                                   ``is_vulnerable=yes`` filter)
- ``GET /api/projects/?wasp_uuid_id=<uuid>``     -> projects linked to a wasp
                                                   (upstream filterset does NOT
                                                   include ``wasp_uuid_id`` --
                                                   see ``endpoints.py`` blocker
                                                   note)

There is **no** dedicated severity-counts or vulnerability-count endpoint
upstream today; ``get_severity_counts``, ``get_vulnerability_count`` and
``list_cve_ids_for_project`` aggregate client-side by paging through
``list_discovered_packages``. A dedicated server-side endpoint would be
materially faster -- see ``TODO(server-endpoint)`` comments in
``endpoints.py``.

Activation: set the environment variable ``LIBINV_SCIO_USE_HTTP=true``.
When unset, callers retain the existing ``scio_models.py`` reflection
path; this client is **inactive scaffolding** until callers are migrated.

Module layout (Sprint 42.1 - 42.4):
    transport.py  -- requests.Session lifecycle + low-level _request_json
    dtos.py       -- TypedDict schema declarations (Sprint 42.3)
    endpoints.py  -- EndpointsMixin with per-endpoint methods (Sprint 42.4)
    __init__.py   -- thin ScancodeioClient facade composing the above
"""

from __future__ import annotations

import logging
import os
from typing import Any
from typing import Dict
from typing import Optional

# Sprint 42.2: transport plumbing extracted to a sibling module so retry /
# backoff / Session lifecycle changes don't churn the endpoint code.
# Re-export the public transport symbols from this package so existing
# `from libinv.services.scancodeio_client import X` shim imports continue
# to resolve.
from libinv.services.scancodeio.transport import ScancodeioError  # noqa: F401
from libinv.services.scancodeio.transport import ScancodeioNotFound  # noqa: F401
from libinv.services.scancodeio.transport import _request_json as _request_json_impl
from libinv.services.scancodeio.transport import build_session

# Sprint 42.3: TypedDict schema declarations moved to a sibling ``dtos``
# module. Re-export every public name so existing call-sites keep
# working (`from libinv.services.scancodeio import DiscoveredPackageDTO`).
from libinv.services.scancodeio.dtos import DiscoveredPackageDTO  # noqa: F401
from libinv.services.scancodeio.dtos import ScanpipeProjectDTO  # noqa: F401
from libinv.services.scancodeio.dtos import SeverityCountDTO  # noqa: F401

# Sprint 42.4: per-endpoint methods extracted to ``endpoints.EndpointsMixin``;
# ``_classify_severity`` follows (the test suite imports it directly from
# the package). Re-export both so existing call-sites stay stable.
from libinv.services.scancodeio.endpoints import EndpointsMixin
from libinv.services.scancodeio.endpoints import _classify_severity  # noqa: F401

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Client facade
# ---------------------------------------------------------------------------


class ScancodeioClient(EndpointsMixin):
    """Stateless HTTP client for the queries libinv makes against scancodeio.

    Sprint 42.4: the per-endpoint methods live in
    ``libinv.services.scancodeio.endpoints.EndpointsMixin``; this class is
    now a thin facade composing Transport + Endpoints. ``__init__`` wires
    the session and timeout/base_url state the mixin reads from ``self``,
    and ``_request_json`` is the local wrapper that the test suite patches
    against (it forwards to ``transport._request_json`` so retry/backoff
    changes only touch the transport module).

    Every endpoint method here corresponds 1:1 with a SQL/ORM access
    pattern catalogued in ``docs/scancodeio_contract.md``.
    """

    def __init__(
        self,
        base_url: str,
        api_key: Optional[str] = None,
        timeout: int = 30,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._timeout = timeout
        # Sprint 42.2: Session lifecycle moved to transport.build_session().
        self._session = build_session(api_key)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _request_json(
        self,
        url: str,
        params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """GET ``url`` and return parsed JSON, mapping HTTP failures to
        typed exceptions.

        Sprint 42.2: the implementation moved to
        ``libinv.services.scancodeio.transport._request_json``. This
        wrapper preserves the method shape (and the ``client._session``
        attribute) that the existing test suite patches against.
        """
        return _request_json_impl(
            self._session, url, self._timeout, params=params
        )


# ---------------------------------------------------------------------------
# Default-client helper
# ---------------------------------------------------------------------------


def get_default_client() -> Optional[ScancodeioClient]:
    """Return a singleton-style client, or ``None`` if HTTP mode is off.

    The HTTP path is opt-in until every caller has migrated. If
    ``LIBINV_SCIO_USE_HTTP`` is unset (or set to anything other than a
    truthy literal), callers fall back to the legacy SQL reflection
    exported by ``libinv/scio_models.py``.
    """
    flag = os.environ.get("LIBINV_SCIO_USE_HTTP", "").lower()
    if flag not in ("true", "1", "yes"):
        return None

    # Imported lazily so this module stays importable in environments that
    # haven't loaded the libinv env (e.g. unit tests for the client itself).
    from libinv.env import SCANCODEIO_API_KEY
    from libinv.env import SCANCODEIO_URL

    if not SCANCODEIO_URL:
        logger.warning(
            "LIBINV_SCIO_USE_HTTP set but SCANCODEIO_URL is empty; "
            "falling back to SQL reflection path."
        )
        return None

    return ScancodeioClient(SCANCODEIO_URL, SCANCODEIO_API_KEY)


__all__ = [
    "DiscoveredPackageDTO",
    "ScancodeioClient",
    "ScancodeioError",
    "ScancodeioNotFound",
    "ScanpipeProjectDTO",
    "SeverityCountDTO",
    "get_default_client",
]
