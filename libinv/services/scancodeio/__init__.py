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
                                                   see TODO below)

There is **no** dedicated severity-counts or vulnerability-count endpoint
upstream today; ``get_severity_counts``, ``get_vulnerability_count`` and
``list_cve_ids_for_project`` aggregate client-side by paging through
``list_discovered_packages``. A dedicated server-side endpoint would be
materially faster -- see ``TODO(server-endpoint)`` comments below.

Activation: set the environment variable ``LIBINV_SCIO_USE_HTTP=true``.
When unset, callers retain the existing ``scio_models.py`` reflection
path; this client is **inactive scaffolding** until callers are migrated.
"""

from __future__ import annotations

import logging
import os
from typing import Any
from typing import Dict
from typing import Iterator
from typing import List
from typing import Optional
from typing import Set
from typing import TypedDict
from typing import cast

# Sprint 42.2: transport plumbing extracted to a sibling module so retry /
# backoff / Session lifecycle changes don't churn the endpoint code below.
# Re-export the public transport symbols from this package so existing
# `from libinv.services.scancodeio_client import X` shim imports continue
# to resolve.
from libinv.services.scancodeio.transport import ScancodeioError  # noqa: F401
from libinv.services.scancodeio.transport import ScancodeioNotFound  # noqa: F401
from libinv.services.scancodeio.transport import _request_json as _request_json_impl
from libinv.services.scancodeio.transport import build_session

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Typed return shapes
# ---------------------------------------------------------------------------


class DiscoveredPackageDTO(TypedDict, total=False):
    """Mirror of ``scanpipe_discoveredpackage`` columns libinv reads.

    Only the fields actually consumed by libinv are listed; the upstream
    serializer returns many more (license metadata, file paths, etc.).
    """

    purl: str
    type: str
    namespace: str
    name: str
    version: str
    qualifiers: str
    project_id: str
    affected_by_vulnerabilities: List[dict]


class SeverityCountDTO(TypedDict):
    """One row of the severity aggregate currently built via raw SQL."""

    severity_level: str
    count: int


class ScanpipeProjectDTO(TypedDict, total=False):
    """Subset of ``scanpipe_project`` columns libinv reads."""

    uuid: str
    name: str
    wasp_uuid_id: str


# ---------------------------------------------------------------------------
# Exceptions (re-exported from .transport for backwards compatibility)
# ---------------------------------------------------------------------------
# Sprint 42.2: `ScancodeioError` and `ScancodeioNotFound` now live in
# `libinv.services.scancodeio.transport`. They are re-exported above via
# the `from .transport import ...` block so existing imports
# (`from libinv.services.scancodeio_client import ScancodeioError`) keep
# working unchanged.


# ---------------------------------------------------------------------------
# Severity classification (mirrors the SQL CTE in libinv/models.py)
# ---------------------------------------------------------------------------

# Order matters: the SQL CTE returns severities in this canonical order.
_SEVERITY_LEVELS = ("critical", "high", "medium", "low", "unknown")


def _classify_severity(vulns: List[dict]) -> str:
    """Return the highest severity level represented in a vulnerabilities list.

    Mirrors the CASE expression in
    ``libinv/models.py::ActionablePackageAvailableVersion.vulnerability_severities``::

        CRITICAL -> critical
        HIGH     -> high
        MEDIUM / MODERATE -> medium
        LOW      -> low
        otherwise -> unknown

    The check is against the string representation of each list element,
    matching ``elem::varchar LIKE '%CRITICAL%'`` semantics from the CTE.
    """
    haystack = repr(vulns).upper()
    if "CRITICAL" in haystack:
        return "critical"
    if "HIGH" in haystack:
        return "high"
    if "MEDIUM" in haystack or "MODERATE" in haystack:
        return "medium"
    if "LOW" in haystack:
        return "low"
    return "unknown"


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------


class ScancodeioClient:
    """Stateless HTTP client for the queries libinv makes against scancodeio.

    Every method here corresponds 1:1 with a SQL/ORM access pattern catalogued
    in ``docs/scancodeio_contract.md``.
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

    # ------------------------------------------------------------------
    # Project-level reads
    # ------------------------------------------------------------------

    def get_project(self, project_uuid: str) -> ScanpipeProjectDTO:
        """Return project metadata.

        Wraps ``GET /api/projects/<uuid>/`` (the retrieve action provided by
        ``mixins.RetrieveModelMixin`` on ``ProjectViewSet`` --
        ``scancode.io/scanpipe/api/views.py``).
        """
        url = f"{self._base_url}/api/projects/{project_uuid}/"
        return cast(ScanpipeProjectDTO, self._request_json(url))

    def list_projects_for_wasp(self, wasp_uuid: str) -> List[ScanpipeProjectDTO]:
        """Return every scanpipe project whose ``wasp_uuid_id`` matches.

        Replaces the JOIN in ``libinv/api/compare_builds.py``.

        NOTE: ``wasp_uuid_id`` is a SupplyShield-specific column added to
        ``scanpipe_project``; the upstream ``ProjectFilterSet`` (see
        ``scancode.io/scanpipe/api/views.py``, ``Meta.fields``) does NOT
        accept it as a filter parameter. Wiring this to a real call without
        first extending the upstream filterset would silently return the
        unfiltered project list -- worse than failing loudly. Leaving as
        NotImplementedError until either:

        1. an upstream patch adds ``wasp_uuid_id`` to ``ProjectFilterSet``,
           or
        2. a SupplyShield-side proxy endpoint is added that handles the
           filter.
        """
        # TODO(server-endpoint): wire to GET /api/projects/?wasp_uuid_id=<uuid>
        # once ProjectFilterSet (scanpipe/api/views.py) supports the param.
        raise NotImplementedError(
            "Upstream ProjectFilterSet does not accept ``wasp_uuid_id``. "
            "Extend ProjectFilterSet upstream or add a SupplyShield-side "
            "endpoint before enabling this method."
        )

    # ------------------------------------------------------------------
    # Discovered packages
    # ------------------------------------------------------------------

    def _packages_url(self, project_uuid: str) -> str:
        return f"{self._base_url}/api/projects/{project_uuid}/packages/"

    def _packages_initial_params(
        self,
        only_vulnerable: bool,
    ) -> Dict[str, Any]:
        """Build the initial query params for the packages endpoint.

        ``is_vulnerable=yes`` matches the upstream ``IsVulnerable`` filter
        (``scancode.io/scanpipe/filters.py`` line ~620), which filters on
        ``affected_by_vulnerabilities`` not being empty.
        """
        params: Dict[str, Any] = {"page_size": 1000}
        if only_vulnerable:
            params["is_vulnerable"] = "yes"
        return params

    def list_discovered_packages(
        self,
        project_uuid: str,
        only_vulnerable: bool = False,
    ) -> List[DiscoveredPackageDTO]:
        """Return every discovered package for the given scancodeio project.

        Wraps ``GET /api/projects/<uuid>/packages/`` (the ``packages``
        ``@action`` on ``ProjectViewSet`` -- paginated via DRF). Follows
        the ``next`` cursor until exhausted.

        When ``only_vulnerable=True``, sends ``is_vulnerable=yes`` (matches
        the upstream ``IsVulnerable`` filter on ``PackageFilterSet``).
        """
        return list(self.iter_discovered_packages(project_uuid, only_vulnerable))

    def iter_discovered_packages(
        self,
        project_uuid: str,
        only_vulnerable: bool = False,
    ) -> Iterator[DiscoveredPackageDTO]:
        """Generator variant of ``list_discovered_packages``.

        Yields packages one at a time so the EPSS batch job (and similar
        long walks over many projects) can stream instead of materialising
        every package up front.
        """
        url: Optional[str] = self._packages_url(project_uuid)
        params: Optional[Dict[str, Any]] = self._packages_initial_params(
            only_vulnerable
        )
        while url:
            data = self._request_json(url, params=params)
            for pkg in data.get("results", []):
                yield pkg
            # DRF's PageNumberPagination returns the next absolute URL with
            # the query string baked in -- do not re-send params on the
            # follow-up request or we'd double the page_size param.
            url = data.get("next")
            params = None

    # ------------------------------------------------------------------
    # Derived aggregates
    # ------------------------------------------------------------------

    def get_severity_counts(self, project_uuid: str) -> List[SeverityCountDTO]:
        """Return per-severity vulnerability counts for the project.

        Replaces the raw ``text(...)`` CTE in
        ``libinv/models.py::ActionablePackageAvailableVersion.vulnerability_severities``.

        Result shape::

            [
                {"severity_level": "critical", "count": 4},
                {"severity_level": "high",     "count": 12},
                {"severity_level": "medium",   "count": 7},
                {"severity_level": "low",      "count": 1},
                {"severity_level": "unknown",  "count": 0},
            ]

        The five severity buckets are always present (count=0 if absent),
        matching the upstream CTE that LEFT JOINs against a VALUES table.

        TODO(server-endpoint): the SQL CTE aggregates in the database in a
        single round trip; doing the same over HTTP requires paging the
        full package list. Add ``GET /api/projects/<uuid>/severity-counts/``
        upstream so this can be a constant-time call.
        """
        counts: Dict[str, int] = {level: 0 for level in _SEVERITY_LEVELS}
        for pkg in self.iter_discovered_packages(
            project_uuid, only_vulnerable=True
        ):
            vulns = pkg.get("affected_by_vulnerabilities") or []
            if not vulns:
                continue
            level = _classify_severity(vulns)
            counts[level] = counts.get(level, 0) + 1
        return [
            {"severity_level": level, "count": counts[level]}
            for level in _SEVERITY_LEVELS
        ]

    def get_vulnerability_count(self, project_uuid: str) -> int:
        """Return the total vulnerability count across the project.

        Replaces the ``func.sum(func.jsonb_array_length(...))`` query in
        ``libinv/models.py::_get_vulnerabilities_count``: sum of
        ``len(affected_by_vulnerabilities)`` across every discovered
        package that has at least one vulnerability.

        TODO(server-endpoint): same as ``get_severity_counts`` -- a
        server-side aggregate would avoid paging the whole package list.
        """
        total = 0
        for pkg in self.iter_discovered_packages(
            project_uuid, only_vulnerable=True
        ):
            vulns = pkg.get("affected_by_vulnerabilities") or []
            total += len(vulns)
        return total

    def list_cve_ids_for_project(self, project_uuid: str) -> List[str]:
        """Return every ``CVE-*`` id referenced by the project's discovered packages.

        Replaces the nested Python loop in ``libinv/cli/epss.py`` and
        ``libinv/api/actionable/package_details.py``: each discovered
        package's ``affected_by_vulnerabilities`` is a list of
        VulnerableCode dicts; CVE ids appear inside ``aliases``.

        De-duplicates and returns a sorted list for deterministic output.

        TODO(server-endpoint): could be a single
        ``GET /api/projects/<uuid>/cves/`` call upstream.
        """
        seen: Set[str] = set()
        for pkg in self.iter_discovered_packages(
            project_uuid, only_vulnerable=True
        ):
            vulns = pkg.get("affected_by_vulnerabilities") or []
            for vuln in vulns:
                aliases = vuln.get("aliases") or []
                for alias in aliases:
                    if isinstance(alias, str) and alias.startswith("CVE-"):
                        seen.add(alias)
        return sorted(seen)


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
