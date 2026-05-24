"""
Per-endpoint methods for the ScanCode.io REST client.

Sprint 42.4: extracted from ``scancodeio/__init__.py`` so endpoint
methods (project metadata, discovered-packages walk, derived aggregates)
are isolated from the client's ``__init__``/transport-wiring concerns.

Implemented as ``EndpointsMixin`` so ``ScancodeioClient`` can compose
``TransportMixin``-style attributes (``self._session``, ``self._base_url``,
``self._timeout``, ``self._request_json``) without explicit delegation
boilerplate. The mixin assumes the host class exposes:

    * ``self._base_url``    -- str, trailing slash stripped
    * ``self._timeout``     -- int
    * ``self._session``     -- ``requests.Session`` (set by ``build_session``)
    * ``self._request_json`` -- bound wrapper around
      ``libinv.services.scancodeio.transport._request_json``

These attributes are established by ``ScancodeioClient.__init__`` in the
package ``__init__.py`` facade.
"""

from __future__ import annotations

from typing import Any
from typing import Dict
from typing import Iterator
from typing import List
from typing import Optional
from typing import Set
from typing import cast

import requests

from libinv.services.scancodeio.dtos import DiscoveredPackageDTO
from libinv.services.scancodeio.dtos import ScanpipeProjectDTO
from libinv.services.scancodeio.dtos import SeverityCountDTO


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
# Endpoints mixin
# ---------------------------------------------------------------------------


class EndpointsMixin:
    """Mixin housing the per-endpoint methods.

    Composed into ``ScancodeioClient`` (see package ``__init__.py``). The
    host class is responsible for setting ``_base_url``, ``_timeout``,
    ``_session``, and exposing a ``_request_json`` method (which forwards
    to ``transport._request_json``).
    """

    # Attributes provided by the host class (declared here so mypy doesn't
    # complain about ``self.<attr>`` accesses inside the mixin).
    _base_url: str
    _timeout: int
    _session: requests.Session

    def _request_json(
        self,
        url: str,
        params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:  # pragma: no cover - overridden by host class
        raise NotImplementedError

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

        BLOCKER (Sprint 42.4 / referenced in CHANGELOG):
        ``wasp_uuid_id`` is a SupplyShield-specific column added to
        ``scanpipe_project``; the upstream ``ProjectFilterSet`` in
        ``scancode.io/scanpipe/api/views.py`` does NOT include
        ``wasp_uuid_id`` in its ``Meta.fields`` declaration. Issuing
        ``GET /api/projects/?wasp_uuid_id=<uuid>`` against an upstream
        scancodeio would therefore silently return the unfiltered project
        list -- worse than failing loudly.

        REQUIRED UPSTREAM CHANGE (do not delete this method):

            class ProjectFilterSet(django_filters.rest_framework.FilterSet):
                class Meta:
                    model = Project
                    fields = [
                        "uuid",
                        "name",
                        "wasp_uuid_id",   # <-- add this entry
                    ]

        After the upstream patch lands (or a SupplyShield-side proxy
        endpoint is added), replace this NotImplementedError with the
        wired GET call -- see ``TODO(server-endpoint)`` below for the
        exact request shape. ``libinv/api/compare_builds.py`` (the only
        caller) currently still drives the legacy SQL/reflection path
        via ``libinv/scio_models.py`` until this method is wired.
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


__all__ = [
    "EndpointsMixin",
    "_classify_severity",
]
