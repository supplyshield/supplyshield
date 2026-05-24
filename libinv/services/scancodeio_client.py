"""
HTTP client for ScanCode.io's REST API.

Replaces the SQL-reflection coupling in ``libinv/scio_models.py`` with a
typed, versioned HTTP contract. Implemented in stages — this module
currently provides the interface and stubbed methods (NotImplementedError)
so callers can incrementally migrate. The real HTTP calls land in a
future sprint.

The endpoint shape assumed by this client (verified against
``scancode.io/scanpipe/api/views.py`` ``ProjectViewSet``):

- ``GET /api/projects/<uuid>/``                  → project metadata
- ``GET /api/projects/<uuid>/packages/``         → list discovered packages
                                                   (paginated DRF response)
- ``GET /api/projects/?wasp_uuid_id=<uuid>``     → projects linked to a wasp
                                                   (requires an upstream filter
                                                   addition; see TODO below)

There is **no** dedicated severity-counts endpoint upstream today; the
current SQL aggregate in ``libinv/models.py`` must either be re-implemented
client-side (loop over ``affected_by_vulnerabilities`` from
``list_discovered_packages``) or added as a custom action upstream.

Activation: set the environment variable ``LIBINV_SCIO_USE_HTTP=true``.
When unset, callers retain the existing ``scio_models.py`` reflection
path; this client is **inactive scaffolding** until Sprint 15+.
"""

from __future__ import annotations

import logging
import os
from typing import Any
from typing import Iterable
from typing import List
from typing import Optional
from typing import TypedDict

import requests

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
# Client
# ---------------------------------------------------------------------------


class ScancodeioClient:
    """Stateless HTTP client for the queries libinv makes against scancodeio.

    Every method here corresponds 1:1 with a SQL/ORM access pattern catalogued
    in ``docs/scancodeio_contract.md``. Methods raise ``NotImplementedError``
    today; real implementations land in Sprint 15+.
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
        self._session = requests.Session()
        if api_key:
            self._session.headers["Authorization"] = f"Token {api_key}"

    # ------------------------------------------------------------------
    # Project-level reads
    # ------------------------------------------------------------------

    def get_project(self, project_uuid: str) -> ScanpipeProjectDTO:
        """Return project metadata.

        Replaces direct ORM access to ``ScanpipeProject`` (the reflected
        model in ``libinv/scio_models.py``).
        """
        raise NotImplementedError(
            "Sprint 15+ — wire to GET /api/projects/<uuid>/"
        )

    def list_projects_for_wasp(self, wasp_uuid: str) -> List[ScanpipeProjectDTO]:
        """Return every scanpipe project whose ``wasp_uuid_id`` matches.

        Replaces the JOIN in ``libinv/api/compare_builds.py``::

            session.query(Wasp).join(
                ScanpipeProject, ScanpipeProject.wasp_uuid_id == Wasp.uuid
            )

        NOTE: ``wasp_uuid_id`` is a SupplyShield-specific column added to
        ``scanpipe_project`` — the upstream filter set may need to be
        extended before this endpoint accepts ``?wasp_uuid_id=...``.
        """
        raise NotImplementedError(
            "Sprint 15+ — wire to GET /api/projects/?wasp_uuid_id=<uuid> "
            "(requires upstream filterset support for wasp_uuid_id)"
        )

    # ------------------------------------------------------------------
    # Discovered packages
    # ------------------------------------------------------------------

    def list_discovered_packages(
        self,
        project_uuid: str,
        only_vulnerable: bool = False,
    ) -> List[DiscoveredPackageDTO]:
        """Return every discovered package for the given scancodeio project.

        Replaces::

            session.query(DiscoveredPackage)
                .filter(DiscoveredPackage.project_id == uuid)
                .all()

        When ``only_vulnerable=True``, equivalent to additionally filtering
        ``affected_by_vulnerabilities != '[]'``. The upstream endpoint
        ``GET /api/projects/<uuid>/packages/`` is paginated; the
        implementation must follow ``next`` links until exhausted.
        """
        raise NotImplementedError(
            "Sprint 15+ — wire to GET /api/projects/<uuid>/packages/ "
            "(follow pagination cursor)"
        )

    def iter_discovered_packages(
        self,
        project_uuid: str,
        only_vulnerable: bool = False,
    ) -> Iterable[DiscoveredPackageDTO]:
        """Generator variant of ``list_discovered_packages``.

        Preferable for the EPSS batch job, which walks thousands of
        projects and only needs a CVE set; materialising every package
        for every project at once is wasteful.
        """
        raise NotImplementedError(
            "Sprint 15+ — yield discovered packages page-by-page"
        )

    # ------------------------------------------------------------------
    # Derived aggregates
    # ------------------------------------------------------------------

    def get_severity_counts(self, project_uuid: str) -> List[SeverityCountDTO]:
        """Return per-severity vulnerability counts for the project.

        Replaces the raw ``text(...)`` CTE in
        ``libinv/models.py::ActionablePackageAvailableVersion.vulnerability_severities``
        which scans ``scanpipe_discoveredpackage.affected_by_vulnerabilities``.

        Return shape::

            [
                {"severity_level": "critical", "count": 4},
                {"severity_level": "high",     "count": 12},
                {"severity_level": "medium",   "count": 7},
                {"severity_level": "low",      "count": 1},
                {"severity_level": "unknown",  "count": 0},
            ]

        Recommended strategy: aggregate client-side from
        ``list_discovered_packages`` until a dedicated upstream endpoint
        exists; the math is trivial and avoids an upstream patch.
        """
        raise NotImplementedError(
            "Sprint 15+ — aggregate client-side from list_discovered_packages, "
            "or wire to a future GET /api/projects/<uuid>/severity-counts/"
        )

    def get_vulnerability_count(self, project_uuid: str) -> int:
        """Return the total vulnerability count across the project.

        Replaces the ``func.sum(func.jsonb_array_length(...))`` query in
        ``libinv/models.py::_get_vulnerabilities_count``. Computable
        client-side as ``sum(len(p["affected_by_vulnerabilities"]) for p in
        list_discovered_packages(uuid))``.
        """
        raise NotImplementedError(
            "Sprint 15+ — sum len(affected_by_vulnerabilities) over packages"
        )

    def list_cve_ids_for_project(self, project_uuid: str) -> List[str]:
        """Return every ``CVE-*`` id referenced by the project's discovered packages.

        Replaces the nested Python loop in ``libinv/cli/epss.py`` and the
        equivalent loop in
        ``libinv/api/actionable/package_details.py``. Each discovered
        package's ``affected_by_vulnerabilities`` is a JSONB list of
        VulnerableCode dicts; CVE ids appear in the ``aliases`` field.
        """
        raise NotImplementedError(
            "Sprint 15+ — derive client-side from list_discovered_packages, "
            "extracting aliases that start with 'CVE-'"
        )


# ---------------------------------------------------------------------------
# Default-client helper
# ---------------------------------------------------------------------------


def get_default_client() -> Optional[ScancodeioClient]:
    """Return a singleton-style client, or ``None`` if HTTP mode is off.

    The HTTP path is opt-in until Sprint 15+ has migrated every caller. If
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
    "ScanpipeProjectDTO",
    "SeverityCountDTO",
    "get_default_client",
]
