"""Query builder for the ``/v3/package-details`` route.

Sprint 44.2 lift of the data-access surface out of the route handler so
that ``package_details.py`` stays as a thin view layer.

The builder owns:
* The repeated ``ActionablePackageAvailableVersion`` lookup by
  ``(package_url, version)`` -- previously issued twice in the route.
* The ``DiscoveredPackage`` SQL fallback path when the SCIO HTTP client
  is unavailable or fails.
* The ``EPSS`` bulk fetch by CVE-id list.
* The ``Repository`` + ``Repository_ActionablePackageAvailableVersion``
  join that surfaces which repositories use a given package version.

Everything that is *not* data-access (CVE extraction loop, severity
classification, template rendering) stays in the route handler.
"""

from __future__ import annotations

from typing import Any
from typing import Dict
from typing import Iterable
from typing import List
from typing import Optional

from libinv.models import EPSS
from libinv.models import ActionablePackageAvailableVersion
from libinv.models import Repository
from libinv.models import Repository_ActionablePackageAvailableVersion
from libinv.scio_models import DiscoveredPackage


class PackageDetailsQuery:
    """Pure data-fetch helper for the package-details route.

    Each method takes an open ``session`` and returns SQLAlchemy ORM
    objects / row tuples / lists -- no Flask context, no rendering.
    The route composes these results into the template payload.
    """

    def __init__(self, package_url: str, version: str):
        self.package_url = package_url
        self.version = version

    # ------------------------------------------------------------------
    # Primary lookup
    # ------------------------------------------------------------------
    def fetch_actionable_package(
        self, session
    ) -> Optional[ActionablePackageAvailableVersion]:
        """Return the APAV row matching ``(package_url, version)`` or ``None``."""
        return (
            session.query(ActionablePackageAvailableVersion)
            .filter(ActionablePackageAvailableVersion.package_url == self.package_url)
            .filter(ActionablePackageAvailableVersion.version == self.version)
            .first()
        )

    # ------------------------------------------------------------------
    # Discovered packages -- SQL fallback for the HTTP branch
    # ------------------------------------------------------------------
    def fetch_discovered_packages_sql(
        self, session, scancode_project_uuid: str
    ) -> List[DiscoveredPackage]:
        """SQL-path fallback when the SCIO HTTP client is unavailable / fails.

        Mirrors the legacy
        ``session.query(DiscoveredPackage).filter(...).all()`` block.
        """
        return (
            session.query(DiscoveredPackage)
            .filter(DiscoveredPackage.project_id == scancode_project_uuid)
            .all()
        )

    # ------------------------------------------------------------------
    # EPSS bulk fetch
    # ------------------------------------------------------------------
    def fetch_epss_records(self, session, cve_ids: Iterable[str]) -> Dict[str, EPSS]:
        """Return ``{cve_id: EPSS}`` for the given CVE ids (empty dict on empty input)."""
        cve_list = list(cve_ids)
        if not cve_list:
            return {}
        records = session.query(EPSS).filter(EPSS.cve.in_(cve_list)).all()
        return {record.cve: record for record in records}

    # ------------------------------------------------------------------
    # Repositories using this package version
    # ------------------------------------------------------------------
    def fetch_repositories_using_package(
        self, session, actionable_package_uuid: str
    ) -> List[Dict[str, Any]]:
        """Return list of repository dicts that reference the given APAV uuid."""
        rows = (
            session.query(
                Repository.id,
                Repository.name,
                Repository.org,
                Repository.provider,
                Repository.pod,
                Repository.subpod,
                Repository_ActionablePackageAvailableVersion.environment,
            )
            .join(
                Repository_ActionablePackageAvailableVersion,
                Repository.id
                == Repository_ActionablePackageAvailableVersion.repository_id,
            )
            .filter(
                Repository_ActionablePackageAvailableVersion.actionable_package_version_id
                == actionable_package_uuid
            )
            .all()
        )

        return [
            {
                "id": repo.id,
                "name": repo.name,
                "org": repo.org,
                "provider": repo.provider,
                "pod": repo.pod,
                "subpod": repo.subpod,
                "environment": repo.environment,
            }
            for repo in rows
        ]
