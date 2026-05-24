"""Sprint 44.1 — ``RepositoryListingQuery`` builder.

Extracts the inline query assembly that previously lived in
``libinv.api.actionable.repositories.repositories_listing``:

  * Base join (Repository x Repository_APAV x APAV) + aggregate columns.
  * 7 chainable ``.having(...)`` / ``.filter(...)`` predicates driven by
    request query params (environment, pod, org, search, has_vulnerabilities,
    priority — split into 5 priority branches).
  * 3 facet aggregates (environments, pods, orgs) for the filter dropdowns.
  * Final ``GROUP BY`` + ``ORDER BY`` and ``.execute()`` returning
    ``(rows, facets)``.

Behavior is preserved bit-for-bit so the existing 37 behavioral
regression tests in ``tests/integration/test_repositories_route_behavioral.py``
continue to pass unchanged.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import and_, distinct, func, or_

from libinv.models import (
    ActionablePackageAvailableVersion,
    Repository,
    RepositoryActionablePackageAvailableVersion,
)

# Type aliases for clarity.
FacetMap = Dict[str, List[Any]]


class RepositoryListingQuery:
    """Chainable builder for ``GET /v3/repositories`` listing query.

    Usage:

        q = RepositoryListingQuery(session, params)
        rows, facets = (
            q.having_environment()
             .having_pod()
             .having_org()
             .having_search()
             .having_vulnerabilities()
             .having_priority()
             .with_facet("environments")
             .with_facet("pods")
             .with_facet("orgs")
             .execute()
        )

    Each ``having_*`` method short-circuits when the corresponding param
    is empty/missing — matching the pre-refactor branch shape exactly.
    """

    # Centralised priority -> having clause table. Mirrors lines 109-135
    # of the original route. The factory must be called lazily so each
    # invocation produces a fresh ``func.max(...)`` SQL expression.
    _PRIORITY_HAVING = {
        "p0": lambda: func.max(ActionablePackageAvailableVersion.epss_score) > 0.8,
        "p1": lambda: and_(
            func.max(ActionablePackageAvailableVersion.epss_score) > 0.7,
            func.max(ActionablePackageAvailableVersion.epss_score) <= 0.8,
        ),
        "p2": lambda: and_(
            func.max(ActionablePackageAvailableVersion.epss_score) > 0.5,
            func.max(ActionablePackageAvailableVersion.epss_score) <= 0.7,
        ),
        "p3": lambda: func.max(ActionablePackageAvailableVersion.epss_score) <= 0.5,
        "no_epss": lambda: func.max(
            ActionablePackageAvailableVersion.epss_score
        ).is_(None),
    }

    def __init__(self, session, params: Dict[str, str]):
        self.session = session
        self.params = params
        self._facets: List[str] = []
        self._query = self._build_base_query()

    # ------------------------------------------------------------------
    # Base query construction
    # ------------------------------------------------------------------
    def _build_base_query(self):
        """Build the Repository x Repository_APAV x APAV join + aggregates."""
        return (
            self.session.query(
                Repository.id,
                Repository.name,
                Repository.org,
                Repository.provider,
                Repository.pod,
                Repository.subpod,
                RepositoryActionablePackageAvailableVersion.environment,
                func.count(
                    distinct(
                        RepositoryActionablePackageAvailableVersion.actionable_package_version_id
                    )
                ).label("total_packages"),
                func.count(distinct(ActionablePackageAvailableVersion.uuid))
                .filter(ActionablePackageAvailableVersion.vulns_count > 0)
                .label("vulnerable_packages"),
                func.max(ActionablePackageAvailableVersion.epss_score).label(
                    "max_epss_score"
                ),
            )
            .join(
                RepositoryActionablePackageAvailableVersion,
                Repository.id
                == RepositoryActionablePackageAvailableVersion.repository_id,
            )
            .join(
                ActionablePackageAvailableVersion,
                RepositoryActionablePackageAvailableVersion.actionable_package_version_id
                == ActionablePackageAvailableVersion.uuid,
            )
        )

    # ------------------------------------------------------------------
    # Chainable predicates (filter / having)
    # ------------------------------------------------------------------
    def having_environment(self) -> "RepositoryListingQuery":
        value = self.params.get("environment", "")
        if value:
            self._query = self._query.filter(
                RepositoryActionablePackageAvailableVersion.environment == value
            )
        return self

    def having_pod(self) -> "RepositoryListingQuery":
        value = self.params.get("pod", "")
        if value:
            self._query = self._query.filter(Repository.pod == value)
        return self

    def having_org(self) -> "RepositoryListingQuery":
        value = self.params.get("org", "")
        if value:
            self._query = self._query.filter(Repository.org == value)
        return self

    def having_search(self) -> "RepositoryListingQuery":
        value = self.params.get("search", "")
        if value:
            self._query = self._query.filter(
                or_(
                    Repository.name.ilike(f"%{value}%"),
                    Repository.org.ilike(f"%{value}%"),
                )
            )
        return self

    def _group_by_repository(self) -> None:
        self._query = self._query.group_by(
            Repository.id,
            Repository.name,
            Repository.org,
            Repository.provider,
            Repository.pod,
            Repository.subpod,
            RepositoryActionablePackageAvailableVersion.environment,
        )

    def having_vulnerabilities(self) -> "RepositoryListingQuery":
        value = self.params.get("has_vulnerabilities", "")
        if value == "true":
            self._query = self._query.having(
                func.count(distinct(ActionablePackageAvailableVersion.uuid)).filter(
                    ActionablePackageAvailableVersion.vulns_count > 0
                )
                > 0
            )
        elif value == "false":
            self._query = self._query.having(
                func.count(distinct(ActionablePackageAvailableVersion.uuid)).filter(
                    ActionablePackageAvailableVersion.vulns_count > 0
                )
                == 0
            )
        return self

    def having_priority(self) -> "RepositoryListingQuery":
        value = self.params.get("priority", "")
        factory = self._PRIORITY_HAVING.get(value)
        if factory is not None:
            self._query = self._query.having(factory())
        return self

    # ------------------------------------------------------------------
    # Facets
    # ------------------------------------------------------------------
    def with_facet(self, name: str) -> "RepositoryListingQuery":
        if name not in ("environments", "pods", "orgs"):
            raise ValueError(f"Unknown facet: {name}")
        if name not in self._facets:
            self._facets.append(name)
        return self

    def _compute_facets(self) -> FacetMap:
        result: FacetMap = {}
        for name in self._facets:
            if name == "environments":
                rows = (
                    self.session.query(
                        distinct(
                            RepositoryActionablePackageAvailableVersion.environment
                        )
                    )
                    .order_by(RepositoryActionablePackageAvailableVersion.environment)
                    .all()
                )
                result["environments"] = [r[0] for r in rows]
            elif name == "pods":
                rows = (
                    self.session.query(distinct(Repository.pod))
                    .filter(Repository.pod.isnot(None))
                    .order_by(Repository.pod)
                    .all()
                )
                result["pods"] = [r[0] for r in rows]
            elif name == "orgs":
                rows = (
                    self.session.query(distinct(Repository.org))
                    .order_by(Repository.org)
                    .all()
                )
                result["orgs"] = [r[0] for r in rows]
        return result

    # ------------------------------------------------------------------
    # Pagination (stub — preserved for forward compatibility; current
    # route does not paginate and the builder default is an identity op)
    # ------------------------------------------------------------------
    def paginate(
        self, page: Optional[int] = None, size: Optional[int] = None
    ) -> "RepositoryListingQuery":
        if page is not None and size is not None:
            offset = max(0, (page - 1) * size)
            self._query = self._query.offset(offset).limit(size)
        return self

    # ------------------------------------------------------------------
    # Terminal: execute returns (rows, facets)
    # ------------------------------------------------------------------
    def execute(self) -> Tuple[List[Any], FacetMap]:
        self._group_by_repository()
        rows = self._query.order_by(
            Repository.name,
            RepositoryActionablePackageAvailableVersion.environment,
        ).all()
        facets = self._compute_facets()
        return rows, facets


__all__ = ("RepositoryListingQuery", "FacetMap")
