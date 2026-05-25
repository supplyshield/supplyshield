"""Sprint 40.3: EPSS-domain ORM class.

Extracted from ``libinv/models/_legacy.py`` following the Sprint 39.2 /
40.1 / 40.2 pattern. Holds the single class describing the EPSS layer
of the ORM:

  * ``EPSS``  — one row per CVE, storing ``epss_score`` and
                ``epss_percentile`` from first.org's public API along
                with the date the score was published. Includes batch
                helpers (``refresh_cves``, ``update_epss_scores``,
                ``get_fresh_cves``, ``get_stale_or_missing_cves``)
                used by the ``libinv epss`` CLI and the EPSS-related
                workflows under ``libinv.services.epss``.

The class continues to use the module-level ``requests`` symbol — that
binding is exported by the ``libinv.models`` package and patched by a
small number of tests via ``patch("libinv.models._legacy.requests",
...)`` (see Sprint 39.1 evidence). To keep both invocation paths
working, this module imports ``requests`` directly *and* the legacy
re-exports it. New code should mock either binding deliberately.

The package's previous home (`_legacy.py`) re-imports this name at the
bottom of the file so any historical
``from libinv.models._legacy import EPSS`` callers continue to find it.
"""

from __future__ import annotations

import time
from datetime import datetime
from datetime import timedelta
from datetime import timezone

import requests
from sqlalchemy import Column
from sqlalchemy import Date
from sqlalchemy import DateTime
from sqlalchemy import Float
from sqlalchemy import Index
from sqlalchemy import String
from sqlalchemy import func
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.exc import SQLAlchemyError

from libinv.base import Base


class EPSS(Base):
    """
    EPSS (Exploit Prediction Scoring System) model to store CVE EPSS scores
    """

    __tablename__ = "epss"

    cve = Column(String(50), primary_key=True, nullable=False)
    epss_score = Column(Float(precision=6), nullable=False)
    epss_percentile = Column(Float(precision=6), nullable=False)
    # Sprint 34.2: epss_date promoted from String(20) to native DATE for
    # proper ordering / range queries. Migration 0003 ALTERs the column with
    # ``USING epss_date::date`` so existing 'YYYY-MM-DD' string rows convert
    # losslessly. Callers should pass either a ``datetime.date`` or an
    # ISO-8601 'YYYY-MM-DD' string — psycopg2 parses both.
    epss_date = Column(Date, nullable=True)
    # Sprint 34.1: server_default guarantees population — NOT NULL.
    updated_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    # Sprint 33.1/33.2: declare composite index already created by alembic 0002_fk_indexes
    __table_args__ = (
        Index("ix_epss_cve_updated_at", "cve", "updated_at"),
        {"schema": "libinv"},
    )

    def __str__(self):
        return f"{self.cve} - {self.epss_score}"

    @classmethod
    def get_fresh_cves(cls, session, cve_list, days=30):

        stale_threshold = datetime.now(timezone.utc) - timedelta(days=days)

        fresh_cves = set(
            r.cve
            for r in session.query(cls.cve)
            .filter(cls.cve.in_(cve_list))
            .filter(cls.updated_at > stale_threshold)
            .all()
        )
        return fresh_cves

    @classmethod
    def get_stale_or_missing_cves(cls, session, cve_list, days=30):
        fresh_cves = cls.get_fresh_cves(session, cve_list, days)
        return [cve for cve in cve_list if cve not in fresh_cves]

    @classmethod
    def refresh_cves(cls, session, cve_list, verbose=False, logger=None):
        valid_cves_upper = [c.upper() for c in cve_list]
        # Use model methods to determine which CVEs need updates
        to_fetch = cls.get_stale_or_missing_cves(session, valid_cves_upper)
        fresh_cves = cls.get_fresh_cves(session, valid_cves_upper)

        updated, skipped, failed = 0, 0, len(fresh_cves)

        if verbose and fresh_cves and logger:
            logger.warning(f"Skipping {len(fresh_cves)} fresh CVEs (updated within 30 days)")

        # Fetch from API if needed
        if to_fetch:
            if logger:
                logger.warning(f"Fetching {len(to_fetch)} CVEs from EPSS API...")

            batch_size = 100
            for i in range(0, len(to_fetch), batch_size):
                if i > 0:
                    # Polite rate-limit between batches against the public EPSS API.
                    time.sleep(0.5)
                batch = to_fetch[i : i + batch_size]
                cve_string = ",".join(batch)
                try:
                    response = requests.get(
                        f"https://api.first.org/data/v1/epss?cve={cve_string}", timeout=30
                    )
                    if response.status_code == 200:
                        api_data = response.json()
                        new_epss_data = {}
                        found_cves = set()
                        for item in api_data.get("data", []):
                            cve_id = item.get("cve", "").upper()
                            found_cves.add(cve_id)
                            new_epss_data[cve_id] = {
                                "epss_score": float(item.get("epss", 0)),
                                "epss_percentile": float(item.get("percentile", 0)),
                                "epss_date": item.get("date", ""),
                            }

                        for cve_nf in batch:
                            if cve_nf not in found_cves:
                                if logger:
                                    logger.warning(f"CVE {cve_nf} not found in EPSS API, skipping")
                                continue

                        cls.update_epss_scores(session, new_epss_data)
                        updated += len([cve for cve in batch if cve in found_cves])
                        failed += len([cve for cve in batch if cve not in found_cves])
                    else:
                        if logger:
                            logger.error(f"API error: {response.status_code} {response.text}")
                        failed += len(batch)
                except (requests.RequestException, ValueError, SQLAlchemyError) as e:
                    # Sprint 47.2: narrowed from `except Exception`. Sources:
                    # * ``requests.get`` -> requests.RequestException
                    # * ``response.json()`` / ``float(...)`` -> ValueError
                    # * ``cls.update_epss_scores`` -> SQLAlchemyError on
                    #   the pg_insert / session.execute path.
                    if logger:
                        logger.error(f"Error fetching EPSS data: {e}")
                    failed += len(batch)

        # Sprint 46.3 — keep the EPSS table bounded by pruning rows
        # whose ``epss_date`` is older than the configured retention
        # window. Defer the import + env-var read so test stubs that
        # monkeypatch ``libinv.services.epss.prune`` or
        # ``libinv.env.LIBINV_EPSS_RETENTION_DAYS`` are respected.
        try:
            from libinv.env import LIBINV_EPSS_RETENTION_DAYS
            from libinv.services.epss.prune import prune_stale_epss_rows

            deleted = prune_stale_epss_rows(
                session, retention_days=LIBINV_EPSS_RETENTION_DAYS
            )
            if deleted and logger:
                logger.warning(
                    f"Pruned {deleted} stale EPSS rows older than "
                    f"{LIBINV_EPSS_RETENTION_DAYS} days from max(epss_date)"
                )
        except Exception as e:  # noqa: BLE001
            # Pruning is best-effort: never let it bubble up and mask
            # a successful refresh.
            if logger:
                logger.error(f"EPSS row pruning failed: {e}")

        return {"updated": updated, "skipped": skipped, "failed": failed}

    @classmethod
    def update_epss_scores(cls, session, epss_data_dict):
        """Bulk-upsert EPSS scores via INSERT ... ON CONFLICT DO UPDATE.

        One round trip per batch instead of one SELECT + one INSERT/UPDATE
        per CVE.
        """
        if not epss_data_dict:
            return

        now = datetime.now(timezone.utc)
        rows = [
            {
                "cve": cve_id,
                "epss_score": data["epss_score"],
                "epss_percentile": data["epss_percentile"],
                "epss_date": data["epss_date"],
                "updated_at": now,
            }
            for cve_id, data in epss_data_dict.items()
        ]
        stmt = pg_insert(cls).values(rows)
        stmt = stmt.on_conflict_do_update(
            index_elements=[cls.cve],
            set_={
                "epss_score": stmt.excluded.epss_score,
                "epss_percentile": stmt.excluded.epss_percentile,
                "epss_date": stmt.excluded.epss_date,
                "updated_at": stmt.excluded.updated_at,
            },
        )
        session.execute(stmt)
        session.commit()
