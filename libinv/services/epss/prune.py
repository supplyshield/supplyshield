"""Sprint 46.3 — EPSS row pruning.

The EPSS feed from first.org publishes a new dated snapshot every day.
``EPSS.refresh_cves`` upserts on ``cve`` (primary key) so the row count
is bounded by the number of CVEs we have ever scored — not by how many
days we have been running. However, the ``epss_date`` column records
the *publication date* of the score, and as new CVEs appear we can
accumulate rows whose ``epss_date`` is well outside the operational
window we care about (e.g. several years old).

This module exposes ``prune_stale_epss_rows`` — a small helper that
deletes rows whose ``epss_date`` is older than
``max(epss_date) - retention_days`` (default 90). It is called from
``EPSS.refresh_cves`` immediately after the upsert so the canonical
EPSS refresh path keeps the table bounded without any caller
remembering to invoke it.

The retention horizon is sourced from the env-var
``LIBINV_EPSS_RETENTION_DAYS`` (parsed in ``libinv/env.py``); callers
may override per-invocation via the ``retention_days`` kwarg.
"""

from __future__ import annotations

from datetime import timedelta

from sqlalchemy import delete
from sqlalchemy import func
from sqlalchemy import select


def prune_stale_epss_rows(session, retention_days: int = 90) -> int:
    """Delete ``EPSS`` rows with ``epss_date < max(epss_date) - retention_days``.

    Args:
        session: An active SQLAlchemy ``Session``.
        retention_days: Window (in days) of EPSS history to retain,
            measured backwards from the most recent ``epss_date`` in the
            table. Defaults to 90.

    Returns:
        The number of rows deleted (0 if the table is empty, all rows
        are within the window, or there is no ``max(epss_date)`` —
        e.g. all rows have NULL ``epss_date``).
    """
    # Local import keeps this module importable without triggering the
    # ORM mapper at module-import time (mirrors the deferred-import
    # discipline used in ``libinv/services/epss/all_actionable_cves.py``).
    from libinv.models import EPSS

    if retention_days < 0:
        # Negative retention would be a destructive misconfig; bail out.
        return 0

    max_date = session.execute(select(func.max(EPSS.epss_date))).scalar()
    if max_date is None:
        # Empty table OR all rows have NULL epss_date — nothing to prune.
        return 0

    cutoff = max_date - timedelta(days=retention_days)
    result = session.execute(
        delete(EPSS).where(EPSS.epss_date < cutoff)
    )
    session.commit()
    # ``result.rowcount`` is the deleted-row count for a DELETE statement
    # on Postgres via psycopg2; cast to int for the public signature.
    return int(result.rowcount or 0)


__all__ = ("prune_stale_epss_rows",)
