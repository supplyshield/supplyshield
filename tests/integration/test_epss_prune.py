"""Sprint 46.3 — integration tests for EPSS row pruning.

The ``prune_stale_epss_rows`` helper deletes rows whose ``epss_date`` is
older than ``max(epss_date) - retention_days``. These tests exercise
the real Postgres path against the ephemeral test DB.

Scenarios covered:
  - 200 rows spanning a 200-day window pruned with retention=30 shrinks
    the table to the expected count (31 rows: days 170..200 inclusive).
  - Empty table is a no-op (returns 0).
  - Retention window wider than the data range deletes nothing.
  - Negative retention bails out (defense-in-depth against misconfig).
"""
from __future__ import annotations

from datetime import date
from datetime import timedelta


def _seed_epss_rows(session, count: int, base_day: date) -> None:
    """Insert ``count`` EPSS rows, one per consecutive day starting at base_day.

    Row ``i`` has ``cve='CVE-2099-{i:05d}'`` and ``epss_date=base_day + i days``.
    Scores are arbitrary placeholders.
    """
    from libinv.models import EPSS

    rows = [
        EPSS(
            cve=f"CVE-2099-{i:05d}",
            epss_score=0.1,
            epss_percentile=0.5,
            epss_date=base_day + timedelta(days=i),
        )
        for i in range(count)
    ]
    session.add_all(rows)
    session.flush()


def test_prune_stale_epss_rows_shrinks_to_retention_window(db_session):
    """Populate 200 rows over 200 days; retention=30 should keep ~31."""
    from libinv.models import EPSS
    from libinv.services.epss.prune import prune_stale_epss_rows

    base = date(2024, 1, 1)
    total = 200
    _seed_epss_rows(db_session, total, base)

    # Sanity: pre-prune row count for our seeded slice.
    pre = (
        db_session.query(EPSS)
        .filter(EPSS.cve.like("CVE-2099-%"))
        .count()
    )
    assert pre == total

    # max(epss_date) is base + 199 days. With retention=30 the cutoff is
    # max - 30 days = base + 169. We delete rows where epss_date < cutoff,
    # i.e. days 0..168 (169 rows). Remaining: days 169..199 = 31 rows.
    deleted = prune_stale_epss_rows(db_session, retention_days=30)

    remaining = (
        db_session.query(EPSS)
        .filter(EPSS.cve.like("CVE-2099-%"))
        .count()
    )
    assert remaining == 31
    assert deleted == 169


def test_prune_stale_epss_rows_empty_table_is_noop(db_session):
    """An empty (or all-NULL-epss_date) table returns 0 deletions cleanly."""
    from libinv.models import EPSS
    from libinv.services.epss.prune import prune_stale_epss_rows

    # No rows in our slice — confirm the helper returns 0 and doesn't blow up.
    assert (
        db_session.query(EPSS)
        .filter(EPSS.cve.like("CVE-2098-%"))
        .count()
        == 0
    )

    deleted = prune_stale_epss_rows(db_session, retention_days=30)
    assert deleted == 0


def test_prune_stale_epss_rows_wide_window_deletes_nothing(db_session):
    """Retention >= data span -> no row falls outside the window."""
    from libinv.models import EPSS
    from libinv.services.epss.prune import prune_stale_epss_rows

    base = date(2024, 6, 1)
    _seed_epss_rows(db_session, 10, base)

    pre = (
        db_session.query(EPSS)
        .filter(EPSS.cve.like("CVE-2099-%"))
        .count()
    )
    assert pre == 10

    deleted = prune_stale_epss_rows(db_session, retention_days=365)
    post = (
        db_session.query(EPSS)
        .filter(EPSS.cve.like("CVE-2099-%"))
        .count()
    )
    assert deleted == 0
    assert post == 10


def test_prune_stale_epss_rows_negative_retention_is_noop(db_session):
    """Negative retention is a misconfig — bail out without deleting."""
    from libinv.models import EPSS
    from libinv.services.epss.prune import prune_stale_epss_rows

    base = date(2024, 7, 1)
    _seed_epss_rows(db_session, 5, base)

    deleted = prune_stale_epss_rows(db_session, retention_days=-10)
    post = (
        db_session.query(EPSS)
        .filter(EPSS.cve.like("CVE-2099-%"))
        .count()
    )
    assert deleted == 0
    assert post == 5
