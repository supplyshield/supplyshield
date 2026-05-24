"""Integration tests for the Sprint-2 EPSS bulk-upsert path.

Verifies `EPSS.update_epss_scores` against a real Postgres:
  - fresh inserts populate rows + set updated_at
  - subsequent calls with the same CVE upsert (overwrite) rather than dup
  - empty input is a no-op
  - `EPSS.get_fresh_cves` only returns rows newer than the staleness window
"""
from datetime import datetime
from datetime import timedelta
from datetime import timezone


def _row(session, cve):
    """Return the EPSS row for ``cve`` via the bound session."""
    from libinv.models import EPSS

    return session.query(EPSS).filter(EPSS.cve == cve).one_or_none()


def test_update_epss_scores_fresh_insert(db_session):
    """Bulk-insert N new EPSS rows; verify all rows present and timestamped."""
    from libinv.models import EPSS

    payload = {
        "CVE-2024-0001": {
            "epss_score": 0.12,
            "epss_percentile": 0.55,
            "epss_date": "2024-01-01",
        },
        "CVE-2024-0002": {
            "epss_score": 0.34,
            "epss_percentile": 0.66,
            "epss_date": "2024-01-02",
        },
        "CVE-2024-0003": {
            "epss_score": 0.56,
            "epss_percentile": 0.77,
            "epss_date": "2024-01-03",
        },
    }

    EPSS.update_epss_scores(db_session, payload)

    rows = (
        db_session.query(EPSS).filter(EPSS.cve.in_(list(payload.keys()))).all()
    )
    assert len(rows) == 3
    for r in rows:
        assert r.cve in payload
        assert r.updated_at is not None
        assert r.epss_score == payload[r.cve]["epss_score"]
        assert r.epss_percentile == payload[r.cve]["epss_percentile"]
        assert r.epss_date == payload[r.cve]["epss_date"]


def test_update_epss_scores_upsert_overwrites_existing(db_session):
    """A second call with the same CVE updates the row in place."""
    from libinv.models import EPSS

    cve = "CVE-2024-1000"
    EPSS.update_epss_scores(
        db_session,
        {cve: {"epss_score": 0.10, "epss_percentile": 0.20, "epss_date": "2024-02-01"}},
    )
    before = _row(db_session, cve)
    assert before is not None
    assert before.epss_score == 0.10
    first_updated_at = before.updated_at

    EPSS.update_epss_scores(
        db_session,
        {cve: {"epss_score": 0.99, "epss_percentile": 0.95, "epss_date": "2024-02-02"}},
    )

    # Still exactly one row (upsert, not duplicate).
    rows = db_session.query(EPSS).filter(EPSS.cve == cve).all()
    assert len(rows) == 1

    after = rows[0]
    assert after.epss_score == 0.99
    assert after.epss_percentile == 0.95
    assert after.epss_date == "2024-02-02"
    # updated_at should advance (the upsert sets a fresh `now`).
    assert after.updated_at >= first_updated_at


def test_update_epss_scores_empty_dict_is_noop(db_session):
    """Passing {} returns cleanly and adds no rows."""
    from libinv.models import EPSS

    before_count = db_session.query(EPSS).count()
    result = EPSS.update_epss_scores(db_session, {})
    # The method returns None on the empty-path; just assert it didn't blow up.
    assert result is None
    after_count = db_session.query(EPSS).count()
    assert after_count == before_count


def test_get_fresh_cves_filters_by_age(db_session):
    """`get_fresh_cves` only returns rows updated within the staleness window."""
    from libinv.models import EPSS

    recent_cve = "CVE-2024-2001"
    stale_cve = "CVE-2024-2002"

    # Insert the recent one normally — its updated_at is "now".
    EPSS.update_epss_scores(
        db_session,
        {
            recent_cve: {
                "epss_score": 0.11,
                "epss_percentile": 0.22,
                "epss_date": "2024-03-01",
            },
        },
    )

    # Insert the stale one directly via the ORM so we control updated_at.
    stale_dt = datetime.now(timezone.utc) - timedelta(days=90)
    db_session.add(
        EPSS(
            cve=stale_cve,
            epss_score=0.33,
            epss_percentile=0.44,
            epss_date="2024-01-01",
            updated_at=stale_dt,
        )
    )
    db_session.flush()

    fresh = EPSS.get_fresh_cves(db_session, [recent_cve, stale_cve], days=30)
    assert recent_cve in fresh
    assert stale_cve not in fresh
