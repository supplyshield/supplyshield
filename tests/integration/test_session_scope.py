"""Integration tests for `libinv.base.session_scope` against a real DB.

Verifies the Sprint-1 contract:
  - clean exit commits
  - exception rolls back
  - the scoped session is removed at the end (next call returns a new Session)

These tests reconfigure the module-level `engine`, `Session`, and
`ScopedSession` to bind against the integration test DB. The `db_session`
fixture is NOT used here because `session_scope()` opens its own session
via the engine pool independently of any pre-existing connection.

Cleanup is explicit: each test inserts a row tagged with a unique sentinel
CVE id and deletes it on teardown, so no test residue leaks.
"""
import pytest


# A namespace prefix that's unlikely to collide with real EPSS CVE rows.
SENTINEL_PREFIX = "CVE-TEST-SESSION-"


@pytest.fixture(autouse=True)
def patch_engine(engine, monkeypatch):
    """Rebind libinv.base globals to the test engine for the duration of the test.

    SQLAlchemy 2.0 supports `configure(bind=...)` on both sessionmaker and
    scoped_session, so we use that to repoint the module-level Session
    factories without monkeying private attributes.
    """
    import libinv.base

    monkeypatch.setattr(libinv.base, "engine", engine)
    libinv.base.Session.configure(bind=engine)
    libinv.base.ScopedSession.configure(bind=engine)
    yield
    # Make sure no leftover thread-local session leaks into the next test.
    libinv.base.ScopedSession.remove()


@pytest.fixture
def cleanup_epss(engine):
    """Remove sentinel EPSS rows after a test to keep the DB clean."""
    yield
    from sqlalchemy.orm import Session

    from libinv.models import EPSS

    with Session(bind=engine) as s:
        s.query(EPSS).filter(EPSS.cve.like(f"{SENTINEL_PREFIX}%")).delete(
            synchronize_session=False
        )
        s.commit()


def test_session_scope_commits_on_clean_exit(engine, cleanup_epss):
    """Inside session_scope: add a row; assert it was committed (visible to a fresh session)."""
    from sqlalchemy.orm import Session

    from libinv.base import session_scope
    from libinv.models import EPSS

    cve = f"{SENTINEL_PREFIX}COMMIT"
    with session_scope() as s:
        s.add(
            EPSS(
                cve=cve,
                epss_score=0.42,
                epss_percentile=0.50,
                epss_date="2024-04-01",
            )
        )
        # No exception — commit happens at scope exit.

    # Open a brand-new session bound directly to the engine: if the commit
    # didn't happen, this read would return None.
    with Session(bind=engine) as fresh:
        row = fresh.query(EPSS).filter(EPSS.cve == cve).one_or_none()
        assert row is not None, "session_scope did not commit on clean exit"
        assert row.epss_score == 0.42


def test_session_scope_rolls_back_on_exception(engine, cleanup_epss):
    """An exception inside session_scope must roll back; the row must NOT persist."""
    from sqlalchemy.orm import Session

    from libinv.base import session_scope
    from libinv.models import EPSS

    cve = f"{SENTINEL_PREFIX}ROLLBACK"

    class _Boom(RuntimeError):
        pass

    with pytest.raises(_Boom):
        with session_scope() as s:
            s.add(
                EPSS(
                    cve=cve,
                    epss_score=0.99,
                    epss_percentile=0.99,
                    epss_date="2024-04-02",
                )
            )
            s.flush()  # send to the DB, but still inside the transaction
            raise _Boom("explode mid-scope")

    with Session(bind=engine) as fresh:
        row = fresh.query(EPSS).filter(EPSS.cve == cve).one_or_none()
        assert row is None, "session_scope did not roll back on exception"


def test_session_scope_removes_thread_local_session():
    """After session_scope exits, ScopedSession() must yield a fresh Session instance."""
    from libinv.base import ScopedSession
    from libinv.base import session_scope

    # Capture the session object used inside the scope.
    with session_scope() as inside:
        inner_id = id(inside)

    # After exit, the scoped registry should have been cleared via .remove(),
    # so the next call returns a brand-new Session.
    after = ScopedSession()
    try:
        assert id(after) != inner_id, (
            "ScopedSession.remove() was not called: the same session leaked across scopes"
        )
    finally:
        ScopedSession.remove()
