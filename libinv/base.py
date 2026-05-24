from contextlib import contextmanager

import sqlalchemy as db
from sqlalchemy import MetaData
from sqlalchemy import Table  # noqa: F401  re-exported for callers
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import scoped_session
from sqlalchemy.orm import sessionmaker

from libinv.env import DB_STRING

engine = db.create_engine(DB_STRING, pool_pre_ping=True)
Session = sessionmaker(bind=engine)

ScopedSession = scoped_session(Session)

# DEPRECATED: prefer `session_scope()` for explicit-lifecycle code, or accept a
# `session` parameter on model methods (see `Actionable.get_latest` / `get_safe_versions`
# for the canonical pattern). `conn` is kept as an alias for the scoped session so the
# ~30 existing call sites keep working; new code should not use it. Slated for removal
# once all callers are migrated (tracked under Sprint 4+).
conn = ScopedSession


class LibinvBase:
    __table_args__ = {"schema": "libinv"}


Base = declarative_base(cls=LibinvBase)

metadata = MetaData()


@contextmanager
def session_scope():
    """Yield a thread-scoped Session for explicit-lifecycle code.

    Commits on clean exit, rolls back on exception, and removes the thread's
    session at the end so subsequent calls start fresh. Prefer this over
    `with Session() as s` for new code; existing code that uses the
    module-level `conn` keeps working — `conn` is now the scoped session, so
    per-thread isolation is automatic under Flask threading and
    ThreadPoolExecutor.
    """
    session = ScopedSession()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        ScopedSession.remove()
