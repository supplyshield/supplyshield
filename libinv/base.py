import warnings
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


class _ConnDeprecationProxy:
    """Proxy that emits a one-shot DeprecationWarning on first use of `conn`.

    Sprint 0-12 migrated every libinv caller from `conn.<method>` to
    `with session_scope() as session: session.<method>` or the
    `s = session or conn` fallback inside methods that accept an
    optional `session=` kwarg. The `conn` symbol is retained only for
    that fallback (which uses `or conn` -- accesses `conn` only when
    `session is None`).

    Any *direct* `conn.<method>` call surfaces here and warns. The
    warning fires once per process to avoid log spam.
    """

    _warned = False

    def __init__(self, target):
        self._target = target

    def _warn_once(self):
        if not _ConnDeprecationProxy._warned:
            _ConnDeprecationProxy._warned = True
            warnings.warn(
                "libinv.base.conn is deprecated; use `session_scope()` or "
                "accept an explicit `session` parameter.",
                DeprecationWarning,
                stacklevel=3,
            )

    def __getattr__(self, name):
        self._warn_once()
        return getattr(self._target, name)

    def __call__(self, *args, **kwargs):
        self._warn_once()
        return self._target(*args, **kwargs)

    def __bool__(self):
        # Used by `s = session or conn` -- must not warn on `bool(conn)`
        # because that's the explicit fallback case Sprint 0-12 left in
        # place. Return True so `or conn` resolves to `conn` itself
        # when `session` is None/falsy.
        return True


# DEPRECATED: prefer `session_scope()` for explicit-lifecycle code, or accept a
# `session` parameter on model methods (see `Actionable.get_latest` / `get_safe_versions`
# for the canonical pattern). `conn` is kept as an alias for the scoped session so the
# ~30 existing call sites keep working; new code should not use it. Slated for removal
# once all callers are migrated (tracked under Sprint 4+).
conn = _ConnDeprecationProxy(ScopedSession)


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
