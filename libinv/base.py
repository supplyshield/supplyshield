from __future__ import annotations

from contextlib import contextmanager
from typing import Iterator

import sqlalchemy as db
from sqlalchemy import MetaData
from sqlalchemy import Table  # noqa: F401  re-exported for callers
from sqlalchemy import event
from sqlalchemy.engine import Engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import Mapper
from sqlalchemy.orm import Session as OrmSession
from sqlalchemy.orm import scoped_session
from sqlalchemy.orm import sessionmaker

from libinv.env import DB_STRING
from libinv.env import LIBINV_STRICT_LAZY


# Sprint 51.3 — engine creation is lazy.
#
# ``db.create_engine`` itself only parses the DSN — it does NOT open a
# TCP connection, so technically the import-time call is safe even when
# Postgres is unreachable. The real failure surface is the *first* SQL
# round-trip (``session.execute``, ``connect()``, etc.). Even so, we
# wrap engine instantiation in a ``get_engine()`` helper + module-level
# cache so:
#   1. A future SQLAlchemy version that decides to probe the server on
#      ``create_engine`` (some dialects already do via ``pool_pre_ping``
#      pre-check hooks) cannot crash the daemon at import time.
#   2. Callers that need to recreate the engine after a transient outage
#      can call ``reset_engine_cache()`` followed by ``get_engine()``.
#   3. The daemon startup-retry loop (``libinv/cli/daemon.py``) can
#      explicitly drive ``SELECT 1`` against the engine and back off
#      with exponential delays before the first ``session_scope()`` is
#      ever opened.
_engine: Engine | None = None


def get_engine() -> Engine:
    """Return the process-wide SQLAlchemy engine, creating it on first call.

    Lazy + cached. Subsequent calls return the same engine instance unless
    ``reset_engine_cache()`` has been invoked. Pool tuning matches Sprint
    35.1 (pool_size=10, max_overflow=20, pool_recycle=1800,
    pool_use_lifo=True, pool_pre_ping=True).
    """
    global _engine
    if _engine is None:
        _engine = db.create_engine(
            DB_STRING,
            pool_pre_ping=True,
            pool_size=10,
            max_overflow=20,
            pool_recycle=1800,
            pool_use_lifo=True,
        )
    return _engine


def reset_engine_cache() -> None:
    """Drop the cached engine + dispose its connection pool.

    Tests + Sprint 51.3's daemon retry loop call this to force a fresh
    ``create_engine`` invocation after a transient failure (e.g. so a
    rotated DB password picks up cleanly).
    """
    global _engine
    if _engine is not None:
        try:
            _engine.dispose()
        except Exception:
            pass
        _engine = None


engine: Engine = get_engine()
Session: sessionmaker = sessionmaker(bind=engine)

ScopedSession: scoped_session = scoped_session(Session)


# Sprint 56 — `_ConnDeprecationProxy` + module-level `conn` removed.
# All historical `libinv.base.conn` import sites were eliminated by
# Sprint 48.1 (helpers migrated to required `session` parameters) and
# the remaining four locally-scoped `conn` variables (cli/bridge.py,
# cli/daemon.py, api/health.py, api/actionable/_common.py) are *local*
# bindings to `Session()` / `engine.connect()` — they never depended
# on the module-level proxy. Prefer `session_scope()` for new code.


class LibinvBase:
    __table_args__ = {"schema": "libinv"}


Base = declarative_base(cls=LibinvBase)

metadata = MetaData()


# Sprint 37.1 — strict-lazy policy hook.
#
# When `LIBINV_STRICT_LAZY=true` (env var, default False), we register a
# one-shot `Mapper.after_configured` listener that walks every mapped
# relationship on the declarative ``Base.registry`` and flips its
# ``lazy`` strategy to ``"raise_on_sql"``. Any subsequent implicit
# attribute access that would otherwise trigger a lazy SELECT raises
# ``sqlalchemy.exc.InvalidRequestError`` instead. This is a dev/CI
# guardrail for surfacing N+1 patterns -- production default is
# intentionally False because legitimate call sites still rely on
# implicit loading.
def _apply_strict_lazy_policy() -> None:
    """Flip every mapped relationship to ``lazy='raise_on_sql'``.

    Walks ``Base.registry.mappers`` (the canonical declarative registry
    for libinv ORM classes) and swaps the default attribute-access
    loader so subsequent implicit loads raise instead of issuing SQL.

    Mechanics:
      - ``rel.lazy`` is the public knob; we set it for introspection.
      - The real loader used during attribute access is
        ``rel._lazy_strategy`` (populated in ``RelationshipProperty.
        do_init``). Replacing it with a ``RaiseLoader`` flips behavior
        without disturbing the cached ``strategy_key`` /
        ``_default_path_loader_key`` machinery the rest of the ORM
        depends on.

    Idempotent: re-applies the same loader on each invocation. Safe to
    call when no mappers have been declared yet (registry empty ->
    loop is a no-op).
    """
    raise_key = (("lazy", "raise_on_sql"),)
    for mapper in Base.registry.mappers:
        for rel in mapper.relationships:
            rel.lazy = "raise_on_sql"
            try:
                raise_strategy = rel._get_strategy(raise_key)
            except Exception:
                # Skip relationships that don't register a raise variant
                # (self-referential / custom strategies) rather than
                # crash boot.
                continue
            # The attribute-access path calls ``_lazy_strategy`` directly;
            # swap it to the raise variant.
            rel._lazy_strategy = raise_strategy


if LIBINV_STRICT_LAZY:
    @event.listens_for(Mapper, "after_configured")
    def _strict_lazy_after_configured() -> None:  # pragma: no cover - hook
        _apply_strict_lazy_policy()


@contextmanager
def session_scope() -> Iterator[OrmSession]:
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
