from __future__ import annotations

import warnings
from contextlib import contextmanager
from typing import Any
from typing import ClassVar
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

engine: Engine = db.create_engine(
    DB_STRING,
    pool_pre_ping=True,
    pool_size=10,
    max_overflow=20,
    pool_recycle=1800,
    pool_use_lifo=True,
)
Session: sessionmaker = sessionmaker(bind=engine)

ScopedSession: scoped_session = scoped_session(Session)


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

    _warned: ClassVar[bool] = False
    _target: Any

    def __init__(self, target: Any) -> None:
        self._target = target

    def _warn_once(self) -> None:
        if not _ConnDeprecationProxy._warned:
            _ConnDeprecationProxy._warned = True
            warnings.warn(
                "libinv.base.conn is deprecated; use `session_scope()` or "
                "accept an explicit `session` parameter.",
                DeprecationWarning,
                stacklevel=3,
            )

    def __getattr__(self, name: str) -> Any:
        self._warn_once()
        return getattr(self._target, name)

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        self._warn_once()
        return self._target(*args, **kwargs)

    def __bool__(self) -> bool:
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
