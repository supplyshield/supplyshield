"""
Integration-test fixtures.

Tests in this directory require a real PostgreSQL database. Resolution order
for the DSN used by the ``engine`` fixture:

  1. ``TEST_DATABASE_URL`` env var (operator override — points at a manually
     provisioned Postgres).
  2. The ``postgresql`` fixture from pytest-postgresql (ephemeral in-tmpfs DB,
     spun up by the top-level ``tests/conftest.py``).

When neither is available (pytest-postgresql install broken AND no env var),
every test here is skipped cleanly so the unit-test run (``make tests``)
stays green without DB infrastructure.

Sprint 30.2 wires ``alembic upgrade head`` into the ``engine`` fixture so the
integration suite always sees a fully-migrated schema, mirroring production.
"""
import os
from pathlib import Path
from urllib.parse import urlparse

import pytest


_TEST_DATABASE_URL_ENV = os.environ.get("TEST_DATABASE_URL")


# When neither an operator-supplied DSN nor pytest-postgresql is available,
# silently skip the whole integration suite. We detect pytest-postgresql by
# importing the package — if it's missing we fall back to the legacy
# env-var-only behavior so unit-only environments keep working.
try:
    import pytest_postgresql  # noqa: F401

    _HAS_PYTEST_POSTGRESQL = True
except ImportError:  # pragma: no cover
    _HAS_PYTEST_POSTGRESQL = False


collect_ignore_glob = []
if not _TEST_DATABASE_URL_ENV and not _HAS_PYTEST_POSTGRESQL:
    collect_ignore_glob.append("test_*.py")


REPO_ROOT = Path(__file__).resolve().parents[2]


def _set_db_env_from_url(url: str) -> dict:
    """Translate a SQLAlchemy DSN into DB_* env vars libinv.env reads.

    Returns a NEW dict layered on top of ``os.environ`` so callers can mutate
    the live process environment safely.
    """
    parsed = urlparse(url)
    host = parsed.hostname or ""
    if parsed.port:
        host = f"{host}:{parsed.port}"
    return {
        "DB_HOSTNAME": host,
        "DB_USERNAME": parsed.username or "",
        "DB_PASSWORD": parsed.password or "",
        "DB_NAME": (parsed.path or "/").lstrip("/") or "scancodeio",
    }


def _run_alembic_upgrade_head(db_url: str) -> None:
    """Programmatically run ``alembic upgrade head`` against ``db_url``.

    Uses ``alembic.config.Config`` + ``alembic.command.upgrade`` rather than
    a subprocess so we share the in-process import graph (faster, no env
    plumbing). ``alembic/env.py:25`` does ``config.set_main_option(
    "sqlalchemy.url", DB_STRING)`` which unconditionally overrides any URL
    the caller passes via ``cfg.set_main_option(...)`` — so we have to make
    sure ``libinv.env.DB_STRING`` itself points at the test database.

    ``libinv.env`` is imported once at the very start of the pytest session
    (via ``tests/conftest.py`` → ``flask_app_client``-related stubs) with
    stub ``DB_HOSTNAME=x`` values. Subsequent ``os.environ`` updates do NOT
    re-trigger that import, so ``DB_STRING`` stays stale. We force-reload
    ``libinv.env`` after patching the DB_* env vars so the next ``from
    libinv.env import DB_STRING`` inside ``alembic/env.py`` picks up the
    correct DSN.
    """
    import importlib

    from alembic import command as alembic_command
    from alembic.config import Config as AlembicConfig

    db_env = _set_db_env_from_url(db_url)
    for k, v in db_env.items():
        os.environ[k] = v

    import libinv.env as _libinv_env

    importlib.reload(_libinv_env)

    cfg = AlembicConfig(str(REPO_ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(REPO_ROOT / "alembic"))
    cfg.set_main_option("sqlalchemy.url", db_url)
    alembic_command.upgrade(cfg, "head")


_INTEGRATION_DBNAME = "supplyshield_integration_tests"


def _resolve_db_url(request) -> str:
    """Return a Postgres DSN at session scope.

    Resolution order:
      1. ``TEST_DATABASE_URL`` env var (explicit operator override).
      2. ``postgresql_proc`` (session-scoped) — bootstrap a dedicated DB
         on the running proc, scoped to the test session.

    NOTE: ``factories.postgresql(...)`` is function-scoped by design in
    pytest-postgresql 6.x and has no ``scope=`` parameter. The session-
    scoped ``engine`` fixture below cannot consume it without a
    ScopeMismatch — so we go one level lower and use ``postgresql_proc``
    (session-scoped) directly, creating/dropping our own DB.
    """
    if _TEST_DATABASE_URL_ENV:
        return _TEST_DATABASE_URL_ENV

    from sqlalchemy import create_engine
    from sqlalchemy import text

    pg_proc = request.getfixturevalue("postgresql_proc")
    user = pg_proc.user
    host = pg_proc.host or "localhost"
    port = pg_proc.port
    auth = f"{user}@"  # pytest-postgresql does not configure a password

    bootstrap_url = f"postgresql://{auth}{host}:{port}/postgres"
    bootstrap = create_engine(bootstrap_url, isolation_level="AUTOCOMMIT")
    with bootstrap.connect() as conn:
        conn.execute(text(f'DROP DATABASE IF EXISTS "{_INTEGRATION_DBNAME}"'))
        conn.execute(text(f'CREATE DATABASE "{_INTEGRATION_DBNAME}"'))
    bootstrap.dispose()

    return f"postgresql://{auth}{host}:{port}/{_INTEGRATION_DBNAME}"


@pytest.fixture(scope="session")
def engine(request):
    """Session-scoped SQLAlchemy engine.

    Source of DSN: ``TEST_DATABASE_URL`` if set, else the pytest-postgresql
    ephemeral DB (resolved lazily via ``request.getfixturevalue``).

    Steps:
      1. Resolve DSN.
      2. ``CREATE SCHEMA IF NOT EXISTS libinv`` (alembic + ORM both expect it).
      3. Run ``alembic upgrade head`` in-process so integration tests run
         against the production migration set.
      4. Belt-and-braces ``Base.metadata.create_all`` to materialize any ORM
         tables not yet covered by alembic (current head is FK-indexes only).
    """
    from sqlalchemy import create_engine
    from sqlalchemy import text

    db_url = _resolve_db_url(request)

    eng = create_engine(db_url, pool_pre_ping=True)

    with eng.connect() as conn:
        conn.execute(text("CREATE SCHEMA IF NOT EXISTS libinv"))
        conn.commit()

    # Step 1: ORM-level table creation simulates ``etc/initdb/init.sql`` in
    # production. ``0001_baseline.py`` is a no-op stamp that assumes the
    # schema was bootstrapped from init.sql, so we must materialize tables
    # via ORM before any subsequent alembic migration runs (e.g. 0002 adds
    # FK indexes and would fail on a fresh DB if tables don't yet exist).
    from libinv.base import Base

    Base.metadata.create_all(eng)

    # Step 2: Run alembic migrations against the ephemeral DB so the schema
    # picks up post-baseline revisions (FK indexes, etc.). ``alembic.command
    # .upgrade`` is idempotent against a DB already at head — safe to call
    # repeatedly across sessions.
    _run_alembic_upgrade_head(db_url)

    yield eng

    eng.dispose()


@pytest.fixture
def db_session(engine):
    """Yield a Session inside a transaction that's rolled back at teardown.

    Each test gets its own connection + outer transaction. On teardown the
    transaction is rolled back, so DB state is left untouched even if the
    test issued commits inside the same transaction. (For nested commits we
    rely on SQLAlchemy's join-on-savepoint trick if a test needs it; the
    simple rollback here is sufficient for the cases we exercise.)
    """
    from sqlalchemy.orm import Session

    connection = engine.connect()
    trans = connection.begin()
    session = Session(bind=connection)
    try:
        yield session
    finally:
        session.close()
        if trans.is_active:
            trans.rollback()
        connection.close()
