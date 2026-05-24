"""Sprint 26 — verifies alembic baseline + FK-index migrations apply
cleanly against a real Postgres.

Sprint 2 set up alembic with two migrations:
- ``0001_baseline.py`` — empty, stamps the existing ``init.sql`` schema
- ``0002_fk_indexes.py`` — adds 17 FK + 2 composite indexes via
  ``CREATE INDEX CONCURRENTLY IF NOT EXISTS``

These tests exercise both, plus verify ``alembic_version`` lives in the
``libinv`` schema (Sprint 2 set ``version_table_schema='libinv'`` in
``alembic/env.py``).

The tests shell out to ``python -m alembic`` rather than calling the
library API in-process — this exercises the real env.py wiring and
guarantees we test the exact code path operators run in production.

Skipped automatically when ``TEST_DATABASE_URL`` is unset (the
``collect_ignore_glob`` pattern in ``tests/integration/conftest.py``
handles discovery-time exclusion).
"""
import os
import subprocess
from pathlib import Path
from urllib.parse import urlparse

import pytest
from sqlalchemy import inspect, text


REPO_ROOT = Path(__file__).resolve().parents[2]

# Sprint 2's head revision — bump this when a new migration lands.
# Sprint 34.2 + 34.3 added 0003 (epss_date -> Date) and 0004 (String(N) tightening).
HEAD_REVISION = "0004_string_n_tightening"


def _db_env_from_url(url: str) -> dict:
    """Translate a TEST_DATABASE_URL into the DB_* env vars libinv.env expects.

    ``alembic/env.py`` imports ``libinv.env.DB_STRING`` which is built at
    module-import time from ``DB_HOSTNAME``/``DB_USERNAME``/``DB_PASSWORD``/
    ``DB_NAME``. We can't override it via ``-x sqlalchemy.url=...`` because
    ``env.py`` calls ``config.set_main_option('sqlalchemy.url', DB_STRING)``
    after the override would have taken effect.

    Instead, we parse the SQLAlchemy URL and set the DB_* env vars before
    spawning the subprocess, so the freshly-imported ``libinv.env`` builds
    a ``DB_STRING`` pointing at the test database.
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


@pytest.fixture(scope="module")
def alembic_env(engine):
    """Drop + recreate the ``libinv`` schema, return the env dict for alembic.

    Yields a dict suitable for passing as ``env=`` to ``subprocess.run`` —
    it inherits the current process env, overlays the DB_* vars parsed from
    ``TEST_DATABASE_URL``, and adds harmless defaults for the JSON-parsed
    config keys ``libinv.env`` requires at import time (``JAVA_HOME``,
    ``BASE_IMAGE_JAVA_VERSION_MAPPING``, ``JOBS``).
    """
    # Sprint 30.1: prefer TEST_DATABASE_URL when set (operator override),
    # otherwise derive the DSN from the session-scoped ``engine`` fixture
    # (pytest-postgresql ephemeral DB). The engine.url's password is hidden
    # by default in __str__, so use render_as_string(hide_password=False).
    url = os.environ.get("TEST_DATABASE_URL") or engine.url.render_as_string(
        hide_password=False
    )

    # Fresh schema each module run so the migration starts from a known state.
    with engine.connect() as conn:
        conn.execute(text("DROP SCHEMA IF EXISTS libinv CASCADE"))
        conn.execute(text("CREATE SCHEMA libinv"))
        conn.commit()

    # Materialize ORM tables — simulates ``etc/initdb/init.sql`` in
    # production. ``0001_baseline.py`` is a no-op stamp that assumes the
    # schema was bootstrapped from init.sql, so subsequent alembic
    # migrations (``0002_fk_indexes`` and beyond) need tables to exist
    # before they can reference them.
    from libinv.base import Base

    Base.metadata.create_all(engine)

    env = dict(os.environ)
    env.update(_db_env_from_url(url))
    # libinv.env parses these as JSON at import time; supply empty defaults
    # in case the surrounding shell didn't set them.
    env.setdefault("JAVA_HOME", "{}")
    env.setdefault("BASE_IMAGE_JAVA_VERSION_MAPPING", "{}")
    env.setdefault("JOBS", "{}")
    yield env

    # Leave the schema in place. The session-scoped ``engine`` fixture from
    # conftest will recreate any missing tables via ``Base.metadata.create_all``
    # for any later tests that need them.


def _run_alembic(cmd_args, env):
    """Run ``alembic <cmd_args>`` from REPO_ROOT, return ``(rc, stdout, stderr)``."""
    result = subprocess.run(
        ["python", "-m", "alembic"] + cmd_args,
        cwd=str(REPO_ROOT),
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )
    return result.returncode, result.stdout, result.stderr


def test_alembic_upgrade_head_creates_version_table(alembic_env, engine):
    """``alembic upgrade head`` creates ``libinv.alembic_version`` and stamps the head."""
    rc, out, err = _run_alembic(["upgrade", "head"], env=alembic_env)
    assert rc == 0, f"alembic upgrade head failed:\nstdout={out}\nstderr={err}"

    insp = inspect(engine)
    assert insp.has_table("alembic_version", schema="libinv"), (
        "alembic_version table should be in the libinv schema "
        "(version_table_schema='libinv' per Sprint 2's env.py)"
    )

    with engine.connect() as conn:
        rows = conn.execute(
            text("SELECT version_num FROM libinv.alembic_version")
        ).all()
    versions = [r[0] for r in rows]
    assert HEAD_REVISION in versions, (
        f"Expected head={HEAD_REVISION!r}, got {versions!r}"
    )


def test_alembic_downgrade_then_upgrade_is_reversible(alembic_env, engine):
    """Downgrade one step then upgrade again — the head revision must reappear."""
    # Ensure we're at head first (upgrade is idempotent).
    rc, out, err = _run_alembic(["upgrade", "head"], env=alembic_env)
    assert rc == 0, f"pre-condition upgrade failed:\nstdout={out}\nstderr={err}"

    rc, out, err = _run_alembic(["downgrade", "-1"], env=alembic_env)
    assert rc == 0, f"alembic downgrade -1 failed:\nstdout={out}\nstderr={err}"

    rc, out, err = _run_alembic(["upgrade", "head"], env=alembic_env)
    assert rc == 0, f"alembic upgrade head (post-downgrade) failed:\nstdout={out}\nstderr={err}"

    with engine.connect() as conn:
        rows = conn.execute(
            text("SELECT version_num FROM libinv.alembic_version")
        ).all()
    versions = [r[0] for r in rows]
    assert HEAD_REVISION in versions, (
        f"After downgrade+upgrade, expected head={HEAD_REVISION!r}, got {versions!r}"
    )


def test_alembic_indexes_present_when_tables_exist(alembic_env, engine):
    """Sprint 2's FK indexes are created when the underlying tables exist.

    The ``engine`` fixture from conftest calls ``Base.metadata.create_all``,
    so the libinv tables exist before this test runs. The fixture in this
    module then drops + recreates the schema, but the ``engine`` fixture is
    session-scoped: any subsequent ``inspect`` call doesn't re-run create_all.
    We therefore re-issue ``create_all`` here to ensure the tables exist,
    then run the migration and verify at least the composite index
    ``ix_epss_cve_updated_at`` (on a small, always-present table) is created.
    """
    from libinv.base import Base

    Base.metadata.create_all(engine)

    rc, out, err = _run_alembic(["upgrade", "head"], env=alembic_env)
    assert rc == 0, f"alembic upgrade head failed:\nstdout={out}\nstderr={err}"

    with engine.connect() as conn:
        rows = conn.execute(
            text(
                """
                SELECT indexname FROM pg_indexes
                WHERE schemaname = 'libinv' AND indexname LIKE 'ix_%'
                """
            )
        ).all()
    index_names = {r[0] for r in rows}
    # ``ix_epss_cve_updated_at`` is on the ``epss`` table, which is part of
    # ``Base.metadata`` — so create_all guarantees it exists.
    assert "ix_epss_cve_updated_at" in index_names, (
        f"expected ix_epss_cve_updated_at after upgrade, got: {sorted(index_names)!r}"
    )
