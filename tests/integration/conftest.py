"""
Integration-test fixtures.

Tests in this directory require a real PostgreSQL database. Set
TEST_DATABASE_URL to a libinv-shaped Postgres URL, e.g.:

    export TEST_DATABASE_URL=postgresql://postgres:postgres@localhost:5432/libinv_test

When unset, every test here is skipped cleanly so the unit-test run
(make tests) stays green without DB infrastructure.

Each test runs in its own savepoint and rolls back at teardown, so
tests are independent and the DB is left untouched.
"""
import os

import pytest


TEST_DATABASE_URL = os.environ.get("TEST_DATABASE_URL")


# Skip everything in this directory if no DB is configured.
# `collect_ignore_glob` is recognized by pytest in conftest.py and excludes
# matching files from collection at discovery time — so without a DB URL the
# whole integration suite is silently skipped and the unit suite stays green.
collect_ignore_glob = []
if not TEST_DATABASE_URL:
    collect_ignore_glob.append("test_*.py")


@pytest.fixture(scope="session")
def engine():
    """Session-scoped SQLAlchemy engine bound to TEST_DATABASE_URL.

    Ensures the `libinv` schema exists, then creates all tables via the
    production `Base.metadata`. Tables persist across the session and across
    test runs (idempotent via create_all + CREATE SCHEMA IF NOT EXISTS).
    """
    # Import here so libinv.env import doesn't blow up when TEST_DATABASE_URL
    # is unset but the user runs unit tests only.
    from sqlalchemy import create_engine
    from sqlalchemy import text

    eng = create_engine(TEST_DATABASE_URL, pool_pre_ping=True)

    # Ensure the libinv schema exists. All libinv models declare
    # __table_args__ = {"schema": "libinv"} via LibinvBase, so create_all
    # requires the schema to exist first.
    with eng.connect() as conn:
        conn.execute(text("CREATE SCHEMA IF NOT EXISTS libinv"))
        conn.commit()

    # Use the production Base.metadata to create the libinv-schema tables.
    from libinv.base import Base

    Base.metadata.create_all(eng)

    yield eng

    # Don't drop the schema — leaving artifacts is fine; the next run does
    # CREATE IF NOT EXISTS. Users who want a clean DB can drop it manually.
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
