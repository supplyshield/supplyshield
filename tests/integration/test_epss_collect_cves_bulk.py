"""Sprint 38.1 regression test: ``_collect_cves_for_projects`` is N+1-free.

Strategy
--------
Stand up an ad-hoc ``scanpipe_discoveredpackage`` table (``managed=False`` in
the production Django scancode.io schema, so it isn't covered by alembic),
seed it with rows spanning multiple project_ids, then run the helper while
counting SQL executions via ``sqlalchemy.event.listen('before_cursor_execute')``.

Before Sprint 38.1
~~~~~~~~~~~~~~~~~~
For ``N`` project UUIDs, the helper issued ``~N`` SELECTs (one per project).

After Sprint 38.1
~~~~~~~~~~~~~~~~~
A single ``WHERE project_id IN (:ids)`` query feeds an in-Python ``defaultdict``
grouping, so the query count stays constant (== 1 for the SQL workload itself,
plus the ambient BEGIN that SQLAlchemy may emit on a fresh transaction —
the test bounds at ``<= 2`` to absorb that without making the assertion brittle).

The integration suite runs against the same Postgres harness as the other
integration tests; without pytest-postgresql AND without ``TEST_DATABASE_URL``
the suite is skipped at collection time by ``tests/integration/conftest.py``.
"""
from __future__ import annotations

import uuid

import pytest
from sqlalchemy import JSON
from sqlalchemy import Column
from sqlalchemy import MetaData
from sqlalchemy import String
from sqlalchemy import Table
from sqlalchemy import event
from sqlalchemy.orm import Session as OrmSession
from sqlalchemy.orm import registry


# Number of distinct project UUIDs we seed. The N+1 path would fire ~N
# SELECTs; we assert <= 2 (the bulk SELECT + an optional BEGIN). Picked
# small enough to keep the test fast but large enough that the ceiling
# is well below the cascade floor.
N_PROJECTS = 6
PACKAGES_PER_PROJECT = 3


@pytest.fixture
def discovered_package_table(engine):
    """Materialize a minimal ``scanpipe_discoveredpackage`` table.

    In production this table is owned by Django (``managed=False`` in
    libinv_models.py), so alembic does not create it. We add it on
    demand using a fresh ``MetaData`` so we don't pollute libinv's
    declarative metadata.

    Drops the table at teardown so concurrent integration tests aren't
    affected.
    """
    from sqlalchemy import text

    md = MetaData()
    tbl = Table(
        "scanpipe_discoveredpackage",
        md,
        Column("uuid", String(36), primary_key=True),
        Column("project_id", String(36), nullable=False, index=True),
        Column("affected_by_vulnerabilities", JSON, nullable=True),
        # Minimal additional columns the ORM reflection layer expects to
        # exist. The real table has ~40 columns; we only need enough for
        # SQLAlchemy's autoload to succeed if anything reflects later.
        schema="public",
    )
    with engine.begin() as conn:
        # Drop if a stale copy exists from a prior aborted run.
        conn.execute(text('DROP TABLE IF EXISTS public.scanpipe_discoveredpackage'))
        md.create_all(conn)
    yield tbl
    with engine.begin() as conn:
        conn.execute(text('DROP TABLE IF EXISTS public.scanpipe_discoveredpackage'))


@pytest.fixture
def discovered_package_model(discovered_package_table):
    """Bind a fresh declarative class to the test table.

    We can't reuse libinv.scio_models.DiscoveredPackage because in this
    test environment ``_load_scanpipe_table`` was evaluated at import
    time against the integration DB before our ``discovered_package_table``
    fixture ran, so the attribute is likely ``None``. Building a local
    class via ``registry().map_imperatively`` keeps the test self-contained.
    """
    mapper_registry = registry()

    class _DP:
        pass

    mapper_registry.map_imperatively(_DP, discovered_package_table)
    return _DP


@pytest.fixture
def seeded_projects(engine, discovered_package_model):
    """Insert N_PROJECTS distinct projects, each with PACKAGES_PER_PROJECT rows.

    Each package carries an ``affected_by_vulnerabilities`` JSON blob with
    a single CVE alias so the helper finds something to collect.
    """
    project_uuids = [str(uuid.uuid4()) for _ in range(N_PROJECTS)]
    cve_per_pkg = []

    with OrmSession(bind=engine) as s:
        for proj in project_uuids:
            for i in range(PACKAGES_PER_PROJECT):
                cve_id = f"CVE-2024-{proj[:4]}{i}"
                cve_per_pkg.append(cve_id)
                pkg = discovered_package_model()
                pkg.uuid = str(uuid.uuid4())
                pkg.project_id = proj
                pkg.affected_by_vulnerabilities = [
                    {"aliases": [cve_id, "GHSA-x"]},
                ]
                s.add(pkg)
        s.commit()

    expected_cves = {c.upper() for c in cve_per_pkg}
    yield project_uuids, expected_cves


@pytest.fixture
def query_counter(engine):
    """Count ``before_cursor_execute`` events on the integration engine.

    Returns a dict ``{"count": int, "statements": list[str]}`` that the
    test can reset between phases.
    """
    state = {"count": 0, "statements": []}

    def _on(conn, cursor, statement, parameters, context, executemany):  # noqa: ARG001
        state["count"] += 1
        state["statements"].append(statement[:120])

    event.listen(engine, "before_cursor_execute", _on)
    try:
        yield state
    finally:
        event.remove(engine, "before_cursor_execute", _on)


def test_collect_cves_for_projects_issues_single_bulk_query(
    engine, discovered_package_model, seeded_projects, query_counter, monkeypatch
):
    """Helper must issue <= 2 SELECT/BEGIN executions regardless of project count."""
    project_uuids, expected_cves = seeded_projects

    # Point the helper at the test-scoped DiscoveredPackage. The legacy SQL
    # path imports it from libinv.scio_models at module load and resolves
    # the symbol via the local ``DiscoveredPackage`` reference in epss.py.
    import libinv.cli.epss as epss_mod

    monkeypatch.setattr(epss_mod, "DiscoveredPackage", discovered_package_model)
    # Ensure the HTTP path is OFF so we exercise the SQL bulk fetch.
    monkeypatch.setattr(epss_mod, "get_default_client", lambda: None)

    with OrmSession(bind=engine) as s:
        # Reset the counter so the prior seed/transaction noise isn't counted.
        query_counter["count"] = 0
        query_counter["statements"].clear()

        cves = epss_mod._collect_cves_for_projects(
            session=s, project_uuids=project_uuids, verbose=False
        )

    # Correctness: every expected CVE was found, GHSA aliases were filtered.
    assert cves == expected_cves
    assert all(not c.startswith("GHSA") for c in cves)

    # The actual regression guard: with the N+1 fix in place, the SQL
    # workload is exactly one bulk SELECT. Allow <= 2 to absorb an
    # implicit BEGIN that SQLAlchemy may insert depending on connection
    # state. Any value >= N_PROJECTS would mean the N+1 is back.
    assert query_counter["count"] <= 2, (
        f"N+1 regression: {query_counter['count']} queries fired for "
        f"N={N_PROJECTS} projects (threshold 2). "
        f"Sample stmts: {query_counter['statements'][:5]}"
    )


def test_collect_cves_for_projects_empty_input_issues_zero_queries(
    engine, discovered_package_model, query_counter, monkeypatch
):
    """Empty ``project_uuids`` must not hit the DB at all."""
    import libinv.cli.epss as epss_mod

    monkeypatch.setattr(epss_mod, "DiscoveredPackage", discovered_package_model)
    monkeypatch.setattr(epss_mod, "get_default_client", lambda: None)

    with OrmSession(bind=engine) as s:
        query_counter["count"] = 0
        query_counter["statements"].clear()

        cves = epss_mod._collect_cves_for_projects(
            session=s, project_uuids=[], verbose=False
        )

    assert cves == set()
    assert query_counter["count"] == 0, (
        f"Empty input fired {query_counter['count']} queries; expected 0. "
        f"Stmts: {query_counter['statements']}"
    )
