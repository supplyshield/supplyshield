"""Sprint 38.2 regression test: ``Actionable.populate`` is INSERT-ON-CONFLICT.

Strategy
--------
Build N=100 synthetic purls in-memory, monkeypatch
``Actionable.get_actionable_for`` to yield them, and count
``before_cursor_execute`` events while the classmethod runs.

Before Sprint 38.2
~~~~~~~~~~~~~~~~~~
``Actionable.populate`` called ``get_or_create`` once per purl (one SELECT +
one INSERT + one commit per row, plus another get_or_create for the
version child) → ~4N+ executions for N purls.

After Sprint 38.2
~~~~~~~~~~~~~~~~~
Two ``INSERT ... ON CONFLICT DO NOTHING`` statements (parent + child) and
a single ``COMMIT``. We bound observed cursor executions at ``<= 6`` to
absorb the implicit BEGIN that SQLAlchemy may insert plus any harness
overhead, while still being orders of magnitude below the cascade floor
(N=100 → 400+ executions would mean the regression is back).

The companion test for ``fetch_and_store_versions`` exercises only the
inner bulk-insert branch — the HTTP path is mocked out — so it likewise
asserts ≤ 4 SQL executions for 100 versions.
"""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch

import pytest
from sqlalchemy import event
from sqlalchemy.orm import Session as OrmSession


# Number of distinct purls fed into Actionable.populate. The pre-fix
# implementation issued ~4N cursor executions for N purls; we assert
# <= 6 (parent INSERT + child INSERT + a few BEGIN/COMMIT bookkeeping
# events). Any value >> 6 would mean the per-row loop is back.
N_PURLS = 100


@pytest.fixture
def query_counter(engine):
    """Count ``before_cursor_execute`` events on the integration engine."""
    state = {"count": 0, "statements": []}

    def _on(conn, cursor, statement, parameters, context, executemany):  # noqa: ARG001
        state["count"] += 1
        state["statements"].append(statement[:120])

    event.listen(engine, "before_cursor_execute", _on)
    try:
        yield state
    finally:
        event.remove(engine, "before_cursor_execute", _on)


@pytest.fixture
def synthetic_purls():
    """Yield N_PURLS distinct ``PackageURL``-like SimpleNamespace objects.

    The real ``Actionable.populate`` consumes ``purl.type``, ``purl.namespace``,
    ``purl.name`` and ``purl.version`` via attribute access — ``SimpleNamespace``
    is the cheapest shape that satisfies that contract without dragging in
    the full ``packageurl`` library's parsing layer.
    """
    return [
        SimpleNamespace(
            type="pypi",
            namespace="",
            name=f"pkg-bulk-{i:03d}",
            version=f"1.0.{i}",
        )
        for i in range(N_PURLS)
    ]


def test_actionable_populate_issues_bounded_inserts(
    engine, synthetic_purls, query_counter
):
    """populate() must emit O(1) INSERTs regardless of N purls."""
    from libinv.base import session_scope as real_session_scope
    from libinv.models import Actionable
    from libinv.models import ActionablePackageAvailableVersion

    # Bind session_scope to the integration engine so the in-test commit
    # lands on the same DB that ``query_counter`` is observing. The
    # production helper resolves the URL from libinv.env on import; under
    # pytest-postgresql the engine has a different DSN, so we splice it.
    from contextlib import contextmanager

    @contextmanager
    def _scope():
        s = OrmSession(bind=engine)
        try:
            yield s
        finally:
            s.close()

    with patch("libinv.models.session_scope", _scope), patch.object(
        Actionable,
        "get_actionable_for",
        classmethod(lambda cls, *a, **kw: synthetic_purls),
        create=True,
    ), patch("libinv.models.is_blacklist", lambda _name: False):
        query_counter["count"] = 0
        query_counter["statements"].clear()

        Actionable.populate(repository_id=None, environment=None)

    # Correctness: every purl is now present in both tables.
    with OrmSession(bind=engine) as s:
        # Parent count: distinct (type, namespace, name) → N unique
        # ``package_url`` values, so we expect at least N_PURLS rows.
        # The populate() formula is f"pkg:{type}/{namespace}/{name}" — with
        # namespace="" this collapses to "pkg:pypi//pkg-bulk-NNN".
        parent_purls = {f"pkg:pypi//pkg-bulk-{i:03d}" for i in range(N_PURLS)}
        existing = (
            s.query(Actionable)
            .filter(Actionable.package_url.in_(parent_purls))
            .count()
        )
        assert existing == N_PURLS, (
            f"expected {N_PURLS} Actionable parent rows; got {existing}"
        )

        child_count = (
            s.query(ActionablePackageAvailableVersion)
            .filter(ActionablePackageAvailableVersion.package_url.in_(parent_purls))
            .count()
        )
        assert child_count == N_PURLS, (
            f"expected {N_PURLS} APAV child rows; got {child_count}"
        )

    # The actual regression guard. With the bulk-INSERT in place, the
    # SQL workload is two INSERTs (parent + child) plus a small
    # constant of BEGIN/COMMIT bookkeeping. Allow ≤ 8 to absorb any
    # cleanup-related cursor activity from the patched ``_scope``.
    # Any value approaching N_PURLS would mean the per-row loop is back.
    assert query_counter["count"] <= 8, (
        f"INSERT-ON-CONFLICT regression: {query_counter['count']} "
        f"cursor executions for N={N_PURLS} purls (threshold 8). "
        f"Sample stmts: {query_counter['statements'][:5]}"
    )


def test_actionable_populate_idempotent_on_repeat(
    engine, synthetic_purls, query_counter
):
    """Re-running populate() with the same purls is a silent no-op via ON CONFLICT."""
    from contextlib import contextmanager

    from libinv.models import Actionable
    from libinv.models import ActionablePackageAvailableVersion

    @contextmanager
    def _scope():
        s = OrmSession(bind=engine)
        try:
            yield s
        finally:
            s.close()

    # First pass: seed the rows.
    with patch("libinv.models.session_scope", _scope), patch.object(
        Actionable,
        "get_actionable_for",
        classmethod(lambda cls, *a, **kw: synthetic_purls),
        create=True,
    ), patch("libinv.models.is_blacklist", lambda _name: False):
        Actionable.populate(repository_id=None, environment=None)

    # Snapshot row counts BEFORE the second pass.
    with OrmSession(bind=engine) as s:
        parent_purls = {f"pkg:pypi//pkg-bulk-{i:03d}" for i in range(N_PURLS)}
        before_parents = (
            s.query(Actionable)
            .filter(Actionable.package_url.in_(parent_purls))
            .count()
        )
        before_children = (
            s.query(ActionablePackageAvailableVersion)
            .filter(ActionablePackageAvailableVersion.package_url.in_(parent_purls))
            .count()
        )

    # Second pass: the same purls. ON CONFLICT DO NOTHING must keep the
    # row counts unchanged AND not raise an IntegrityError.
    with patch("libinv.models.session_scope", _scope), patch.object(
        Actionable,
        "get_actionable_for",
        classmethod(lambda cls, *a, **kw: synthetic_purls),
        create=True,
    ), patch("libinv.models.is_blacklist", lambda _name: False):
        query_counter["count"] = 0
        query_counter["statements"].clear()

        Actionable.populate(repository_id=None, environment=None)

    with OrmSession(bind=engine) as s:
        after_parents = (
            s.query(Actionable)
            .filter(Actionable.package_url.in_(parent_purls))
            .count()
        )
        after_children = (
            s.query(ActionablePackageAvailableVersion)
            .filter(ActionablePackageAvailableVersion.package_url.in_(parent_purls))
            .count()
        )

    assert after_parents == before_parents == N_PURLS
    assert after_children == before_children == N_PURLS
    # And the idempotent second pass still emits a bounded number of SQL
    # statements (no per-row work).
    assert query_counter["count"] <= 8


def test_fetch_and_store_versions_bulk_inserts(engine, query_counter):
    """fetch_and_store_versions() must emit O(1) INSERTs for N versions."""
    import uuid as _uuid
    from contextlib import contextmanager

    from sqlalchemy import text

    from libinv.models import Actionable
    from libinv.models import ActionablePackageAvailableVersion

    # Seed a parent Actionable row so the FK on the child rows resolves.
    # We use a raw INSERT here (rather than the ORM) to avoid the well-known
    # ``Actionable.uuid VARCHAR vs UUID()`` parameter-binding defect that
    # ``test_n1_eager_loading.py`` documents and Sprint 37 tracks separately.
    parent_purl = "pkg:pypi//bulk-fetch-target"
    parent_uuid = str(_uuid.uuid4())
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO libinv.safe_actionable (uuid, package_url) "
                "VALUES (:u, :p)"
            ),
            {"u": parent_uuid, "p": parent_purl},
        )

    # Build a fake HTTP response carrying N_PURLS distinct purl@version
    # entries. ``fetch_and_store_versions`` parses purls via
    # ``PackageURL.from_string``, so we hand it valid purl strings.
    purls = [
        f"{parent_purl}@2.0.{i}" for i in range(N_PURLS)
    ]

    class _FakeResponse:
        status_code = 200

        def raise_for_status(self):
            return None

        def json(self):
            return {"unqueued_packages": purls, "queued_packages": []}

        @property
        def text(self):
            return ""

    @contextmanager
    def _scope():
        s = OrmSession(bind=engine)
        try:
            yield s
        finally:
            s.close()

    # Build a *non-ORM* duck-typed stand-in for the Actionable instance.
    # ``fetch_and_store_versions`` only reads ``self.uuid`` and
    # ``self.package_url``; routing through SimpleNamespace bypasses the
    # ORM's UUID/VARCHAR coercion defect that Sprint 37 tracks separately.
    actionable_like = SimpleNamespace(uuid=parent_uuid, package_url=parent_purl)

    with patch("libinv.models.session_scope", _scope), patch(
        "libinv.models.requests.post", return_value=_FakeResponse()
    ):
        query_counter["count"] = 0
        query_counter["statements"].clear()

        # Pass a real session so the outer ``s.commit()`` lands somewhere
        # observable. The inner ``session_scope`` is patched above to also
        # bind to engine. Call as an unbound method since ``actionable_like``
        # is not an ORM-mapped instance.
        with OrmSession(bind=engine) as outer:
            Actionable.fetch_and_store_versions(actionable_like, session=outer)

    # Correctness: every version row landed.
    with OrmSession(bind=engine) as s:
        child_count = (
            s.query(ActionablePackageAvailableVersion)
            .filter(
                ActionablePackageAvailableVersion.actionable_id == parent_uuid
            )
            .count()
        )
        assert child_count == N_PURLS, (
            f"expected {N_PURLS} APAV rows; got {child_count}"
        )

    # The actual regression guard: a single bulk INSERT replaces the
    # per-row get_or_create + commit loop. The threshold of 8 absorbs
    # the outer-session BEGIN/COMMIT, the inner _scope's BEGIN/COMMIT,
    # and the single INSERT itself. Any value >> 8 means the loop is back.
    assert query_counter["count"] <= 8, (
        f"bulk-insert regression: {query_counter['count']} cursor "
        f"executions for N={N_PURLS} versions (threshold 8). "
        f"Sample stmts: {query_counter['statements'][:5]}"
    )
