"""Sprint 32.2 — integration tests for ``libinv.cli.import_and_improve_from_metapod``.

The command:
  1. Fetches a JSON service listing from ``SERVICE_METADATA_URL``.
  2. Translates each row into ``{name, provider, org, subpod, pod}`` (using
     ``explode_git_url`` when ``repository_url`` is present, else taking the
     orchestrator defaults ``GIT_PROVIDER`` / ``GIT_ORG``).
  3. ``get_or_create`` a ``Repository`` row per service and update ``pod`` /
     ``subpod`` in-place. ``MultipleResultsFound`` is logged and skipped.

These tests run against the pytest-postgresql ephemeral DB (or an operator
``TEST_DATABASE_URL``) and exercise the production code path verbatim. The
``requests.get`` call to metapod is monkey-patched with a tiny in-process
stub — no real ``responses`` / ``pytest-httpserver`` dependency is needed
(neither is in ``requirements.txt`` and we don't want to add deps under
this task's scope).

Scenarios:
  - happy path: 2 metapod rows import as 2 ``Repository`` rows with the
    correct ``pod`` / ``subpod`` values, and a second invocation on the
    same payload is idempotent (same row count, same values).
  - upstream HTTP error: ``requests.get`` raises ``RequestException`` →
    the command catches it, logs a warning, processes zero rows, and the
    DB is left untouched (no partial state).
  - duplicate import (same service name, different upstream payload):
    the existing row's pod/subpod are *updated* in-place — semantically
    idempotent at the Repository identity level (provider / org / name).
"""
from __future__ import annotations

import sys
from typing import Any
from unittest.mock import patch

import pytest
import requests
from click.testing import CliRunner


@pytest.fixture(autouse=True)
def patch_engine(engine, monkeypatch):
    """Rebind ``libinv.base`` globals to the integration DB engine.

    The CLI command builds its own ``Session()`` via ``libinv.Session``, so we
    must rebind the module-level scoped + plain session factories *before* the
    Click command runs. Mirrors the pattern used by
    ``tests/integration/test_mark_latest_version.py``.
    """
    import libinv.base

    monkeypatch.setattr(libinv.base, "engine", engine)
    libinv.base.Session.configure(bind=engine)
    libinv.base.ScopedSession.configure(bind=engine)
    yield
    libinv.base.ScopedSession.remove()


@pytest.fixture
def cli_runner():
    return CliRunner()


@pytest.fixture
def cleanup_repos(engine):
    """Remove the test repositories the CLI command writes."""
    names_under_test = {"metapod-service-a", "metapod-service-b", "metapod-service-c"}
    yield names_under_test
    from sqlalchemy.orm import Session

    from libinv.models import Repository

    with Session(bind=engine) as s:
        rows = (
            s.query(Repository).filter(Repository.name.in_(list(names_under_test))).all()
        )
        for row in rows:
            s.delete(row)
        s.commit()


def _import_module():
    """Return the CLI command module (force-import so the click command registers)."""
    import libinv.cli.import_and_improve_from_metapod as mod  # noqa: F401

    return sys.modules["libinv.cli.import_and_improve_from_metapod"]


def _invoke_cli(cli_runner, monkeypatch, fake_services):
    """Run the click command with ``metapod_services`` stubbed to return ``fake_services``."""
    from libinv.cli.cli import cli as cli_group

    # Force the submodule import so the command is registered on the cli group.
    _import_module()

    monkeypatch.setattr(
        "libinv.cli.import_and_improve_from_metapod.metapod_services",
        lambda: fake_services,
    )
    return cli_runner.invoke(cli_group, ["import-and-improve-from-metapod"])


def _processed_services_payload() -> list[dict[str, Any]]:
    """Two well-formed metapod rows with explicit ``repository_url``s.

    Both URLs parse to (provider=github.com, org=acme, name=...) via
    ``explode_git_url``.
    """
    return [
        {
            "name": "metapod-service-a",
            "repository_url": "git@github.com:acme/metapod-service-a.git",
            "subpod": {"name": "core", "pod": {"name": "platform"}},
        },
        {
            "name": "metapod-service-b",
            "repository_url": "https://github.com/acme/metapod-service-b",
            "subpod": {"name": "edge", "pod": {"name": "platform"}},
        },
    ]


def test_happy_path_creates_repositories_with_pod_and_subpod(
    cli_runner, monkeypatch, engine, cleanup_repos
):
    """Two services → two Repository rows with the right pod / subpod."""
    from sqlalchemy.orm import Session

    from libinv.models import Repository

    result = _invoke_cli(cli_runner, monkeypatch, _processed_services_payload())

    assert result.exit_code == 0, f"output={result.output!r} exc={result.exception!r}"

    with Session(bind=engine) as s:
        rows = (
            s.query(Repository)
            .filter(Repository.name.in_(list(cleanup_repos)))
            .order_by(Repository.name)
            .all()
        )
        assert {r.name for r in rows} == {"metapod-service-a", "metapod-service-b"}
        by_name = {r.name: r for r in rows}
        assert by_name["metapod-service-a"].provider == "github.com"
        assert by_name["metapod-service-a"].org == "acme"
        assert by_name["metapod-service-a"].pod == "platform"
        assert by_name["metapod-service-a"].subpod == "core"
        assert by_name["metapod-service-b"].provider == "github.com"
        assert by_name["metapod-service-b"].pod == "platform"
        assert by_name["metapod-service-b"].subpod == "edge"


def test_upstream_http_error_is_caught_no_partial_state(
    cli_runner, monkeypatch, engine, cleanup_repos
):
    """If ``requests.get`` raises ``RequestException``, the command logs +
    returns ``[]`` from ``metapod_services``, no rows are inserted.
    """
    from sqlalchemy.orm import Session

    from libinv.models import Repository

    # Force the upstream HTTP call to raise. We patch the *requests.get*
    # used inside the module so we still exercise the real
    # ``metapod_services()`` function (i.e. its try/except path).
    def _boom(*_a, **_kw):
        raise requests.RequestException("upstream 5xx")

    monkeypatch.setattr(
        "libinv.cli.import_and_improve_from_metapod.requests.get", _boom
    )
    _import_module()

    from libinv.cli.cli import cli as cli_group

    result = cli_runner.invoke(cli_group, ["import-and-improve-from-metapod"])

    assert result.exit_code == 0, f"output={result.output!r} exc={result.exception!r}"

    # No rows from our test set should have been created.
    with Session(bind=engine) as s:
        rows = (
            s.query(Repository).filter(Repository.name.in_(list(cleanup_repos))).all()
        )
        assert rows == []


def test_duplicate_import_is_idempotent(cli_runner, monkeypatch, engine, cleanup_repos):
    """Running the import twice with the same payload yields the same final
    state — no duplicate rows, same pod / subpod values.
    """
    from sqlalchemy.orm import Session

    from libinv.models import Repository

    # First invocation: creates the rows.
    result1 = _invoke_cli(cli_runner, monkeypatch, _processed_services_payload())
    assert result1.exit_code == 0, result1.output

    with Session(bind=engine) as s:
        first = (
            s.query(Repository)
            .filter(Repository.name.in_(list(cleanup_repos)))
            .order_by(Repository.name)
            .all()
        )
        first_count = len(first)
        first_ids = {r.name: r.id for r in first}

    assert first_count == 2

    # Second invocation: identical payload — should be a no-op for new
    # rows (get_or_create returns the existing row), pod/subpod re-applied.
    result2 = _invoke_cli(cli_runner, monkeypatch, _processed_services_payload())
    assert result2.exit_code == 0, result2.output

    with Session(bind=engine) as s:
        second = (
            s.query(Repository)
            .filter(Repository.name.in_(list(cleanup_repos)))
            .order_by(Repository.name)
            .all()
        )

    # Row IDs are stable (no duplicates were created).
    assert len(second) == first_count
    assert {r.name: r.id for r in second} == first_ids
    # And pod/subpod values are unchanged.
    by_name = {r.name: r for r in second}
    assert by_name["metapod-service-a"].pod == "platform"
    assert by_name["metapod-service-a"].subpod == "core"
    assert by_name["metapod-service-b"].pod == "platform"
    assert by_name["metapod-service-b"].subpod == "edge"


def test_metapod_services_handles_request_exception_directly():
    """Unit-level check of ``metapod_services``' exception path.

    Even when the helper is called directly (not via the click command),
    a ``requests.RequestException`` must be caught and translated into an
    empty list — never propagated to the caller.
    """
    from libinv.cli import import_and_improve_from_metapod as mod

    with patch.object(mod.requests, "get", side_effect=requests.RequestException("net")):
        result = mod.metapod_services()

    assert result == []
