"""Sprint 43.1 — unit tests for ``run_all_actionable_cves``.

These tests exercise the workflow function directly with mocked deps
(no Click runner, no real DB). They pin behavior preserved during the
extraction from ``libinv.cli.epss``:

- The ``all_actionable_cves`` branch queries
  ``ActionablePackageAvailableVersion.scancode_project_uuid``, dedupes,
  collects CVEs via ``_collect_cves_for_projects``, and hands off to
  ``EPSS.refresh_cves``.
- The early-exit paths (no project UUIDs, no CVEs collected, no CVE
  list provided, no valid CVEs after filtering) all return without
  invoking ``EPSS.refresh_cves``.
- The non-``all_actionable_cves`` branch merges ``cve``/``cves``/``file``
  inputs and filters out non-``CVE-*`` entries.
"""

from __future__ import annotations

import logging
from unittest.mock import MagicMock
from unittest.mock import patch

import pytest


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def patched_session():
    """Patch ``libinv.services.epss.all_actionable_cves.Session`` to
    return a MagicMock that supports the ``with Session() as s`` idiom."""
    fake_session = MagicMock()
    cm = MagicMock()
    cm.__enter__.return_value = fake_session
    cm.__exit__.return_value = False
    with patch(
        "libinv.services.epss.all_actionable_cves.Session",
        return_value=cm,
    ):
        yield fake_session


# ---------------------------------------------------------------------------
# all_actionable_cves branch
# ---------------------------------------------------------------------------


def test_all_actionable_cves_no_project_uuids_short_circuits(patched_session):
    """If no scancode_project_uuid rows exist, the function returns
    without hitting ``_collect_cves_for_projects`` or ``EPSS.refresh_cves``."""
    # session.query(...).filter(...).distinct().all() -> []
    chain = patched_session.query.return_value.filter.return_value.distinct
    chain.return_value.all.return_value = []

    with (
        patch(
            "libinv.cli.epss._collect_cves_for_projects",
        ) as fake_collect,
        patch(
            "libinv.services.epss.all_actionable_cves.EPSS",
        ) as fake_epss,
    ):
        from libinv.services.epss.all_actionable_cves import run_all_actionable_cves

        run_all_actionable_cves(
            cve=None,
            cves=None,
            file=None,
            verbose=False,
            all_actionable_cves=True,
        )

    fake_collect.assert_not_called()
    fake_epss.refresh_cves.assert_not_called()


def test_all_actionable_cves_no_cves_collected_short_circuits(patched_session):
    """If the project UUIDs exist but no CVEs surface, we exit without
    calling ``refresh_cves``."""
    chain = patched_session.query.return_value.filter.return_value.distinct
    chain.return_value.all.return_value = [("uuid-1",), ("uuid-2",)]

    with (
        patch(
            "libinv.cli.epss._collect_cves_for_projects",
            return_value=set(),
        ) as fake_collect,
        patch(
            "libinv.services.epss.all_actionable_cves.EPSS",
        ) as fake_epss,
    ):
        from libinv.services.epss.all_actionable_cves import run_all_actionable_cves

        run_all_actionable_cves(
            cve=None,
            cves=None,
            file=None,
            verbose=False,
            all_actionable_cves=True,
        )

    fake_collect.assert_called_once()
    fake_epss.refresh_cves.assert_not_called()


def test_all_actionable_cves_happy_path_invokes_refresh_cves(patched_session):
    """Project UUIDs exist + CVEs collected => ``EPSS.refresh_cves`` is
    called with the deduped valid CVE list."""
    chain = patched_session.query.return_value.filter.return_value.distinct
    chain.return_value.all.return_value = [("uuid-1",), ("uuid-2",), (None,)]

    with (
        patch(
            "libinv.cli.epss._collect_cves_for_projects",
            return_value={"CVE-2024-0001", "CVE-2024-0002"},
        ) as fake_collect,
        patch(
            "libinv.services.epss.all_actionable_cves.EPSS",
        ) as fake_epss,
    ):
        fake_epss.refresh_cves.return_value = {
            "updated": 2,
            "skipped": 0,
            "failed": 0,
        }
        from libinv.services.epss.all_actionable_cves import run_all_actionable_cves

        run_all_actionable_cves(
            cve=None,
            cves=None,
            file=None,
            verbose=False,
            all_actionable_cves=True,
        )

    # _collect_cves_for_projects gets the deduped non-null UUIDs
    args, kwargs = fake_collect.call_args
    assert set(kwargs["project_uuids"]) == {"uuid-1", "uuid-2"}
    # refresh_cves runs with the collected CVEs (both are valid CVE-* format)
    args, kwargs = fake_epss.refresh_cves.call_args
    valid_cves = args[1]
    assert set(valid_cves) == {"CVE-2024-0001", "CVE-2024-0002"}


# ---------------------------------------------------------------------------
# Non-all_actionable_cves branch
# ---------------------------------------------------------------------------


def test_explicit_cve_list_filters_invalid_and_calls_refresh_cves():
    """Inputs from ``--cve``/``--cves`` merge, dedupe, then drop non-CVE
    entries before ``refresh_cves``."""
    fake_session = MagicMock()
    cm = MagicMock()
    cm.__enter__.return_value = fake_session
    cm.__exit__.return_value = False

    with (
        patch(
            "libinv.services.epss.all_actionable_cves.Session",
            return_value=cm,
        ),
        patch(
            "libinv.services.epss.all_actionable_cves.EPSS",
        ) as fake_epss,
    ):
        fake_epss.refresh_cves.return_value = {
            "updated": 1,
            "skipped": 1,
            "failed": 0,
        }
        from libinv.services.epss.all_actionable_cves import run_all_actionable_cves

        run_all_actionable_cves(
            cve="CVE-2024-1111",
            cves="CVE-2024-2222, GHSA-xxxx, CVE-2024-1111",
            file=None,
            verbose=False,
            all_actionable_cves=False,
        )

    args, kwargs = fake_epss.refresh_cves.call_args
    valid_cves = args[1]
    assert set(valid_cves) == {"CVE-2024-1111", "CVE-2024-2222"}


def test_no_input_short_circuits_without_refresh_cves():
    """When all inputs are empty/None, the function exits before
    opening a session or calling ``refresh_cves``."""
    with (
        patch(
            "libinv.services.epss.all_actionable_cves.Session",
        ) as fake_session_factory,
        patch(
            "libinv.services.epss.all_actionable_cves.EPSS",
        ) as fake_epss,
    ):
        from libinv.services.epss.all_actionable_cves import run_all_actionable_cves

        run_all_actionable_cves(
            cve=None,
            cves=None,
            file=None,
            verbose=False,
            all_actionable_cves=False,
        )

    # Session() should NOT be opened at all on this path
    fake_session_factory.assert_not_called()
    fake_epss.refresh_cves.assert_not_called()


def test_no_valid_cves_short_circuits_without_refresh_cves():
    """If all provided CVEs fail the ``CVE-*`` filter, we exit before
    opening a session."""
    with (
        patch(
            "libinv.services.epss.all_actionable_cves.Session",
        ) as fake_session_factory,
        patch(
            "libinv.services.epss.all_actionable_cves.EPSS",
        ) as fake_epss,
    ):
        from libinv.services.epss.all_actionable_cves import run_all_actionable_cves

        run_all_actionable_cves(
            cve="GHSA-xxxx",
            cves="not-a-cve",
            file=None,
            verbose=False,
            all_actionable_cves=False,
        )

    fake_session_factory.assert_not_called()
    fake_epss.refresh_cves.assert_not_called()


def test_verbose_flag_sets_root_logger_to_debug(monkeypatch):
    """``verbose=True`` should escalate root logger to DEBUG."""
    # Snapshot + restore so we don't leak global state.
    original_level = logging.getLogger().level
    monkeypatch.setattr(logging.getLogger(), "level", original_level)

    with (
        patch(
            "libinv.services.epss.all_actionable_cves.Session",
        ),
        patch(
            "libinv.services.epss.all_actionable_cves.EPSS",
        ),
    ):
        from libinv.services.epss.all_actionable_cves import run_all_actionable_cves

        run_all_actionable_cves(
            cve=None,
            cves=None,
            file=None,
            verbose=True,
            all_actionable_cves=False,
        )

    assert logging.getLogger().level == logging.DEBUG
    # Restore so subsequent tests in the suite aren't impacted.
    logging.getLogger().setLevel(original_level)
