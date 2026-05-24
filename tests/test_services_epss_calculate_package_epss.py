"""Sprint 43.2 — unit tests for ``run_calculate_package_epss``.

These tests exercise the workflow function directly with mocked deps
(no Click runner, no real DB). They pin behavior preserved during the
extraction from ``libinv.cli.epss``:

- Empty package set => return early, no commits.
- A package with no CVEs is skipped (no ``epss_score`` write).
- A package with CVEs that have no EPSS records is skipped.
- A package with CVEs + matching EPSS records is updated with the max
  ``epss_score`` and ``session.add`` is called.
- Per-package exceptions are caught and counted; the loop continues.
- ``session.commit`` is called once per batch.
"""

from __future__ import annotations

import logging
from unittest.mock import MagicMock
from unittest.mock import patch

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _patched_session_context(fake_session):
    """Wrap ``fake_session`` so ``with Session() as s`` returns it."""
    cm = MagicMock()
    cm.__enter__.return_value = fake_session
    cm.__exit__.return_value = False
    return cm


def _build_package_query_chain(fake_session, packages):
    """Configure ``session.query(...).filter(...).filter(...).all()`` to
    return ``packages`` exactly once (the first query in the workflow)."""
    fake_session.query.return_value.filter.return_value.filter.return_value.all.return_value = (
        packages
    )


# ---------------------------------------------------------------------------
# Empty / short-circuit paths
# ---------------------------------------------------------------------------


def test_no_packages_returns_early_without_commit():
    """If the initial query returns [], we return before iterating."""
    fake_session = MagicMock()
    _build_package_query_chain(fake_session, [])
    cm = _patched_session_context(fake_session)

    with patch(
        "libinv.services.epss.calculate_package_epss.Session",
        return_value=cm,
    ):
        from libinv.services.epss.calculate_package_epss import (
            run_calculate_package_epss,
        )

        run_calculate_package_epss(verbose=False, batch_size=100)

    fake_session.commit.assert_not_called()
    fake_session.add.assert_not_called()


# ---------------------------------------------------------------------------
# Per-package paths
# ---------------------------------------------------------------------------


def _make_package(uuid: str, purl: str, version: str):
    pkg = MagicMock()
    pkg.uuid = uuid
    pkg.package_url = purl
    pkg.version = version
    pkg.scancode_project_uuid = f"proj-{uuid}"
    return pkg


def test_package_with_no_cves_is_skipped_not_updated():
    """A package whose ``get_cves`` returns an empty set is counted as
    skipped — no ``session.add`` call, no ``epss_score`` mutation."""
    pkg = _make_package("u1", "pkg:pypi/foo", "1.0")
    pkg.get_cves.return_value = set()

    fake_session = MagicMock()
    _build_package_query_chain(fake_session, [pkg])
    # DiscoveredPackage query (unused but called for side effect):
    # Use a separate chain — but reusing the same `query` mock is fine here.
    cm = _patched_session_context(fake_session)

    with patch(
        "libinv.services.epss.calculate_package_epss.Session",
        return_value=cm,
    ):
        from libinv.services.epss.calculate_package_epss import (
            run_calculate_package_epss,
        )

        run_calculate_package_epss(verbose=False, batch_size=100)

    fake_session.add.assert_not_called()
    # One commit per batch (1 batch).
    assert fake_session.commit.call_count == 1


def test_package_with_cves_but_no_epss_records_is_skipped():
    """When ``get_cves`` returns CVEs but ``EPSS`` table has no matching
    rows, the package is skipped (no ``epss_score`` write)."""
    pkg = _make_package("u2", "pkg:pypi/bar", "2.0")
    pkg.get_cves.return_value = {"CVE-2024-0001"}

    fake_session = MagicMock()
    _build_package_query_chain(fake_session, [pkg])
    # The EPSS query (`session.query(EPSS).filter(...).all()`) returns []:
    # That chain is `query(EPSS).filter(...).all()` — a single .filter()
    # depth, distinct from the package query chain above. We override the
    # default MagicMock chain attr for ``filter().all()`` to return [].
    fake_session.query.return_value.filter.return_value.all.return_value = []
    # Restore the package-list chain (.filter().filter().all() takes
    # precedence on the configured Mock spec since we set it explicitly).
    _build_package_query_chain(fake_session, [pkg])
    cm = _patched_session_context(fake_session)

    with patch(
        "libinv.services.epss.calculate_package_epss.Session",
        return_value=cm,
    ):
        from libinv.services.epss.calculate_package_epss import (
            run_calculate_package_epss,
        )

        run_calculate_package_epss(verbose=False, batch_size=100)

    fake_session.add.assert_not_called()
    assert fake_session.commit.call_count == 1


def test_package_with_cves_and_epss_records_updates_max_score():
    """The happy path: ``epss_score`` is set to the max of the
    EPSS-record scores, and ``session.add(package)`` is called."""
    pkg = _make_package("u3", "pkg:pypi/baz", "3.0")
    pkg.get_cves.return_value = {"CVE-2024-0001", "CVE-2024-0002"}

    epss_records = [
        MagicMock(epss_score=0.10),
        MagicMock(epss_score=0.87),
        MagicMock(epss_score=0.42),
    ]

    fake_session = MagicMock()
    _build_package_query_chain(fake_session, [pkg])
    # `.filter().all()` (used by the EPSS query) returns our records.
    fake_session.query.return_value.filter.return_value.all.return_value = epss_records
    # Re-apply the package chain so it isn't clobbered.
    _build_package_query_chain(fake_session, [pkg])
    cm = _patched_session_context(fake_session)

    with patch(
        "libinv.services.epss.calculate_package_epss.Session",
        return_value=cm,
    ):
        from libinv.services.epss.calculate_package_epss import (
            run_calculate_package_epss,
        )

        run_calculate_package_epss(verbose=False, batch_size=100)

    # The package's epss_score was set to the max (0.87)
    assert pkg.epss_score == 0.87
    fake_session.add.assert_called_once_with(pkg)
    assert fake_session.commit.call_count == 1


def test_per_package_exception_is_caught_and_does_not_abort_run():
    """A package whose ``get_cves`` raises should be counted failed but
    not crash the run; the surrounding batch still commits."""
    bad_pkg = _make_package("u-bad", "pkg:pypi/bad", "0.0")
    bad_pkg.get_cves.side_effect = RuntimeError("kaboom")

    good_pkg = _make_package("u-good", "pkg:pypi/good", "1.0")
    good_pkg.get_cves.return_value = set()  # skipped, not failed

    fake_session = MagicMock()
    _build_package_query_chain(fake_session, [bad_pkg, good_pkg])
    cm = _patched_session_context(fake_session)

    with patch(
        "libinv.services.epss.calculate_package_epss.Session",
        return_value=cm,
    ):
        from libinv.services.epss.calculate_package_epss import (
            run_calculate_package_epss,
        )

        # Should not raise.
        run_calculate_package_epss(verbose=False, batch_size=100)

    fake_session.add.assert_not_called()
    # Still commits the (no-op) batch.
    assert fake_session.commit.call_count == 1


# ---------------------------------------------------------------------------
# Batching
# ---------------------------------------------------------------------------


def test_batch_size_drives_commit_count():
    """With ``batch_size=2`` and 5 packages, we expect ``ceil(5/2)=3``
    commits."""
    packages = [
        _make_package(f"u{i}", f"pkg:pypi/p{i}", "1.0") for i in range(5)
    ]
    for p in packages:
        p.get_cves.return_value = set()

    fake_session = MagicMock()
    _build_package_query_chain(fake_session, packages)
    cm = _patched_session_context(fake_session)

    with patch(
        "libinv.services.epss.calculate_package_epss.Session",
        return_value=cm,
    ):
        from libinv.services.epss.calculate_package_epss import (
            run_calculate_package_epss,
        )

        run_calculate_package_epss(verbose=False, batch_size=2)

    # ceil(5/2) == 3 batches → 3 commits
    assert fake_session.commit.call_count == 3


# ---------------------------------------------------------------------------
# Verbose flag
# ---------------------------------------------------------------------------


def test_verbose_flag_sets_root_logger_to_debug(monkeypatch):
    """``verbose=True`` escalates the root logger to DEBUG."""
    original_level = logging.getLogger().level

    fake_session = MagicMock()
    _build_package_query_chain(fake_session, [])
    cm = _patched_session_context(fake_session)

    with patch(
        "libinv.services.epss.calculate_package_epss.Session",
        return_value=cm,
    ):
        from libinv.services.epss.calculate_package_epss import (
            run_calculate_package_epss,
        )

        run_calculate_package_epss(verbose=True, batch_size=100)

    assert logging.getLogger().level == logging.DEBUG
    logging.getLogger().setLevel(original_level)
