"""Integration test for the Sprint-2 fix to `Actionable.mark_latest_version`.

Background:
  The original code wrapped the body in `with Session() as session:` which
  does NOT commit on exit, so all `version.is_latest = ...` mutations were
  silently dropped. Sprint 2 switched the implementation to `session_scope()`
  (which commits on clean exit).

This test verifies the fix actually took: after `mark_latest_version()` the
highest-semver row must have `is_latest=True` (and the rest `False`) as seen
by a fresh, independent session.
"""
import uuid

import pytest


@pytest.fixture(autouse=True)
def patch_engine(engine, monkeypatch):
    """Rebind libinv.base globals to the integration DB engine.

    Necessary because `Actionable.mark_latest_version` uses the production
    `session_scope()`, which goes through the module-level ScopedSession.
    """
    import libinv.base

    monkeypatch.setattr(libinv.base, "engine", engine)
    libinv.base.Session.configure(bind=engine)
    libinv.base.ScopedSession.configure(bind=engine)
    yield
    libinv.base.ScopedSession.remove()


@pytest.fixture
def cleanup_actionable(engine):
    """Drop the test Actionable + its children after the test."""
    package_url = f"pkg:pypi/test-{uuid.uuid4().hex[:8]}"
    yield package_url

    from sqlalchemy.orm import Session

    from libinv.models import Actionable

    with Session(bind=engine) as s:
        actionable = (
            s.query(Actionable).filter(Actionable.package_url == package_url).one_or_none()
        )
        if actionable is not None:
            # cascade="all, delete-orphan" on Actionable.available_versions
            # takes care of the version rows too.
            s.delete(actionable)
            s.commit()


def test_mark_latest_version_persists_writes(engine, cleanup_actionable):
    """Create Actionable + 3 versions; call mark_latest_version; verify persistence."""
    from sqlalchemy.orm import Session

    from libinv.models import Actionable
    from libinv.models import ActionablePackageAvailableVersion

    package_url = cleanup_actionable

    # 1. Seed: one Actionable + three versions (1.0.0, 2.0.0, 3.0.0). All
    #    is_latest=False initially. Commit via a fresh session (NOT through
    #    session_scope, so we don't entangle the assertion with the scope
    #    being tested).
    with Session(bind=engine) as setup_s:
        actionable = Actionable(package_url=package_url)
        setup_s.add(actionable)
        setup_s.flush()  # ensure actionable.uuid is populated

        for v in ("1.0.0", "2.0.0", "3.0.0"):
            setup_s.add(
                ActionablePackageAvailableVersion(
                    package_url=package_url,
                    version=v,
                    is_latest=False,
                    scan_status="ADDED",
                    actionable_id=actionable.uuid,
                )
            )
        setup_s.commit()
        actionable_uuid = actionable.uuid

    # 2. Call the method under test. With the Sprint-2 fix it commits via
    #    session_scope(). With the pre-fix code, the mutations would be
    #    silently dropped.
    with Session(bind=engine) as call_s:
        actionable_for_call = (
            call_s.query(Actionable).filter(Actionable.uuid == actionable_uuid).one()
        )
        # Detach so the method opens its own scope without conflict.
        call_s.expunge(actionable_for_call)
    actionable_for_call.mark_latest_version()

    # 3. Read with a fresh session and verify the latest-flag layout.
    with Session(bind=engine) as verify_s:
        rows = (
            verify_s.query(ActionablePackageAvailableVersion)
            .filter(ActionablePackageAvailableVersion.actionable_id == actionable_uuid)
            .all()
        )
        by_version = {r.version: r for r in rows}

        assert set(by_version.keys()) == {"1.0.0", "2.0.0", "3.0.0"}, (
            f"unexpected version set: {set(by_version)}"
        )

        # Loud failure message if Sprint-2 fix regressed.
        assert by_version["3.0.0"].is_latest is True, (
            "mark_latest_version() did not persist is_latest=True on '3.0.0'. "
            "This indicates the Sprint-2 fix to switch from `with Session() as s` "
            "to `session_scope()` did NOT take effect — writes are being dropped."
        )
        assert by_version["1.0.0"].is_latest is False
        assert by_version["2.0.0"].is_latest is False
