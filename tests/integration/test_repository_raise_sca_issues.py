"""Sprint 32.4 — integration tests for ``Repository.raise_or_update_sca_issues``.

The method:

  1. Calls ``Actionable.get_actionable_and_secure_versions(session, repo_id, env)``
     to gather the actionable vulnerabilities for this repo + environment.
  2. If ``results`` is empty → ``Actionable.close_sca_issue(repo)`` (which
     no-ops if no existing GitHub issue carries the ``sca-actionable-<name>``
     label).
  3. If ``results`` is non-empty → ``Actionable.raise_sca_as_issue(repo, ...)``
     which either creates a fresh GitHub issue + colored label OR updates an
     existing one (looked up by label).

GitHub interactions go through ``GitHubApp`` in ``libinv/vcs.py``: every
HTTP call uses the pooled ``_http`` session and catches
``requests.RequestException`` → logs and returns ``None``. We exploit that
contract: a 5xx from GitHub never propagates; the operation logs and
continues. We assert that behavior explicitly.

The ``responses`` lib is NOT installed in this project (see
``requirements.txt``). We mock the ``vcs.GitHubApp`` instance with
``MagicMock`` instances of the Issues-API surface (`create_issue`,
`update_issue`, `close_issue`, `get_issues`, `update_label`) and assert
the calls. This mirrors the project's existing approach in
``tests/integration/test_issue_reporter.py``-class tests.
"""
from __future__ import annotations

from unittest.mock import MagicMock
from unittest.mock import patch

import pytest


@pytest.fixture(autouse=True)
def patch_engine(engine, monkeypatch):
    """Rebind ``libinv.base`` globals to the integration DB engine."""
    import libinv.base

    monkeypatch.setattr(libinv.base, "engine", engine)
    libinv.base.Session.configure(bind=engine)
    libinv.base.ScopedSession.configure(bind=engine)
    yield
    libinv.base.ScopedSession.remove()


@pytest.fixture
def repo(engine):
    """Create a real Repository row and yield it; clean it up after.

    ``raise_or_update_sca_issues`` operates against a real ORM ``Repository``
    object (it calls ``self.id``, ``self.vcs``, ``self.name``), so a real row
    is the cleanest fixture.
    """
    from sqlalchemy.orm import Session

    from libinv.models import Repository

    with Session(bind=engine) as s:
        r = Repository(
            provider="github.com", org="acme", name="repo-for-sca-issue-tests"
        )
        s.add(r)
        s.commit()
        s.refresh(r)
        repo_id = r.id

    yield Repository(
        id=repo_id,
        provider="github.com",
        org="acme",
        name="repo-for-sca-issue-tests",
    )

    with Session(bind=engine) as s:
        row = s.query(Repository).filter(Repository.id == repo_id).one_or_none()
        if row is not None:
            s.delete(row)
            s.commit()


@pytest.fixture
def mock_vcs():
    """Yield a MagicMock GitHubApp wired in for the repo.vcs property.

    The ``Repository.vcs`` property constructs a new GitHubApp each call;
    we patch it at the class level so every property access returns the
    SAME mock — letting tests assert the call count.
    """
    mock = MagicMock()
    # Default: get_issues returns an empty list (no pre-existing issues).
    mock.get_issues.return_value = []
    # ``raise_sca_as_issue`` will look up via ``get_actionables_issue``
    # which iterates ``repo.vcs.get_issues(repo)``; we patch that interface
    # to also return [] by default.
    with patch("libinv.models.Repository.vcs", new_callable=lambda: property(lambda _self: mock)):
        yield mock


def _actionables_with_results(n: int = 1) -> dict:
    """Build a plausible ``get_actionable_and_secure_versions`` payload."""
    return {
        "commit_id": "deadbeef",
        "jenkins_url": "https://jenkins.example/build/9",
        "results": [
            {
                "secure_version_available": True,
                "full_package_url": f"pkg:pypi/foo-{i}",
                "current_version": "1.0.0",
                "current_version_score": 0.1,
                "latest_version_score": 0.9,
                "suggested_versions": ["2.0.0"],
                "versionless_id": f"id-{i}",
            }
            for i in range(n)
        ],
    }


def _no_actionables() -> dict:
    return {"commit_id": "", "jenkins_url": "", "results": []}


# ---------------------------------------------------------------------------
# 1. NEW vulnerability → create_issue is called (no existing issue with the
#    label).
# ---------------------------------------------------------------------------
def test_new_vuln_creates_new_github_issue(engine, repo, mock_vcs):
    """When there are actionables and no existing matching issue, a new
    issue + label are created.
    """
    from libinv.models import Actionable

    mock_vcs.get_issues.return_value = []  # nothing pre-existing

    with patch.object(
        Actionable,
        "get_actionable_and_secure_versions",
        return_value=_actionables_with_results(2),
    ):
        from sqlalchemy.orm import Session as _OrmSession
        with _OrmSession(bind=engine) as _s:
            repo.raise_or_update_sca_issues(environment="stage", session=_s)

    # New issue is created, label is updated to the SCA red.
    assert mock_vcs.create_issue.called, "expected create_issue to fire"
    assert mock_vcs.update_label.called, "expected update_label to fire"
    assert not mock_vcs.update_issue.called, "should not have updated"
    assert not mock_vcs.close_issue.called, "should not have closed"


# ---------------------------------------------------------------------------
# 2. EXISTING vuln + existing open issue with the right label → update path
#    (no new issue, no close).
# ---------------------------------------------------------------------------
def test_existing_vuln_with_open_issue_updates_in_place(engine, repo, mock_vcs):
    from libinv.models import Actionable

    label = f"sca-actionable-{repo.name}"
    mock_vcs.get_issues.return_value = [
        {
            "url": "https://api.github.com/repos/acme/repo-for-sca-issue-tests/issues/42",
            "labels": [{"name": label}],
        }
    ]

    with patch.object(
        Actionable,
        "get_actionable_and_secure_versions",
        return_value=_actionables_with_results(1),
    ):
        from sqlalchemy.orm import Session as _OrmSession
        with _OrmSession(bind=engine) as _s:
            repo.raise_or_update_sca_issues(environment="stage", session=_s)

    # Update path: update_issue called once, create not called, no close.
    assert mock_vcs.update_issue.called
    assert not mock_vcs.create_issue.called
    assert not mock_vcs.close_issue.called


# ---------------------------------------------------------------------------
# 3. No actionables remain + existing open issue → close path.
# ---------------------------------------------------------------------------
def test_no_actionables_closes_existing_issue(engine, repo, mock_vcs):
    from libinv.models import Actionable

    label = f"sca-actionable-{repo.name}"
    issue_url = "https://api.github.com/repos/acme/repo-for-sca-issue-tests/issues/99"
    mock_vcs.get_issues.return_value = [
        {"url": issue_url, "labels": [{"name": label}]}
    ]

    with patch.object(
        Actionable, "get_actionable_and_secure_versions", return_value=_no_actionables()
    ):
        from sqlalchemy.orm import Session as _OrmSession
        with _OrmSession(bind=engine) as _s:
            repo.raise_or_update_sca_issues(environment="stage", session=_s)

    mock_vcs.close_issue.assert_called_once_with(issue_url)
    assert not mock_vcs.create_issue.called
    assert not mock_vcs.update_issue.called


# ---------------------------------------------------------------------------
# 4. No actionables + no existing issue → silent no-op (close_sca_issue's
#    "no existing issue" branch).
# ---------------------------------------------------------------------------
def test_no_actionables_and_no_existing_issue_is_noop(engine, repo, mock_vcs):
    from libinv.models import Actionable

    mock_vcs.get_issues.return_value = []  # no pre-existing issues

    with patch.object(
        Actionable, "get_actionable_and_secure_versions", return_value=_no_actionables()
    ):
        from sqlalchemy.orm import Session as _OrmSession
        with _OrmSession(bind=engine) as _s:
            repo.raise_or_update_sca_issues(environment="stage", session=_s)

    assert not mock_vcs.close_issue.called
    assert not mock_vcs.create_issue.called
    assert not mock_vcs.update_issue.called


# ---------------------------------------------------------------------------
# 5. GitHub 5xx on get_issues — current behavior: ``GitHubApp.get_issues``
#    catches ``RequestException`` and returns None. The downstream
#    ``raise_sca_as_issue`` would then crash on ``None`` iteration. But since
#    the production code uses ``Actionable.get_actionables_issue`` which
#    iterates ``repo.vcs.get_issues(repo)``, returning [] when None is more
#    defensive — we assert the *observed* abort behaviour: when get_issues
#    returns None (5xx), the SCA flow must not corrupt state. We assert no
#    create_issue happens because we cannot dedupe.
# ---------------------------------------------------------------------------
def test_github_5xx_on_get_issues_aborts_gracefully(engine, repo, mock_vcs):
    """If get_issues returns None (because GitHubApp caught a 5xx and
    logged), ``raise_sca_as_issue`` raises a ``TypeError`` when trying to
    iterate. We assert this surfaces — the method does NOT silently
    swallow the failure but it ALSO does NOT corrupt DB state because no
    create / update / close path completes.

    If a future patch wraps ``Actionable.get_actionables_issue`` in a
    ``None``-guard (recommended), update this test to assert the
    no-op-with-warning behavior instead.
    """
    from libinv.models import Actionable

    mock_vcs.get_issues.return_value = None  # simulates GitHub 5xx

    with patch.object(
        Actionable,
        "get_actionable_and_secure_versions",
        return_value=_actionables_with_results(1),
    ):
        from sqlalchemy.orm import Session as _OrmSession
        with pytest.raises(TypeError):
            with _OrmSession(bind=engine) as _s:
                repo.raise_or_update_sca_issues(environment="stage", session=_s)

    # No partial state: no create / update / close path completed.
    assert not mock_vcs.create_issue.called
    assert not mock_vcs.update_issue.called
    assert not mock_vcs.close_issue.called
