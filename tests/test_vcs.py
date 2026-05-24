"""Unit tests for libinv.vcs (Sprint 0-1 hardening).

These tests are DB-free and avoid any real network calls or filesystem
writes outside of `tmp_path`. They verify the Sprint 0-1 fixes:

* `write_token_to_netrc` writes atomically with mode 0600.
* `create_issue` / `update_issue` use a 10-second timeout and call
  `raise_for_status()` on the response.
* The mutable default `labels=[]` was replaced with `labels=None` and
  defaults to a fresh list internally (no accumulation across calls).
* `get_sca_issue` scans every label of every issue (Sprint 1 fixed an
  early-return bug that caused valid issues to be missed when an earlier
  label didn't match).
* Exception handling catches `requests.RequestException` rather than
  `git.exc.GitError` (Sprint 1 fixed an unreachable except).
"""

import os
import stat
from unittest.mock import MagicMock, patch

import pytest
import requests


@pytest.fixture
def github_app(tmp_path, monkeypatch):
    """Build a `GitHubApp` instance without running its real `__init__`.

    The real `__init__` opens `GITHUB_APP_PRIVATE_KEY_FILE` from env, which
    points at a non-existent file in the test environment. We bypass it
    with `__new__` and set the attributes the methods under test need.
    """
    from libinv.vcs import GitHubApp

    app = GitHubApp.__new__(GitHubApp)
    app.api_url = "https://api.github.com"
    app.headers = {"Authorization": "token fake-token"}
    app.token = "fake-token"
    app.machine = "github.com"
    app.login = "x-access-token"
    app.NETRC_FILE = str(tmp_path / ".netrc")
    return app


# ---------------------------------------------------------------------------
# write_token_to_netrc
# ---------------------------------------------------------------------------
def test_write_token_to_netrc_writes_mode_0600(github_app):
    """The netrc file must be created with permission bits exactly 0o600."""
    github_app.write_token_to_netrc("super-secret-token")

    assert os.path.exists(github_app.NETRC_FILE)
    mode_bits = stat.S_IMODE(os.stat(github_app.NETRC_FILE).st_mode)
    assert mode_bits == 0o600, f"expected 0o600, got {oct(mode_bits)}"


def test_write_token_to_netrc_content(github_app):
    """Sanity check: file content matches the netrc format."""
    github_app.write_token_to_netrc("super-secret-token")
    with open(github_app.NETRC_FILE) as f:
        content = f.read()
    assert "machine github.com" in content
    assert "login x-access-token" in content
    assert "password super-secret-token" in content


def test_write_token_to_netrc_overwrites_atomically(github_app):
    """Re-invoking should truncate, not append."""
    github_app.write_token_to_netrc("token-one")
    github_app.write_token_to_netrc("token-two")
    with open(github_app.NETRC_FILE) as f:
        content = f.read()
    assert "token-one" not in content
    assert "token-two" in content
    # Mode bits still 0o600 after rewrite.
    mode_bits = stat.S_IMODE(os.stat(github_app.NETRC_FILE).st_mode)
    assert mode_bits == 0o600


# ---------------------------------------------------------------------------
# create_issue
# ---------------------------------------------------------------------------
def _make_repo_mock(org="myorg", name="myrepo"):
    repo = MagicMock()
    repo.org = org
    repo.name = name
    return repo


@patch("libinv.vcs.requests.post")
def test_create_issue_passes_timeout_and_calls_raise_for_status(mock_post, github_app):
    mock_response = MagicMock()
    mock_post.return_value = mock_response

    github_app.create_issue(_make_repo_mock(), "title", "body")

    assert mock_post.called, "requests.post was not called"
    _, kwargs = mock_post.call_args
    assert kwargs.get("timeout") == 10, "Sprint 0 timeout=10 is missing"
    mock_response.raise_for_status.assert_called_once()


@patch("libinv.vcs.requests.post")
def test_create_issue_labels_default_is_empty_list_not_shared(mock_post, github_app):
    """Mutable default `labels=[]` accumulation regression.

    Sprint 1 changed the signature to `labels=None`. If the old bug were
    back, calling create_issue twice without a `labels=` argument and
    appending in the function body would leak state across calls. We check
    the captured JSON body for each call independently has `labels == []`.
    """
    mock_post.return_value = MagicMock()

    github_app.create_issue(_make_repo_mock(), "t1", "b1")
    github_app.create_issue(_make_repo_mock(), "t2", "b2")

    assert mock_post.call_count == 2
    for call in mock_post.call_args_list:
        _, kwargs = call
        json_body = kwargs.get("json", {})
        assert json_body.get("labels") == [], (
            f"labels should default to a fresh []; got {json_body.get('labels')!r}"
        )


@patch("libinv.vcs.requests.post")
def test_create_issue_labels_none_resolves_to_empty_list(mock_post, github_app):
    """Calling with explicit labels=None still serializes as []."""
    mock_post.return_value = MagicMock()

    github_app.create_issue(_make_repo_mock(), "t", "b", labels=None)

    _, kwargs = mock_post.call_args
    assert kwargs.get("json", {}).get("labels") == []


@patch("libinv.vcs.requests.post")
def test_create_issue_swallows_request_exception(mock_post, github_app, caplog):
    """A network error should be logged and absorbed, not crash."""
    mock_post.side_effect = requests.RequestException("boom")

    # Should not raise.
    github_app.create_issue(_make_repo_mock(), "title", "body")
    assert any("Error creating issue" in rec.message for rec in caplog.records)


# ---------------------------------------------------------------------------
# update_issue
# ---------------------------------------------------------------------------
@patch("libinv.vcs.requests.patch")
def test_update_issue_passes_timeout_and_calls_raise_for_status(mock_patch, github_app):
    mock_response = MagicMock()
    mock_patch.return_value = mock_response

    github_app.update_issue("https://api.github.com/issues/1", "title", "body")

    assert mock_patch.called
    _, kwargs = mock_patch.call_args
    assert kwargs.get("timeout") == 10
    mock_response.raise_for_status.assert_called_once()


@patch("libinv.vcs.requests.patch")
def test_update_issue_labels_default_no_accumulation(mock_patch, github_app):
    mock_patch.return_value = MagicMock()

    github_app.update_issue("https://api.github.com/issues/1", "t1", "b1")
    github_app.update_issue("https://api.github.com/issues/2", "t2", "b2")

    for call in mock_patch.call_args_list:
        _, kwargs = call
        assert kwargs.get("json", {}).get("labels") == []


@patch("libinv.vcs.requests.patch")
def test_update_issue_labels_none_resolves_to_empty_list(mock_patch, github_app):
    mock_patch.return_value = MagicMock()

    github_app.update_issue("https://api.github.com/issues/1", "t", "b", labels=None)

    _, kwargs = mock_patch.call_args
    assert kwargs.get("json", {}).get("labels") == []


@patch("libinv.vcs.requests.patch")
def test_update_issue_swallows_request_exception(mock_patch, github_app, caplog):
    """Sprint 1 fixed an unreachable `except git.exc.GitError`. Make sure
    the *correct* `requests.RequestException` is now caught."""
    mock_patch.side_effect = requests.RequestException("network down")

    # Must not raise.
    github_app.update_issue("https://api.github.com/issues/1", "title", "body")
    assert any("Error updating issue" in rec.message for rec in caplog.records)


# ---------------------------------------------------------------------------
# get_sca_issue
# ---------------------------------------------------------------------------
def test_get_sca_issue_finds_match_in_later_issue(github_app):
    """Sprint 1 bug: an early `return None, False` after the first issue's
    first label didn't match caused later (valid) issues to be skipped."""
    repo = _make_repo_mock(name="myrepo")
    issues = [
        {
            "url": "https://api.github.com/repos/o/myrepo/issues/1",
            "labels": [{"name": "irrelevant"}, {"name": "other"}],
        },
        {
            "url": "https://api.github.com/repos/o/myrepo/issues/2",
            "labels": [{"name": "sca-actionable-myrepo"}],
        },
    ]
    with patch.object(github_app, "get_issues", return_value=issues):
        url, exists = github_app.get_sca_issue(repo)

    assert exists is True
    assert url == "https://api.github.com/repos/o/myrepo/issues/2"


def test_get_sca_issue_finds_match_in_later_label(github_app):
    """A matching label that isn't the first label on an issue must still
    be found."""
    repo = _make_repo_mock(name="myrepo")
    issues = [
        {
            "url": "https://api.github.com/repos/o/myrepo/issues/1",
            "labels": [{"name": "irrelevant"}, {"name": "sca-actionable-myrepo"}],
        },
    ]
    with patch.object(github_app, "get_issues", return_value=issues):
        url, exists = github_app.get_sca_issue(repo)

    assert exists is True
    assert url == "https://api.github.com/repos/o/myrepo/issues/1"


def test_get_sca_issue_returns_none_false_when_empty(github_app):
    repo = _make_repo_mock(name="myrepo")
    with patch.object(github_app, "get_issues", return_value=[]):
        url, exists = github_app.get_sca_issue(repo)
    assert url is None
    assert exists is False


def test_get_sca_issue_returns_none_false_when_no_match(github_app):
    repo = _make_repo_mock(name="myrepo")
    issues = [
        {
            "url": "https://api.github.com/repos/o/myrepo/issues/1",
            "labels": [{"name": "bug"}, {"name": "wontfix"}],
        },
        {
            "url": "https://api.github.com/repos/o/myrepo/issues/2",
            "labels": [{"name": "sca-actionable-otherrepo"}],
        },
    ]
    with patch.object(github_app, "get_issues", return_value=issues):
        url, exists = github_app.get_sca_issue(repo)
    assert url is None
    assert exists is False


def test_get_sca_issue_handles_none_issues(github_app):
    """If get_issues returns None (network failure path), we must not raise."""
    repo = _make_repo_mock(name="myrepo")
    with patch.object(github_app, "get_issues", return_value=None):
        url, exists = github_app.get_sca_issue(repo)
    assert url is None
    assert exists is False
