"""Unit tests for libinv.helpers (no DB required)."""

from unittest.mock import MagicMock
from unittest.mock import patch

import pytest
import requests

from libinv import helpers
from libinv.exceptions import RetryFailedException


# ---------------------------------------------------------------------------
# explode_git_url
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "url, expected",
    [
        (
            "git@github.com:gitorg/100ft-web.git",
            {"provider": "github.com", "org": "gitorg", "name": "100ft-web"},
        ),
        (
            "https://bitbucket.org/gitorg/libinv",
            {"provider": "bitbucket.org", "org": "gitorg", "name": "libinv"},
        ),
        (
            "git@github.com:org/repo",
            {"provider": "github.com", "org": "org", "name": "repo"},
        ),
        (
            # edge case: https URL with .git suffix is also stripped
            "https://github.com/org/repo.git",
            {"provider": "github.com", "org": "org", "name": "repo"},
        ),
    ],
)
def test_explode_git_url_valid(url, expected):
    assert helpers.explode_git_url(url) == expected


def test_explode_git_url_unsupported_scheme():
    with pytest.raises(ValueError) as excinfo:
        helpers.explode_git_url("ftp://example/foo/bar")
    assert "Unsupported git URL scheme" in str(excinfo.value)


# ---------------------------------------------------------------------------
# retry_on_exception
# ---------------------------------------------------------------------------
def test_retry_on_exception_honors_count(monkeypatch):
    # Patch sleep so the test stays fast.
    monkeypatch.setattr(helpers, "sleep", lambda _s: None)
    monkeypatch.setattr(helpers.random, "uniform", lambda a, b: 0)

    calls = {"n": 0}

    @helpers.retry_on_exception(ValueError, count=4, delay=1)
    def always_fail():
        calls["n"] += 1
        raise ValueError("nope")

    with pytest.raises(RetryFailedException):
        always_fail()
    assert calls["n"] == 4, "function should be called exactly `count` times"


def test_retry_on_exception_returns_on_success(monkeypatch):
    monkeypatch.setattr(helpers, "sleep", lambda _s: None)
    monkeypatch.setattr(helpers.random, "uniform", lambda a, b: 0)

    state = {"n": 0}

    @helpers.retry_on_exception(ValueError, count=3, delay=1)
    def flaky():
        state["n"] += 1
        if state["n"] < 2:
            raise ValueError("flake")
        return "ok"

    assert flaky() == "ok"
    assert state["n"] == 2


def test_retry_on_exception_reraises_retry_failed_not_original(monkeypatch):
    monkeypatch.setattr(helpers, "sleep", lambda _s: None)
    monkeypatch.setattr(helpers.random, "uniform", lambda a, b: 0)

    @helpers.retry_on_exception(RuntimeError, count=2, delay=1)
    def boom():
        raise RuntimeError("kaboom")

    # It should raise RetryFailedException (NOT the original RuntimeError),
    # but the original exception should be chained via __cause__.
    with pytest.raises(RetryFailedException) as excinfo:
        boom()
    assert isinstance(excinfo.value.__cause__, RuntimeError)


# ---------------------------------------------------------------------------
# send_to_slack
# ---------------------------------------------------------------------------
def test_send_to_slack_passes_timeout():
    with patch("libinv.helpers.requests.post") as mock_post:
        helpers.send_to_slack("hello")
        assert mock_post.called
        _, kwargs = mock_post.call_args
        assert kwargs.get("timeout") == 10


def test_send_to_slack_swallows_request_exception(caplog):
    with patch("libinv.helpers.requests.post") as mock_post:
        mock_post.side_effect = requests.RequestException("network down")
        # Should NOT raise.
        helpers.send_to_slack("payload")
    # And should have logged a warning.
    assert any("Slack post failed" in rec.message for rec in caplog.records)
