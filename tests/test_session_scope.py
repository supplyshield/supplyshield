"""Unit tests for libinv.base.session_scope (no DB required).

Strategy: patch `ScopedSession` (the callable) on the libinv.base module.
The fixture-yielded session is a MagicMock; we assert on .commit(), .rollback(),
and .remove() calls.
"""

from unittest.mock import MagicMock
from unittest.mock import patch

import pytest


def test_session_scope_commits_and_removes_on_clean_exit():
    mock_session = MagicMock()
    with patch("libinv.base.ScopedSession") as mock_scoped:
        # `ScopedSession()` -> returns the mock_session.
        mock_scoped.return_value = mock_session

        from libinv.base import session_scope

        with session_scope() as s:
            assert s is mock_session
            # No exception inside the block.

        # ScopedSession() was called exactly once to get the thread-local session.
        mock_scoped.assert_called_once_with()
        mock_session.commit.assert_called_once()
        mock_session.rollback.assert_not_called()
        mock_scoped.remove.assert_called_once()


def test_session_scope_rolls_back_and_removes_on_exception_and_reraises():
    mock_session = MagicMock()
    with patch("libinv.base.ScopedSession") as mock_scoped:
        mock_scoped.return_value = mock_session

        from libinv.base import session_scope

        class _Boom(RuntimeError):
            pass

        with pytest.raises(_Boom):
            with session_scope() as s:
                assert s is mock_session
                raise _Boom("explode")

        mock_session.rollback.assert_called_once()
        mock_session.commit.assert_not_called()
        # ScopedSession.remove() must always run via the `finally`.
        mock_scoped.remove.assert_called_once()


def test_session_scope_removes_even_when_commit_fails():
    """If session.commit() itself raises, .remove() still runs in `finally`."""
    mock_session = MagicMock()
    mock_session.commit.side_effect = RuntimeError("db gone")

    with patch("libinv.base.ScopedSession") as mock_scoped:
        mock_scoped.return_value = mock_session

        from libinv.base import session_scope

        with pytest.raises(RuntimeError, match="db gone"):
            with session_scope():
                pass

        # commit ran (and raised); rollback NOT called because the commit happened
        # after the body completed normally (rollback only triggers in the except).
        # The current implementation's `except Exception:` will catch the commit
        # failure and rollback as well — verify behavior matches source:
        # Looking at libinv/base.py: yield, then session.commit(); if commit
        # raises, control passes to `except Exception: session.rollback(); raise`.
        mock_session.rollback.assert_called_once()
        mock_scoped.remove.assert_called_once()
