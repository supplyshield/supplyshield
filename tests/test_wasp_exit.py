"""Sprint 11 — verify Wasp.__exit__ does not suppress exceptions.

Wasp acts as a context manager. Sprint 0's daemon resilience now
catches per-message exceptions and slacks them, so Wasp must
propagate errors instead of silently swallowing them. Audit HIGH.
"""
from unittest.mock import MagicMock

import pytest

from libinv.models import Wasp


@pytest.fixture
def wasp_with_mocked_state(tmp_path):
    """Build a minimum Wasp instance suitable for context-manager use.

    Avoids hitting the DB by attaching a mocked session and a real
    temp directory that shutil.rmtree can clean up. Also seeds the
    attributes that ``Wasp.throw`` mutates on the exception path so
    we don't drag SQLAlchemy column descriptors into the test.
    """
    # Use the declarative constructor so SQLAlchemy initialises
    # ``_sa_instance_state`` and the Column descriptors work normally.
    w = Wasp(complaints="", ate_successfully=True)
    w._session = MagicMock()
    w._project_dir = tmp_path / "scan"
    w._project_dir.mkdir()
    return w


def test_wasp_exit_propagates_exception(wasp_with_mocked_state):
    """An exception inside `with wasp:` must propagate to the caller."""
    with pytest.raises(ValueError, match="test"):
        with wasp_with_mocked_state:
            raise ValueError("test")

    # Side effects still happened on the exception path:
    wasp_with_mocked_state._session.add.assert_called_once_with(wasp_with_mocked_state)
    wasp_with_mocked_state._session.commit.assert_called_once()
    # Temp dir cleaned up:
    assert not wasp_with_mocked_state._project_dir.exists()
    # throw() recorded the failure on the wasp itself.
    assert wasp_with_mocked_state.ate_successfully is False
    assert "ValueError" in wasp_with_mocked_state.complaints


def test_wasp_exit_commits_on_clean_exit(wasp_with_mocked_state):
    """No exception → side effects still run, control flow normal."""
    with wasp_with_mocked_state:
        pass
    wasp_with_mocked_state._session.add.assert_called_once_with(wasp_with_mocked_state)
    wasp_with_mocked_state._session.commit.assert_called_once()
    assert not wasp_with_mocked_state._project_dir.exists()
    # No exception, so throw() should not have been invoked.
    assert wasp_with_mocked_state.ate_successfully is True
    assert wasp_with_mocked_state.complaints == ""
