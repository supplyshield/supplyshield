"""Unit tests for ``libinv.cli.checkpoint`` (get / set / list).

These tests are DB-free: ``libinv.cli.checkpoint.Session`` is patched out
to a ``MagicMock`` context manager, and ``DeploymentCheckpoint``'s
classmethods (``get`` / ``set`` / ``list``) are stubbed so the CLI's
parsing + branching logic is exercised in isolation.

The checkpoint command is invoked via the parent ``cli`` group so the
global flags + ``seed_request_id_from_env`` from Sprint 22 run too.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from libinv import cli  # noqa: F401 - registers subcommands incl. ``checkpoint``
from libinv.cli.cli import cli as cli_group


def test_checkpoint_get_prints_active():
    """``--get`` prints the active ``DeploymentCheckpoint`` via ``__str__``."""
    fake_checkpoint = MagicMock()
    fake_checkpoint.__str__ = lambda self: "ACTIVE-MOCK"

    with patch("libinv.cli.checkpoint.Session"), patch(
        "libinv.cli.checkpoint.DeploymentCheckpoint.get",
        return_value=fake_checkpoint,
    ):
        runner = CliRunner()
        result = runner.invoke(cli_group, ["checkpoint", "--get"])

    assert result.exit_code == 0, f"output={result.output!r} exc={result.exception!r}"
    assert "ACTIVE-MOCK" in result.output


def test_checkpoint_set_now_calls_set_with_utc_now():
    """``--set NOW`` resolves to a UTC ``datetime`` near ``datetime.now(utc)``."""
    before = datetime.now(timezone.utc)

    with patch("libinv.cli.checkpoint.Session"), patch(
        "libinv.cli.checkpoint.DeploymentCheckpoint.set"
    ) as set_mock:
        runner = CliRunner()
        result = runner.invoke(cli_group, ["checkpoint", "--set", "NOW"])

    after = datetime.now(timezone.utc)
    assert result.exit_code == 0, f"output={result.output!r} exc={result.exception!r}"
    set_mock.assert_called_once()

    called_kwargs = set_mock.call_args.kwargs
    assert "session" in called_kwargs
    passed_checkpoint = called_kwargs["checkpoint"]
    assert isinstance(passed_checkpoint, datetime)
    assert passed_checkpoint.tzinfo is not None
    # Within a generous window in case CI is slow.
    assert before - timedelta(seconds=5) <= passed_checkpoint <= after + timedelta(seconds=5)


def test_checkpoint_set_with_timestamp_parses_correctly():
    """A literal ``YYYY-MM-DD HH:MM:SS`` arg is parsed to a naive ``datetime``."""
    expected = datetime(2025, 1, 15, 12, 0, 0)

    with patch("libinv.cli.checkpoint.Session"), patch(
        "libinv.cli.checkpoint.DeploymentCheckpoint.set"
    ) as set_mock:
        runner = CliRunner()
        result = runner.invoke(cli_group, ["checkpoint", "--set", "2025-01-15 12:00:00"])

    assert result.exit_code == 0, f"output={result.output!r} exc={result.exception!r}"
    set_mock.assert_called_once()
    passed_checkpoint = set_mock.call_args.kwargs["checkpoint"]
    assert passed_checkpoint == expected


def test_checkpoint_list_prints_all_with_active_marker():
    """List output prefixes the active checkpoint with ``"* "``."""
    active = MagicMock()
    active.active = True
    active.__str__ = lambda self: "2025-01-15 12:00:00+00:00"

    inactive = MagicMock()
    inactive.active = False
    inactive.__str__ = lambda self: "2024-12-31 23:59:59+00:00"

    with patch("libinv.cli.checkpoint.Session"), patch(
        "libinv.cli.checkpoint.DeploymentCheckpoint.list",
        return_value=[active, inactive],
    ):
        runner = CliRunner()
        # No flags = the ``else`` branch (list).
        result = runner.invoke(cli_group, ["checkpoint"])

    assert result.exit_code == 0, f"output={result.output!r} exc={result.exception!r}"
    assert "* 2025-01-15 12:00:00+00:00" in result.output
    assert "  2024-12-31 23:59:59+00:00" in result.output


def test_checkpoint_set_invalid_timestamp_raises():
    """An unparseable timestamp surfaces ``ValueError`` from ``strptime``."""
    with patch("libinv.cli.checkpoint.Session"), patch(
        "libinv.cli.checkpoint.DeploymentCheckpoint.set"
    ) as set_mock:
        runner = CliRunner()
        result = runner.invoke(cli_group, ["checkpoint", "--set", "not-a-date"])

    # strptime() raises ValueError - Click surfaces it as a non-zero exit.
    assert result.exit_code != 0
    assert isinstance(result.exception, ValueError)
    set_mock.assert_not_called()
