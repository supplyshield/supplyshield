"""Unit tests for ``libinv.cli.daemon`` resilience behaviors (Sprint 0).

These tests are DB-free and exercise the daemon command via Click's
``CliRunner`` invoked through the parent ``cli`` group so the global
flags + ``seed_request_id_from_env`` from Sprint 22 are exercised.

Key behaviors under test:
- The loop no longer dies on the first exception while processing a
  message; it continues to the next message.
- SIGTERM / SIGINT set ``_shutdown_requested = True`` so the loop exits
  cleanly after the current batch.
- A failure to ``poll()`` is logged and the next iteration is attempted
  (i.e. the daemon does not crash on a transient SQS failure).
- The chunked Slack notification path runs when ``--slack`` is enabled.

Implementation note (re-using the workaround from conftest.py): the
package-init ``from libinv.cli.daemon import daemon`` shadows the
``daemon`` submodule attribute on the ``libinv.cli`` package with the
Click ``Command``. We therefore reach the module via
``sys.modules["libinv.cli.daemon"]`` rather than dotted attribute access.
"""

from __future__ import annotations

import sys

import pytest
from unittest.mock import patch
from click.testing import CliRunner

from libinv import cli  # noqa: F401 - registers subcommands incl. ``daemon``
from libinv.cli.cli import cli as cli_group


def _daemon_module():
    """Return the ``libinv.cli.daemon`` *module* (not the Click Command)."""
    # Force-register the module (idempotent if already imported).
    import libinv.cli.daemon  # noqa: F401

    return sys.modules["libinv.cli.daemon"]


@pytest.fixture(autouse=True)
def reset_shutdown_flag():
    """Reset the module-level ``_shutdown_requested`` flag around every test.

    The daemon command never exits while ``_shutdown_requested`` is False,
    so leaking state from one test would either hang the next test forever
    or cause it to exit prematurely.
    """
    d = _daemon_module()
    original = d._shutdown_requested
    d._shutdown_requested = False
    yield
    d._shutdown_requested = original


def test_daemon_processes_messages_and_continues_on_error():
    """The loop continues across a per-message exception (Sprint 0)."""
    d = _daemon_module()
    calls = {"poll": 0, "process": 0}

    def fake_poll():
        calls["poll"] += 1
        if calls["poll"] == 1:
            return [{"Body": "msg-1"}, {"Body": "msg-2"}]
        # Stop the loop on the second iteration.
        d._shutdown_requested = True
        return []

    def fake_process(message):
        calls["process"] += 1
        if calls["process"] == 2:
            raise RuntimeError("boom on msg-2")

    with patch("libinv.cli.daemon._wait_for_db"), patch(
        "libinv.cli.daemon.poll", side_effect=fake_poll
    ), patch("libinv.cli.daemon.process_message", side_effect=fake_process), patch(
        "libinv.cli.daemon._notify_slack"
    ) as slack_mock:
        runner = CliRunner()
        result = runner.invoke(cli_group, ["daemon", "--no-slack"])

    # Both messages were attempted - the loop did NOT die on the first error.
    assert calls["process"] == 2, (
        f"Expected both messages to be processed, got {calls['process']}; "
        f"output={result.output!r} exc={result.exception!r}"
    )
    # --no-slack disables the slack notification path.
    slack_mock.assert_not_called()
    assert result.exit_code == 0
    assert "daemon exited cleanly" in result.output


def test_daemon_notifies_slack_when_enabled_and_process_fails():
    """With ``--slack`` (the default) the slack notifier fires on error."""
    d = _daemon_module()
    calls = {"poll": 0}

    def fake_poll():
        calls["poll"] += 1
        if calls["poll"] == 1:
            return [{"Body": "msg-1"}]
        d._shutdown_requested = True
        return []

    def fake_process(message):
        raise RuntimeError("boom")

    with patch("libinv.cli.daemon._wait_for_db"), patch(
        "libinv.cli.daemon.poll", side_effect=fake_poll
    ), patch("libinv.cli.daemon.process_message", side_effect=fake_process), patch(
        "libinv.cli.daemon._notify_slack"
    ) as slack_mock:
        runner = CliRunner()
        # Default is --slack (is_flag=True, default=True).
        result = runner.invoke(cli_group, ["daemon"])

    slack_mock.assert_called_once()
    assert result.exit_code == 0


def test_daemon_exits_when_shutdown_requested():
    """If the shutdown flag is already set, the loop exits without polling."""
    d = _daemon_module()
    d._shutdown_requested = True

    with patch("libinv.cli.daemon._wait_for_db"), patch(
        "libinv.cli.daemon.poll"
    ) as poll_mock, patch("libinv.cli.daemon.process_message") as process_mock:
        runner = CliRunner()
        result = runner.invoke(cli_group, ["daemon", "--no-slack"])

    poll_mock.assert_not_called()
    process_mock.assert_not_called()
    assert result.exit_code == 0
    assert "daemon exited cleanly" in result.output


def test_daemon_recovers_from_poll_failure():
    """A poll() exception is logged and the next iteration is attempted."""
    d = _daemon_module()
    poll_calls = {"n": 0}

    def fake_poll():
        poll_calls["n"] += 1
        if poll_calls["n"] == 1:
            raise RuntimeError("AWS down")
        # Second iteration: empty batch, then stop on the third.
        if poll_calls["n"] >= 2:
            d._shutdown_requested = True
        return []

    with patch("libinv.cli.daemon._wait_for_db"), patch(
        "libinv.cli.daemon.poll", side_effect=fake_poll
    ), patch("libinv.cli.daemon.process_message") as process_mock:
        runner = CliRunner()
        result = runner.invoke(cli_group, ["daemon", "--no-slack"])

    # The poll failure was caught (no crash) AND a second poll was attempted.
    assert poll_calls["n"] >= 2, (
        f"Expected at least 2 poll attempts, got {poll_calls['n']}; "
        f"output={result.output!r} exc={result.exception!r}"
    )
    process_mock.assert_not_called()  # No messages were ever returned.
    assert result.exit_code == 0
    assert "daemon exited cleanly" in result.output


def test_request_shutdown_sets_flag():
    """Direct call to the signal handler flips the module-level flag."""
    import signal as _signal

    d = _daemon_module()
    assert d._shutdown_requested is False
    d._request_shutdown(_signal.SIGTERM, None)
    assert d._shutdown_requested is True


def test_daemon_breaks_out_of_message_loop_on_shutdown():
    """SIGTERM mid-batch stops processing the rest of the batch."""
    d = _daemon_module()
    calls = {"process": 0}

    def fake_poll():
        # Return a batch big enough to observe the break.
        return [{"Body": f"msg-{i}"} for i in range(5)]

    def fake_process(message):
        calls["process"] += 1
        if calls["process"] == 2:
            # Simulate the signal handler firing in the middle of a batch.
            d._shutdown_requested = True

    with patch("libinv.cli.daemon._wait_for_db"), patch(
        "libinv.cli.daemon.poll", side_effect=fake_poll
    ), patch("libinv.cli.daemon.process_message", side_effect=fake_process):
        runner = CliRunner()
        result = runner.invoke(cli_group, ["daemon", "--no-slack"])

    # Loop broke after the in-flight message; messages 3..5 were skipped.
    assert calls["process"] == 2
    assert result.exit_code == 0


def test_wait_for_db_returns_on_first_success():
    """Sprint 51.3 — happy path: a single ``SELECT 1`` and we return."""
    d = _daemon_module()

    fake_engine = type("E", (), {"url": type("U", (), {"host": "db.svc"})()})()
    conn_cm = type(
        "C",
        (),
        {
            "__enter__": lambda self: self,
            "__exit__": lambda self, *a: False,
            "execute": lambda self, _s: None,
        },
    )()
    fake_engine.connect = lambda: conn_cm

    with patch("libinv.base.get_engine", return_value=fake_engine), patch(
        "libinv.base.reset_engine_cache"
    ) as reset_mock, patch("libinv.cli.daemon.time.sleep") as sleep_mock:
        d._wait_for_db()

    sleep_mock.assert_not_called()
    reset_mock.assert_not_called()


def test_wait_for_db_retries_until_success():
    """Sprint 51.3 — first attempt fails, second succeeds; backoff invoked."""
    from sqlalchemy.exc import OperationalError

    d = _daemon_module()
    attempts = {"n": 0}

    class _FakeEngine:
        url = type("U", (), {"host": "db.svc"})()

        def connect(self):
            attempts["n"] += 1
            if attempts["n"] == 1:
                raise OperationalError("SELECT 1", {}, Exception("conn refused"))

            class _CM:
                def __enter__(self_inner):
                    return self_inner

                def __exit__(self_inner, *a):
                    return False

                def execute(self_inner, _s):
                    return None

            return _CM()

    fake = _FakeEngine()
    with patch("libinv.base.get_engine", return_value=fake), patch(
        "libinv.base.reset_engine_cache"
    ) as reset_mock, patch("libinv.cli.daemon.time.sleep") as sleep_mock:
        d._wait_for_db(initial_interval=0.01, max_interval=0.01, total_budget=60.0)

    assert attempts["n"] == 2
    sleep_mock.assert_called_once()
    reset_mock.assert_called_once()


def test_wait_for_db_raises_when_budget_exhausted():
    """Sprint 51.3 — budget exhaustion surfaces a RuntimeError."""
    from sqlalchemy.exc import OperationalError

    d = _daemon_module()

    class _FakeEngine:
        url = type("U", (), {"host": "db.svc"})()

        def connect(self):
            raise OperationalError("SELECT 1", {}, Exception("down"))

    # Force ``time.monotonic`` to jump past the budget after a single attempt.
    times = iter([0.0, 9999.0, 9999.0, 9999.0])
    with patch("libinv.base.get_engine", return_value=_FakeEngine()), patch(
        "libinv.base.reset_engine_cache"
    ), patch(
        "libinv.cli.daemon.time.monotonic", side_effect=lambda: next(times)
    ), patch("libinv.cli.daemon.time.sleep"):
        with pytest.raises(RuntimeError, match="failed to reach Postgres"):
            d._wait_for_db(initial_interval=0.01, max_interval=0.01, total_budget=1.0)


def test_daemon_increments_sqs_failed_counter_on_process_exception():
    """Sprint 52.3 — ``sqs_messages_failed_total`` is incremented on failure."""
    from libinv.api.metrics import sqs_messages_failed_total

    d = _daemon_module()
    calls = {"process": 0}

    def fake_poll():
        # Return a one-message batch; the shutdown flag is flipped from
        # inside fake_process AFTER it raises, so the failure path runs
        # at least once and the daemon then exits cleanly.
        return [{"Body": "msg-1"}]

    def fake_process(_msg):
        calls["process"] += 1
        d._shutdown_requested = True
        raise RuntimeError("boom")

    # Snapshot the counter before the test so we can assert a delta of +1.
    before = sqs_messages_failed_total.labels(reason="RuntimeError")._value.get()

    with patch("libinv.cli.daemon._wait_for_db"), patch(
        "libinv.cli.daemon.poll", side_effect=fake_poll
    ), patch(
        "libinv.cli.daemon.process_message", side_effect=fake_process
    ), patch("libinv.cli.daemon._notify_slack"):
        runner = CliRunner()
        result = runner.invoke(cli_group, ["daemon", "--no-slack"])

    after = sqs_messages_failed_total.labels(reason="RuntimeError")._value.get()
    assert calls["process"] == 1, (
        f"Expected fake_process to be invoked once; got {calls['process']}; "
        f"exit_code={result.exit_code} output={result.output!r}"
    )
    assert after - before == 1, (
        f"Expected sqs_messages_failed_total[reason=RuntimeError] to bump by 1; "
        f"before={before} after={after} exit_code={result.exit_code}"
    )


def test_notify_slack_chunks_long_traceback():
    """The chunked slack notifier sends multiple posts for a long trace."""
    d = _daemon_module()

    long_trace = "x" * 12000  # > 3 * chunk_size (3900)
    with patch("libinv.cli.daemon.traceback.format_exc", return_value=long_trace), patch(
        "libinv.cli.daemon.send_to_slack"
    ) as send_mock:
        d._notify_slack({"Body": "msg-1"})

    # 1 call for the error header + 1 for the first chunk of the trace +
    # at least 2 more calls for the remaining chunks of a 12000-char trace
    # split at 3900 chars => total >= 4.
    assert send_mock.call_count >= 4
