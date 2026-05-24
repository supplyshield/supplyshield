"""Sprint 52.1 — cron_scheduler graceful shutdown on SIGTERM.

These tests pin the SIGTERM contract:
  * ``_shutdown_handler`` flips the module-level ``_shutdown_requested``
    flag so the main loop bails between jobs.
  * If a child subprocess is running, the handler waits up to
    ``_SHUTDOWN_WAIT_S`` for it to exit before sending SIGTERM.
  * ``execute_command`` short-circuits when shutdown is already
    requested.
  * ``run_all_once`` halts iteration on shutdown.

They patch ``signal.signal`` + ``sys.exit`` so the test process is not
torn down when the handler runs, and patch ``time.sleep`` so the
30-second poll loop doesn't actually wait.
"""

from __future__ import annotations

import signal
from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture(autouse=True)
def _reset_cron_state():
    """Restore module state around each test so leakage cannot occur."""
    from libinv import cron_scheduler

    original_flag = cron_scheduler._shutdown_requested
    original_proc = cron_scheduler._current_process
    yield
    cron_scheduler._shutdown_requested = original_flag
    cron_scheduler._current_process = original_proc


def test_shutdown_handler_sets_flag_when_no_running_job():
    """With no live subprocess the handler just flips the flag + exits."""
    from libinv import cron_scheduler

    cron_scheduler._current_process = None

    with patch.object(cron_scheduler.sys, "exit") as exit_mock:
        cron_scheduler._shutdown_handler(signal.SIGTERM, None)

    assert cron_scheduler._shutdown_requested is True
    exit_mock.assert_called_once_with(0)


def test_shutdown_handler_waits_for_running_subprocess():
    """If a child is running, handler polls it before exiting (graceful drain)."""
    from libinv import cron_scheduler

    proc = MagicMock()
    # Pretend the child takes two polls to exit cleanly.
    proc.poll.side_effect = [None, None, 0, 0]
    cron_scheduler._current_process = proc

    with patch.object(cron_scheduler.time, "sleep") as sleep_mock, patch.object(
        cron_scheduler.sys, "exit"
    ) as exit_mock:
        cron_scheduler._shutdown_handler(signal.SIGTERM, None)

    assert cron_scheduler._shutdown_requested is True
    # The handler polled the process at least twice while it was still
    # running, so ``sleep`` should have been called at least twice.
    assert sleep_mock.call_count >= 2
    # Child exited within the grace window; ``terminate`` must NOT be called.
    proc.terminate.assert_not_called()
    exit_mock.assert_called_once_with(0)


def test_shutdown_handler_terminates_stuck_job_after_grace_window():
    """If the child never exits within the window, send it SIGTERM."""
    from libinv import cron_scheduler

    proc = MagicMock()
    proc.poll.return_value = None  # Never exits
    cron_scheduler._current_process = proc

    # Patch monotonic so the deadline elapses after a single sleep call —
    # this simulates the 30-second drain window without making the test
    # actually wait.
    fake_times = iter([0.0, 0.5, 9999.0])
    with patch.object(cron_scheduler.time, "monotonic", side_effect=lambda: next(fake_times)), \
         patch.object(cron_scheduler.time, "sleep") as _sleep_mock, \
         patch.object(cron_scheduler.sys, "exit") as exit_mock:
        cron_scheduler._shutdown_handler(signal.SIGTERM, None)

    proc.terminate.assert_called_once()
    exit_mock.assert_called_once_with(0)


def test_execute_command_short_circuits_when_shutdown_requested():
    """``execute_command`` must NOT spawn a child if shutdown is already requested."""
    from libinv import cron_scheduler

    cron_scheduler._shutdown_requested = True
    with patch.object(cron_scheduler.subprocess, "Popen") as popen_mock:
        cron_scheduler.execute_command("echo hi", timeout=5)
    popen_mock.assert_not_called()


def test_run_all_once_halts_on_shutdown_requested():
    """``run_all_once`` must stop iterating ``JOBS`` once shutdown is requested."""
    from libinv import cron_scheduler

    # Inject two fake jobs; the first one trips the shutdown flag, so the
    # second one must NOT be invoked.
    fake_jobs = {
        "first": {"command": "echo first", "timeout": 5},
        "second": {"command": "echo second", "timeout": 5},
    }
    invoked = []

    def fake_execute(command, timeout):
        invoked.append(command)
        cron_scheduler._shutdown_requested = True

    with patch.dict(cron_scheduler.JOBS, fake_jobs, clear=True), patch.object(
        cron_scheduler, "execute_command", side_effect=fake_execute
    ):
        cron_scheduler.run_all_once()

    assert invoked == ["echo first"], (
        f"Expected only 'first' job to run before shutdown halt; got {invoked}"
    )


def test_main_installs_sigterm_handler():
    """``main`` must register ``_shutdown_handler`` against SIGTERM."""
    from libinv import cron_scheduler

    captured = {}

    def fake_signal(signum, handler):
        captured[signum] = handler

    # Force run_all_once to set shutdown so main exits without entering
    # the schedule loop.
    def stop_immediately():
        cron_scheduler._shutdown_requested = True

    with patch.object(cron_scheduler.signal, "signal", side_effect=fake_signal), patch.object(
        cron_scheduler, "run_all_once", side_effect=stop_immediately
    ), patch.object(cron_scheduler, "schedule_jobs") as schedule_mock:
        cron_scheduler.main()

    assert signal.SIGTERM in captured
    assert captured[signal.SIGTERM] is cron_scheduler._shutdown_handler
    # Scheduler loop must not be entered when shutdown trips during startup.
    schedule_mock.assert_not_called()
