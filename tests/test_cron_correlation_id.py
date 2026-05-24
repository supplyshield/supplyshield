"""Sprint 21 — cron_scheduler sets request_id_var per job."""

import logging
from unittest.mock import MagicMock, patch
import pytest


def test_execute_command_sets_request_id_in_logs():
    """Each cron job invocation gets a fresh UUID in the contextvar so
    log records carry the correlation id."""
    from libinv.logger import request_id_var
    from libinv import cron_scheduler

    captured: list[str] = []

    class _CaptureFilter(logging.Filter):
        def filter(self, record):
            captured.append(request_id_var.get())
            return True

    test_logger = logging.getLogger("libinv.cron-scheduler")
    flt = _CaptureFilter()
    test_logger.addFilter(flt)
    # Ensure INFO/DEBUG records reach the filter under pytest's default
    # WARNING-level root logger.
    prior_level = test_logger.level
    test_logger.setLevel(logging.DEBUG)

    try:
        # subprocess.Popen mock so we don't actually run anything
        fake_proc = MagicMock()
        fake_proc.stdout.readline.return_value = ""
        fake_proc.poll.return_value = 0
        with patch("libinv.cron_scheduler.subprocess.Popen", return_value=fake_proc):
            cron_scheduler.execute_command("echo hi", timeout=5)

        # All captured request_ids during execute_command should be
        # the same non-default value (one UUID per call).
        non_default = [rid for rid in captured if rid != "-"]
        assert non_default, "No log records captured the new request_id"
        assert all(rid == non_default[0] for rid in non_default), (
            f"Multiple ids captured: {set(non_default)}"
        )
    finally:
        test_logger.removeFilter(flt)
        test_logger.setLevel(prior_level)


def test_execute_command_resets_request_id_after_run():
    """After the job finishes, the contextvar reverts to its prior value."""
    from libinv.logger import request_id_var
    from libinv import cron_scheduler

    request_id_var.set("outside-id")
    fake_proc = MagicMock()
    fake_proc.stdout.readline.return_value = ""
    fake_proc.poll.return_value = 0
    with patch("libinv.cron_scheduler.subprocess.Popen", return_value=fake_proc):
        cron_scheduler.execute_command("echo hi", timeout=5)
    assert request_id_var.get() == "outside-id"
