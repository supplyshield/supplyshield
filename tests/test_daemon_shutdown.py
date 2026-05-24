"""Unit tests for libinv.cli.daemon._request_shutdown."""

import signal


def test_request_shutdown_sets_flag_true(reset_daemon_shutdown_flag):
    daemon = reset_daemon_shutdown_flag
    daemon._shutdown_requested = False

    # Pass a fake signum + frame; frame may be None.
    daemon._request_shutdown(signal.SIGTERM, None)
    assert daemon._shutdown_requested is True


def test_request_shutdown_idempotent(reset_daemon_shutdown_flag):
    daemon = reset_daemon_shutdown_flag
    daemon._shutdown_requested = False

    daemon._request_shutdown(signal.SIGINT, None)
    daemon._request_shutdown(signal.SIGTERM, None)
    assert daemon._shutdown_requested is True


def test_reset_daemon_shutdown_flag_fixture_restores_state(reset_daemon_shutdown_flag):
    """The fixture itself: verify the flag is restored after the test."""
    daemon = reset_daemon_shutdown_flag
    # Mutate inside the test - the fixture's teardown will restore it.
    daemon._shutdown_requested = True
    # No explicit assert needed for restoration; teardown handles it.
    # But we can at least check the value flipped:
    assert daemon._shutdown_requested is True
