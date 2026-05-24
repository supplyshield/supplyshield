"""Sprint 47.1 — cron_scheduler must invoke subprocess.Popen with shell=False.

Background
----------
Until Sprint 47.1, ``libinv/cron_scheduler.execute_command`` called
``subprocess.Popen(command, shell=True, ...)`` which feeds the raw
``JOBS`` command string through ``/bin/sh -c``. Because ``JOBS`` is an
environment variable (``libinv/env.py:113``) populated by deploy
manifests, any operator or supply-chain actor who can modify those
manifests could inject arbitrary shell — pipes, command-substitution,
file redirects — and run it under the cron user. The fix swaps the
invocation to ``shlex.split(command)`` + ``shell=False``.

This regression test pins the safe call-shape so a future edit cannot
silently re-introduce ``shell=True``.
"""

from unittest.mock import MagicMock, patch


def test_execute_command_uses_shell_false():
    """``execute_command`` must call ``subprocess.Popen`` with
    ``shell=False`` and a *list* argv produced by ``shlex.split``."""
    from libinv import cron_scheduler

    fake_proc = MagicMock()
    fake_proc.stdout.readline.return_value = ""
    fake_proc.poll.return_value = 0

    with patch("libinv.cron_scheduler.subprocess.Popen", return_value=fake_proc) as popen:
        cron_scheduler.execute_command("echo hello world", timeout=5)

    assert popen.call_count == 1, "Popen should be invoked exactly once per job"
    # Inspect both positional and keyword arguments for resilience —
    # Sprint 47.1 lands a kwarg-only call but a future refactor might
    # pass argv positionally.
    args, kwargs = popen.call_args
    if args:
        argv = args[0]
    else:
        argv = kwargs.get("args")
    assert isinstance(argv, list), (
        f"Popen was called with a non-list argv ({type(argv).__name__}); "
        "shell=False requires a tokenised list to avoid shell injection."
    )
    assert argv == ["echo", "hello", "world"], (
        f"shlex.split should have tokenised the command; got {argv!r}"
    )
    assert kwargs.get("shell") is False, (
        f"shell must be False to prevent shell-injection; got "
        f"shell={kwargs.get('shell')!r}"
    )


def test_execute_command_quoted_arg_preserved():
    """``shlex.split`` keeps quoted arguments intact — a real-world
    JOBS command like ``python -m my.tool --message 'hello world'``
    must yield a 4-element argv where the message stays one token."""
    from libinv import cron_scheduler

    fake_proc = MagicMock()
    fake_proc.stdout.readline.return_value = ""
    fake_proc.poll.return_value = 0

    with patch("libinv.cron_scheduler.subprocess.Popen", return_value=fake_proc) as popen:
        cron_scheduler.execute_command(
            "python -m my.tool --message 'hello world'", timeout=5
        )

    args, kwargs = popen.call_args
    argv = args[0] if args else kwargs.get("args")
    assert argv == ["python", "-m", "my.tool", "--message", "hello world"], argv
    assert kwargs.get("shell") is False
