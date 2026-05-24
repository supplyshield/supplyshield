"""Unit tests for SemgrepRunner.run_semgrep.

Verifies that argv (not shell=True) is used and that untrusted-looking
config values flow through to subprocess.run as literal list elements
(no shell interpolation).
"""

from types import SimpleNamespace
from unittest.mock import MagicMock
from unittest.mock import patch

from libinv.scanners.repository_scanner.sast.semgrep.SemgrepRunner import SemgrepRunner


def _make_config(repo_name="benign-repo", project_dir="/tmp/proj", base_dir="/tmp/code"):
    return SimpleNamespace(
        wasp=SimpleNamespace(
            project_dir=project_dir,
            repository=SimpleNamespace(name=repo_name),
        ),
        base_code_directory=base_dir,
    )


def _completed():
    """Helper: realistic subprocess.run return value (no stderr)."""
    return SimpleNamespace(stderr="", stdout="", returncode=0)


# ---------------------------------------------------------------------------
def test_run_semgrep_passes_argv_list_not_shell_string():
    config = _make_config()
    runner = SemgrepRunner(config)

    with patch(
        "libinv.scanners.repository_scanner.sast.semgrep.SemgrepRunner.subprocess.run",
        return_value=_completed(),
    ) as mock_run:
        runner.run_semgrep()

    assert mock_run.called
    args, kwargs = mock_run.call_args
    # First positional arg must be a list (argv form), not a string.
    assert args, "subprocess.run was not called positionally with argv"
    argv = args[0]
    assert isinstance(argv, list), f"expected list argv, got {type(argv).__name__}"
    assert argv[0] == "semgrep"


# ---------------------------------------------------------------------------
def test_run_semgrep_does_not_use_shell_true():
    config = _make_config()
    runner = SemgrepRunner(config)

    with patch(
        "libinv.scanners.repository_scanner.sast.semgrep.SemgrepRunner.subprocess.run",
        return_value=_completed(),
    ) as mock_run:
        runner.run_semgrep()

    _, kwargs = mock_run.call_args
    # `shell=True` must NOT be set. Either kwargs lacks 'shell' (default False)
    # or it's explicitly False.
    assert kwargs.get("shell", False) is False


# ---------------------------------------------------------------------------
def test_run_semgrep_preserves_untrusted_values_as_literal_argv():
    """The shell-injection guarantee: weird config values must survive as-is."""
    config = _make_config(
        repo_name="evil; rm -rf /",
        project_dir="/tmp/proj-with-space and ;rm",
        base_dir="/tmp/x; rm -rf /",
    )
    runner = SemgrepRunner(config)

    with patch(
        "libinv.scanners.repository_scanner.sast.semgrep.SemgrepRunner.subprocess.run",
        return_value=_completed(),
    ) as mock_run:
        runner.run_semgrep()

    argv = mock_run.call_args.args[0]
    # The base_code_directory MUST appear as a single argv element,
    # not interpolated into a shell string.
    assert "/tmp/x; rm -rf /" in argv
    # And it must be the final positional argument to semgrep.
    assert argv[-1] == "/tmp/x; rm -rf /"


def test_run_semgrep_output_path_includes_repo_name_unchanged():
    """The repository.name (potentially untrusted) is embedded into --output."""
    config = _make_config(
        repo_name="weird & chars; ok",
        project_dir="/tmp/proj",
        base_dir="/tmp/code",
    )
    runner = SemgrepRunner(config)

    with patch(
        "libinv.scanners.repository_scanner.sast.semgrep.SemgrepRunner.subprocess.run",
        return_value=_completed(),
    ) as mock_run:
        runner.run_semgrep()

    argv = mock_run.call_args.args[0]
    # --output <path> where path contains the unchanged repo name.
    output_idx = argv.index("--output")
    output_path = argv[output_idx + 1]
    assert "weird & chars; ok" in output_path


# ---------------------------------------------------------------------------
def test_run_semgrep_passes_timeout_3600():
    config = _make_config()
    runner = SemgrepRunner(config)

    with patch(
        "libinv.scanners.repository_scanner.sast.semgrep.SemgrepRunner.subprocess.run",
        return_value=_completed(),
    ) as mock_run:
        runner.run_semgrep()

    _, kwargs = mock_run.call_args
    assert kwargs.get("timeout") == 3600
