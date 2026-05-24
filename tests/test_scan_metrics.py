"""Sprint 25 — `scan_invocations_total` counter is incremented per scan.

The counter is defined in `libinv.api.metrics` (Sprint 24) and is wired
in this sprint at the highest-level scan entry points:

* `libinv.scanners.image_scanner.scanner.scan_image_index`
  — `type="image"`, one increment per scan invocation (NOT per image_tar
    iterated inside the loop). All three public entry points
    (`scan_orgsre_image` / `scan_dockerhub_image` / `scan_ecr_image`)
    funnel here, so this is the single chokepoint.

* `libinv.scanners.repository_scanner.bridge.connect_using_queue_message_agreement`
  — `type="repository_bridge"`, one increment per SQS bridge message.

* `libinv.scanners.repository_scanner.cdx_scanner.run_cdxgen_scan`
  — `type="cdxgen"`, one increment per cdxgen run (a sub-step of a
    repository scan, tagged separately because it has its own failure
    modes and runtime profile worth observing).

Tests are DB-free and network-free — all scan dependencies are mocked.
"""

from unittest.mock import MagicMock, patch


def _counter_value(label_type: str) -> float:
    """Read the current value of the per-label `scan_invocations_total`.

    The prometheus_client `Counter`'s `.labels(...)` returns a child whose
    `_value.get()` exposes the current count. Using a stable read helper
    keeps the per-test before/after diff readable.
    """
    from libinv.api.metrics import scan_invocations_total

    return scan_invocations_total.labels(type=label_type)._value.get()


# ---------------------------------------------------------------------------
# image scanner — scan_image_index is the single chokepoint for all three
# public entry points. Counting here avoids double-counting (e.g. wrapping
# scan_ecr_image AND scan_image_index would count an ECR scan twice).
# ---------------------------------------------------------------------------
def test_scan_image_index_increments_image_counter():
    from libinv.scanners.image_scanner.scanner import scan_image_index

    before = _counter_value("image")

    # An ImageIndex whose pull yields nothing — the body of the for-loop
    # never runs, so we don't need to mock sbom/sca/session_scope.
    image_index = MagicMock()
    image_index.pull_images_if_not_exist.return_value = iter([])

    scan_image_index(image_index, account_id="acct-test")

    assert _counter_value("image") == before + 1


def test_scan_image_index_increments_once_even_when_pull_raises():
    """A crash inside the scan must still register in the counter — we
    increment BEFORE the work to keep failure rates observable. We don't
    add a separate `scan_failures_total` counter in this sprint."""
    from libinv.scanners.image_scanner.scanner import scan_image_index

    before = _counter_value("image")

    image_index = MagicMock()
    image_index.pull_images_if_not_exist.side_effect = RuntimeError("boom")

    try:
        scan_image_index(image_index, account_id="acct-test")
    except RuntimeError:
        pass

    assert _counter_value("image") == before + 1


# ---------------------------------------------------------------------------
# repository bridge — type="repository_bridge"
# ---------------------------------------------------------------------------
def test_repository_bridge_increments_counter():
    from libinv.scanners.repository_scanner.bridge import (
        connect_using_queue_message_agreement,
    )

    before = _counter_value("repository_bridge")

    wasp = MagicMock()
    # `ecr_image: []` makes the for-loop a no-op — no DB / connect() calls.
    wasp.raw_message = '{"ecr_image": [], "aws_environment": "stage"}'

    connect_using_queue_message_agreement(wasp, session=MagicMock())

    assert _counter_value("repository_bridge") == before + 1


def test_repository_bridge_increments_even_for_malformed_message():
    """Increment happens BEFORE json.loads, so a bad message still
    surfaces in the metric (caller's exception propagates as usual)."""
    from libinv.scanners.repository_scanner.bridge import (
        connect_using_queue_message_agreement,
    )

    before = _counter_value("repository_bridge")

    wasp = MagicMock()
    wasp.raw_message = "not-json"

    try:
        connect_using_queue_message_agreement(wasp, session=MagicMock())
    except ValueError:
        pass  # json.JSONDecodeError is a ValueError subclass

    assert _counter_value("repository_bridge") == before + 1


# ---------------------------------------------------------------------------
# cdxgen — type="cdxgen"
# ---------------------------------------------------------------------------
def test_run_cdxgen_scan_increments_cdxgen_counter():
    from libinv.scanners.repository_scanner import cdx_scanner

    before = _counter_value("cdxgen")

    # Patch CdxScanner so we never touch the filesystem, subprocess, or env
    # detection. We only care that the counter is bumped.
    fake_scanner = MagicMock()
    fake_scanner.errors = ""
    fake_scanner.run.return_value = "/tmp/fake.sbom.cdx.json"

    wasp = MagicMock()
    wasp.repo_dir = "/tmp/repo"
    wasp.project_dir = "/tmp/project"

    with patch.object(cdx_scanner, "CdxScanner", return_value=fake_scanner):
        out = cdx_scanner.run_cdxgen_scan(wasp)

    assert out == "/tmp/fake.sbom.cdx.json"
    assert _counter_value("cdxgen") == before + 1


def test_run_cdxgen_scan_increments_even_when_scanner_init_fails():
    """Increment happens at the very top of `run_cdxgen_scan`, before
    `CdxScanner(repo_dir)` is constructed — a constructor crash (e.g.
    `get_env` failing on a missing Dockerfile path) still counts."""
    from libinv.scanners.repository_scanner import cdx_scanner

    before = _counter_value("cdxgen")

    wasp = MagicMock()
    wasp.repo_dir = "/tmp/repo"

    with patch.object(
        cdx_scanner, "CdxScanner", side_effect=RuntimeError("env exploded")
    ):
        try:
            cdx_scanner.run_cdxgen_scan(wasp)
        except RuntimeError:
            pass

    assert _counter_value("cdxgen") == before + 1


# ---------------------------------------------------------------------------
# scan_failures_total — exceptions raised inside scan entry points are
# counted by (type, error_class) so dashboards can compute success rate
# and group failures by root cause without parsing stack traces.
# ---------------------------------------------------------------------------
import pytest  # noqa: E402


def _failure_value(label_type: str, error_class: str) -> float:
    from libinv.api.metrics import scan_failures_total

    return scan_failures_total.labels(
        type=label_type, error_class=error_class
    )._value.get()


def test_image_scan_increments_failures_on_exception():
    """A RuntimeError inside the scan body bumps scan_failures_total with
    `type="image"` and `error_class="RuntimeError"` and re-raises."""
    from libinv.scanners.image_scanner.scanner import scan_image_index

    before = _failure_value("image", "RuntimeError")

    image_index = MagicMock()
    image_index.pull_images_if_not_exist.side_effect = RuntimeError("boom")

    with pytest.raises(RuntimeError):
        scan_image_index(image_index, account_id="acct-test")

    assert _failure_value("image", "RuntimeError") == before + 1


def test_repository_bridge_increments_failures_on_exception():
    """A malformed message raises `json.JSONDecodeError` (a `ValueError`
    subclass) — assert the failure counter records the concrete class
    name so dashboards group by root cause."""
    from libinv.scanners.repository_scanner.bridge import (
        connect_using_queue_message_agreement,
    )

    before = _failure_value("repository_bridge", "JSONDecodeError")

    wasp = MagicMock()
    wasp.raw_message = "not-json"

    with pytest.raises(ValueError):
        connect_using_queue_message_agreement(wasp, session=MagicMock())

    assert _failure_value("repository_bridge", "JSONDecodeError") == before + 1


def test_run_cdxgen_scan_increments_failures_on_exception():
    """A constructor crash inside `run_cdxgen_scan` bumps the failure
    counter with `type="cdxgen"` / `error_class="RuntimeError"` and
    re-raises."""
    from libinv.scanners.repository_scanner import cdx_scanner

    before = _failure_value("cdxgen", "RuntimeError")

    wasp = MagicMock()
    wasp.repo_dir = "/tmp/repo"

    with patch.object(
        cdx_scanner, "CdxScanner", side_effect=RuntimeError("env exploded")
    ):
        with pytest.raises(RuntimeError):
            cdx_scanner.run_cdxgen_scan(wasp)

    assert _failure_value("cdxgen", "RuntimeError") == before + 1
