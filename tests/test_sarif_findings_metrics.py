"""Sprint 28 - ``libinv_sast_findings_total`` Counter verifies SARIF
findings are persisted with severity + tool labels.

The Counter lives in ``libinv.api.metrics`` and is incremented inside
``SarifResult.add_sarif_result_to_db`` AFTER each successful row commit
(insert OR update). The label set is bounded:

  * ``severity`` is normalized via ``_normalize_sarif_severity`` to one of
    {error, warning, note, none, low, medium, high, critical, unknown}.
  * ``tool`` comes from ``runs[0].tool.driver.name`` and falls back to
    ``"unknown"`` if missing.

These tests are DB-free: ``_s`` is a ``MagicMock`` so ``query/add/commit``
are no-ops, and ``memo_lob_id`` is primed before invocation to bypass
``add_lob_module``.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
def _rule(rule_id: str) -> dict:
    """Build a minimal SARIF rule entry that ``parsesarifmetadata`` accepts."""
    return {
        "id": rule_id,
        "fullDescription": {"text": f"{rule_id} description"},
        "properties": {"category": "security"},
    }


def _result(rule_id: str, level: str | None) -> dict:
    """Build a SARIF result row with enough structure for
    ``add_sarif_result_to_db`` to run end-to-end against a mocked session."""
    row: dict = {
        "ruleId": rule_id,
        "message": {"text": f"vuln from {rule_id}"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": "/base/app/foo.py"},
                    "region": {
                        "startLine": 42,
                        "snippet": {"text": "do_thing(user_input)"},
                    },
                }
            }
        ],
    }
    if level is not None:
        row["level"] = level
    return row


def _sarif(tool_name: str, rule_ids, results) -> dict:
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": tool_name,
                        "rules": [_rule(r) for r in rule_ids],
                    }
                },
                "results": results,
            }
        ],
    }


def _fake_config(base_dir="/base"):
    cfg = MagicMock()
    cfg.base_code_directory = base_dir
    cfg.wasp.id = 7
    cfg.wasp.commit = "deadbeef"
    cfg.wasp.repository.pod = "pod-a"
    cfg.wasp.repository.subpod = "sub-a"
    cfg.wasp.repository.url = "git@github.com:org/repo.git"
    cfg.wasp.repository_id = 99
    return cfg


@pytest.fixture
def sarif_with_two_findings(tmp_path):
    """A SARIF doc with two persisted findings: one ``error``, one
    ``warning`` from the ``semgrep`` driver."""
    sarif = _sarif(
        tool_name="semgrep",
        rule_ids=["rule-1", "rule-2"],
        results=[
            _result("rule-1", "error"),
            _result("rule-2", "warning"),
        ],
    )
    path = tmp_path / "two_findings.sarif"
    path.write_text(json.dumps(sarif))
    return path


@pytest.fixture
def sarif_with_weird_level(tmp_path):
    """A SARIF doc whose ``level`` is non-standard ("HIGH"). The
    normalizer must fold this into ``"high"`` (case-insensitive,
    in the allowed extended set)."""
    sarif = _sarif(
        tool_name="semgrep",
        rule_ids=["rule-1"],
        results=[_result("rule-1", "HIGH")],
    )
    path = tmp_path / "weird.sarif"
    path.write_text(json.dumps(sarif))
    return path


@pytest.fixture
def sarif_with_missing_level(tmp_path):
    """A SARIF doc whose result row has no ``level`` field at all. The
    persister must default to ``"none"`` (SARIF spec default)."""
    sarif = _sarif(
        tool_name="semgrep",
        rule_ids=["rule-1"],
        results=[_result("rule-1", None)],
    )
    path = tmp_path / "no_level.sarif"
    path.write_text(json.dumps(sarif))
    return path


def _new_sarif_result(sarif_path):
    """Build a ``SarifResult`` whose session always reports "no existing
    record" so the insert branch runs end-to-end, and whose ``memo_lob_id``
    is primed so the persistence path does not call ``add_lob_module``."""
    from libinv.scanners.repository_scanner.sast.SarifResult import SarifResult

    fake_session = MagicMock(name="injected_session")
    fake_session.query.return_value.filter_by.return_value.first.return_value = None

    source = MagicMock()
    source.value = "semgrep"

    sr = SarifResult(_fake_config(), str(sarif_path), source, session=fake_session)

    # Prime memo_lob_id so add_sarif_result_to_db can look up `lob_id`
    # without first calling add_lob_module (which is exercised by
    # tests/test_sarif_result.py).
    for row in sr.sarifjson["runs"][0]["results"]:
        key = sr.make_memo_key("pod-a", "sub-a", row["ruleId"])
        sr.memo_lob_id[key] = 1234
    return sr, fake_session


# ---------------------------------------------------------------------------
# 1. Counter increments once per persisted finding, with correct labels.
# ---------------------------------------------------------------------------
def test_sast_findings_counter_increments_per_result(sarif_with_two_findings):
    from libinv.api.metrics import sast_findings_total

    before_error = (
        sast_findings_total.labels(severity="error", tool="semgrep")._value.get()
    )
    before_warning = (
        sast_findings_total.labels(severity="warning", tool="semgrep")._value.get()
    )

    sr, _session = _new_sarif_result(sarif_with_two_findings)
    sr.add_sarif_result_to_db()

    after_error = (
        sast_findings_total.labels(severity="error", tool="semgrep")._value.get()
    )
    after_warning = (
        sast_findings_total.labels(severity="warning", tool="semgrep")._value.get()
    )

    assert after_error == before_error + 1
    assert after_warning == before_warning + 1


# ---------------------------------------------------------------------------
# 2. Non-standard ``level`` strings are normalized (case-folded into the
#    bounded allow-list) so prometheus cardinality stays predictable.
# ---------------------------------------------------------------------------
def test_sast_findings_counter_normalizes_non_standard_severity(
    sarif_with_weird_level,
):
    from libinv.api.metrics import sast_findings_total

    before = sast_findings_total.labels(severity="high", tool="semgrep")._value.get()

    sr, _session = _new_sarif_result(sarif_with_weird_level)
    sr.add_sarif_result_to_db()

    after = sast_findings_total.labels(severity="high", tool="semgrep")._value.get()
    assert after == before + 1


# ---------------------------------------------------------------------------
# 3. Missing ``level`` defaults to SARIF's spec default of ``"none"``.
# ---------------------------------------------------------------------------
def test_sast_findings_counter_defaults_to_none_when_level_missing(
    sarif_with_missing_level,
):
    from libinv.api.metrics import sast_findings_total

    before = sast_findings_total.labels(severity="none", tool="semgrep")._value.get()

    sr, _session = _new_sarif_result(sarif_with_missing_level)
    sr.add_sarif_result_to_db()

    after = sast_findings_total.labels(severity="none", tool="semgrep")._value.get()
    assert after == before + 1


# ---------------------------------------------------------------------------
# 4. The counter must NOT increment when persistence commit fails.
#    We trigger this by making `_s.commit` raise on the insert path; the
#    raised exception bubbles up before the .inc() call.
# ---------------------------------------------------------------------------
def test_sast_findings_counter_does_not_increment_when_commit_raises(
    sarif_with_two_findings,
):
    from libinv.api.metrics import sast_findings_total

    before = sast_findings_total.labels(severity="error", tool="semgrep")._value.get()

    sr, session = _new_sarif_result(sarif_with_two_findings)
    session.commit.side_effect = RuntimeError("db boom")

    with pytest.raises(RuntimeError):
        sr.add_sarif_result_to_db()

    after = sast_findings_total.labels(severity="error", tool="semgrep")._value.get()
    # No commits succeeded -> no counter movement on the "error" label.
    assert after == before


# ---------------------------------------------------------------------------
# 5. ``_normalize_sarif_severity`` is the single source of truth for the
#    bounded label set; sanity-check the buckets directly.
# ---------------------------------------------------------------------------
def test_normalize_sarif_severity_buckets():
    from libinv.scanners.repository_scanner.sast.SarifResult import (
        _normalize_sarif_severity,
    )

    # Spec values pass through unchanged.
    for lvl in ("error", "warning", "note", "none"):
        assert _normalize_sarif_severity(lvl) == lvl

    # Extended four-tier set is allowed (case-folded).
    assert _normalize_sarif_severity("HIGH") == "high"
    assert _normalize_sarif_severity("Critical") == "critical"

    # Anything else -> "unknown" (bounded cardinality).
    assert _normalize_sarif_severity("informational") == "unknown"
    assert _normalize_sarif_severity("") == "unknown"
    assert _normalize_sarif_severity(None) == "unknown"
    assert _normalize_sarif_severity(42) == "unknown"
