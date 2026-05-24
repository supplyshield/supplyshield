"""Sprint 27 - unit tests for the SAST SarifResult persister.

Sprint 20 migrated this class from module-level ``conn`` to instance-level
``_session`` injection (Option A). These tests pin that contract:

  * an injected session is preferred over the module-level fallback,
  * the SARIF JSON parses correctly at construction time,
  * persistence calls (query/add/commit) land on the injected session.

All tests are DB-free: ``SastLobMetaData`` / ``SastResult`` are not patched
because we only need to observe that ``_s`` (the session proxy) receives
the expected method calls. ``self._s`` resolves to ``self._session or conn``
via the ``_s`` property, so injecting a ``MagicMock`` as ``session=`` lets
us assert on ``query``, ``add``, and ``commit`` directly.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock
from unittest.mock import patch

import pytest


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
def _minimal_sarif(results=None, rules=None):
    """Return a minimal-but-parseable SARIF 2.1.0 document.

    ``parsesarifmetadata`` (called from ``__init__``) walks
    ``runs[0].tool.driver.rules`` and expects each rule to expose
    ``id``, ``fullDescription.text`` and ``properties``.
    """
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "semgrep",
                        "rules": rules or [],
                    }
                },
                "results": results or [],
            }
        ],
    }


@pytest.fixture
def empty_sarif_file(tmp_path):
    """An otherwise valid SARIF document with no rules and no results."""
    path = tmp_path / "empty.sarif"
    path.write_text(json.dumps(_minimal_sarif()))
    return path


@pytest.fixture
def one_rule_one_result_sarif(tmp_path):
    """A SARIF doc with one rule and one matching result row."""
    rules = [
        {
            "id": "libinv.idor.rule-1",
            "fullDescription": {"text": "demo rule"},
            "properties": {"category": "security"},
        }
    ]
    results = [
        {
            "ruleId": "libinv.idor.rule-1",
            "message": {"text": "vuln found"},
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
    ]
    path = tmp_path / "one.sarif"
    path.write_text(json.dumps(_minimal_sarif(results=results, rules=rules)))
    return path


def _fake_config(base_dir="/base"):
    """Build a MagicMock config exposing only the attributes SarifResult reads."""
    cfg = MagicMock()
    cfg.base_code_directory = base_dir
    cfg.wasp.id = 7
    cfg.wasp.commit = "deadbeef"
    cfg.wasp.repository.pod = "pod-a"
    cfg.wasp.repository.subpod = "sub-a"
    cfg.wasp.repository.url = "git@github.com:org/repo.git"
    cfg.wasp.repository_id = 99
    return cfg


# ---------------------------------------------------------------------------
# 1. Injected session is preferred over the module-level ``conn``.
# ---------------------------------------------------------------------------
def test_sarif_result_uses_injected_session(empty_sarif_file):
    from libinv.scanners.repository_scanner.sast.SarifResult import SarifResult

    fake_session = MagicMock(name="injected_session")
    source = MagicMock()
    source.value = "semgrep"

    sr = SarifResult(_fake_config(), str(empty_sarif_file), source, session=fake_session)

    # The class stores the caller's session verbatim and `_s` resolves to it.
    assert sr._session is fake_session
    assert sr._s is fake_session


# ---------------------------------------------------------------------------
# 2. Without an injected session, ``_s`` falls back to the legacy ``conn``.
# ---------------------------------------------------------------------------
def test_sarif_result_falls_back_to_conn_when_no_session(empty_sarif_file):
    from libinv.scanners.repository_scanner.sast import SarifResult as sr_mod
    from libinv.scanners.repository_scanner.sast.SarifResult import SarifResult

    sentinel = MagicMock(name="module_conn")
    source = MagicMock()
    source.value = "semgrep"

    with patch.object(sr_mod, "conn", sentinel):
        sr = SarifResult(_fake_config(), str(empty_sarif_file), source)

        assert sr._session is None
        # `_s` is a property; with no injected session it resolves to the
        # patched module-level `conn`.
        assert sr._s is sentinel


# ---------------------------------------------------------------------------
# 3. The SARIF JSON is loaded and exposed at __init__ time.
# ---------------------------------------------------------------------------
def test_sarif_result_loads_json_correctly(one_rule_one_result_sarif):
    from libinv.scanners.repository_scanner.sast.SarifResult import SarifResult

    source = MagicMock()
    sr = SarifResult(
        _fake_config(), str(one_rule_one_result_sarif), source, session=MagicMock()
    )

    # The parsed SARIF is available verbatim under `sarifjson`.
    assert sr.sarifjson["version"] == "2.1.0"
    assert len(sr.sarifjson["runs"][0]["results"]) == 1
    assert sr.sarifjson["runs"][0]["results"][0]["ruleId"] == "libinv.idor.rule-1"

    # `parsesarifmetadata` ran during __init__ and indexed by rule id.
    assert "libinv.idor.rule-1" in sr.rulemetadata
    assert sr.rulemetadata["libinv.idor.rule-1"]["description"] == "demo rule"

    # The default-mode parser is wired even when no per-rule parser exists.
    assert "default" in sr.rulesId_ModeParser
    assert sr.memo_lob_id == {}


# ---------------------------------------------------------------------------
# 4. `add_lob_module` persists a new SastLobMetaData row via the injected session.
# ---------------------------------------------------------------------------
def test_sarif_result_persists_lob_metadata_via_injected_session(
    one_rule_one_result_sarif,
):
    from libinv.scanners.repository_scanner.sast.SarifResult import SarifResult

    fake_session = MagicMock(name="injected_session")
    # No existing row -> .query(...).filter_by(...).first() returns None.
    fake_session.query.return_value.filter_by.return_value.first.return_value = None

    source = MagicMock()
    sr = SarifResult(
        _fake_config(), str(one_rule_one_result_sarif), source, session=fake_session
    )

    sr.add_lob_module()

    # query() was invoked on the injected session (NOT on module-level conn).
    assert fake_session.query.called, "expected query() on the injected session"
    # And because no existing row was found, the code path adds & commits.
    assert fake_session.add.called, "expected add() on the injected session"
    assert fake_session.commit.called, "expected commit() on the injected session"

    # The submodule key was memoised under pod::subpod::ruleId.
    expected_key = "pod-a::sub-a::libinv.idor.rule-1"
    assert expected_key in sr.memo_lob_id


# ---------------------------------------------------------------------------
# 5. Empty `runs[0].results` is a no-op: no DB writes, no crash.
# ---------------------------------------------------------------------------
def test_sarif_result_handles_empty_runs(empty_sarif_file):
    from libinv.scanners.repository_scanner.sast.SarifResult import SarifResult

    fake_session = MagicMock(name="injected_session")
    source = MagicMock()

    sr = SarifResult(
        _fake_config(), str(empty_sarif_file), source, session=fake_session
    )

    # Neither method should touch the DB when the results list is empty.
    sr.add_lob_module()
    sr.add_sarif_result_to_db()

    assert not fake_session.add.called
    assert not fake_session.commit.called
    assert sr.memo_lob_id == {}


# ---------------------------------------------------------------------------
# 6. `add_lob_module` short-circuits on an existing SastLobMetaData row.
# ---------------------------------------------------------------------------
def test_add_lob_module_reuses_existing_row(one_rule_one_result_sarif):
    from libinv.scanners.repository_scanner.sast.SarifResult import SarifResult

    fake_session = MagicMock(name="injected_session")
    existing = MagicMock()
    existing.id = 1234
    fake_session.query.return_value.filter_by.return_value.first.return_value = existing

    source = MagicMock()
    sr = SarifResult(
        _fake_config(), str(one_rule_one_result_sarif), source, session=fake_session
    )

    sr.add_lob_module()

    # Row already exists -> no add/commit, just a memo entry pointing at it.
    fake_session.add.assert_not_called()
    fake_session.commit.assert_not_called()
    assert sr.memo_lob_id["pod-a::sub-a::libinv.idor.rule-1"] == 1234


# ---------------------------------------------------------------------------
# 7. `make_memo_key` is the canonical pod::subpod::module concatenation.
# ---------------------------------------------------------------------------
def test_make_memo_key_format(empty_sarif_file):
    from libinv.scanners.repository_scanner.sast.SarifResult import SarifResult

    sr = SarifResult(
        _fake_config(), str(empty_sarif_file), MagicMock(), session=MagicMock()
    )
    assert sr.make_memo_key("pod", "subpod", "mod") == "pod::subpod::mod"
