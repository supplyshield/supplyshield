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
# 2. Sprint 48.1: SarifResult now requires a keyword-only ``session`` —
#    constructor without one raises TypeError.
# ---------------------------------------------------------------------------
def test_sarif_result_requires_session_keyword(empty_sarif_file):
    from libinv.scanners.repository_scanner.sast.SarifResult import SarifResult

    source = MagicMock()
    source.value = "semgrep"

    with pytest.raises(TypeError):
        SarifResult(_fake_config(), str(empty_sarif_file), source)


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


# ---------------------------------------------------------------------------
# 8. Sprint 28 - __init__ uses `with open(...)` (no fd leak).
# ---------------------------------------------------------------------------
def test_sarif_result_closes_file_handle(empty_sarif_file):
    """The SARIF file handle must be closed after __init__.

    Verifies the ``with open(...)`` context-manager protocol is used so a
    long-running scanner cannot exhaust file descriptors. Uses a patched
    ``builtins.open`` to inspect the file object's ``__exit__`` is invoked,
    and follows up with a smoke test that 100 instantiations do not raise.
    """
    from libinv.scanners.repository_scanner.sast.SarifResult import SarifResult

    real_open = open
    opened_files = []

    def tracking_open(*args, **kwargs):
        fh = real_open(*args, **kwargs)
        opened_files.append(fh)
        return fh

    source = MagicMock()
    with patch("builtins.open", side_effect=tracking_open):
        SarifResult(
            _fake_config(), str(empty_sarif_file), source, session=MagicMock()
        )

    # The handle opened inside __init__ must be closed after the ``with``.
    assert opened_files, "expected SarifResult.__init__ to open the sarif file"
    assert all(
        fh.closed for fh in opened_files
    ), "SarifResult.__init__ leaked a file descriptor"

    # Smoke test: 100 sequential instantiations must not exhaust fds.
    instances = []
    try:
        for _ in range(100):
            instances.append(
                SarifResult(
                    _fake_config(),
                    str(empty_sarif_file),
                    source,
                    session=MagicMock(),
                )
            )
    except OSError:
        pytest.fail("file-descriptor leak in SarifResult.__init__")


# ---------------------------------------------------------------------------
# 9. Sprint 28 - record.extras as a JSON string is parsed correctly.
# ---------------------------------------------------------------------------
def test_add_sarif_result_handles_string_extras(one_rule_one_result_sarif):
    """``add_sarif_result_to_db`` must use ``json.loads`` on stringified extras.

    The DB stores ``SastResult.extras`` as a Text column, so the row comes
    back as a JSON string. ``json.load`` (file-like) raises AttributeError
    on strings; ``json.loads`` is correct. The fix wraps the call in an
    ``isinstance(record.extras, str)`` guard so already-parsed dicts pass
    through untouched.
    """
    from libinv.scanners.repository_scanner.sast.SarifResult import SarifResult

    fake_session = MagicMock(name="injected_session")

    # Existing record whose extras came back from the DB as a JSON string,
    # AND whose public_endpoints matches the new extras so the comparison
    # short-circuits (we only want to exercise the json.loads path).
    record_mock = MagicMock()
    record_mock.validated = "NOTVALIDATED-other"  # not the "validated" sentinel
    record_mock.extras = '{"public_endpoints": {}}'
    fake_session.query.return_value.filter_by.return_value.first.return_value = (
        record_mock
    )

    source = MagicMock()
    source.value = "semgrep"

    sr = SarifResult(
        _fake_config(),
        str(one_rule_one_result_sarif),
        source,
        session=fake_session,
    )

    # Force the validation check to enter the "not yet validated" branch and
    # also force module.get_publicpaths_priority to return empty public_paths
    # so the comparison hits the equal-endpoints short-circuit.
    from libinv.scanners.repository_scanner.sast.enums.ValidEnum import ValidEnum

    record_mock.validated = ValidEnum.NOTVALIDATED.value

    fake_module = MagicMock()
    fake_module.get_vuln_paths.return_value = []
    fake_module.get_publicpaths_priority.return_value = (MagicMock(value="MEDIUM"), {})
    sr.rulesId_ModeParser["default"] = fake_module
    sr.memo_lob_id["pod-a::sub-a::libinv.idor.rule-1"] = 1

    sr.add_sarif_result_to_db()

    # The string was parsed into a dict by json.loads (NOT json.load, which
    # would have raised AttributeError on the string).
    assert isinstance(record_mock.extras, dict)
    assert record_mock.extras == {"public_endpoints": {}}


# ---------------------------------------------------------------------------
# 10. Sprint 28 - SARIF without `rules` array doesn't crash.
# ---------------------------------------------------------------------------
def test_parsesarifmetadata_handles_missing_rules(tmp_path):
    """parsesarifmetadata must tolerate a tool/driver with no `rules` key.

    Semgrep with ``--severity`` filters can emit SARIF where the driver
    section omits ``rules`` entirely. The previous KeyError would crash
    every scan on such tools.
    """
    from libinv.scanners.repository_scanner.sast.SarifResult import SarifResult

    sarif = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {"driver": {"name": "semgrep"}},  # no `rules` key
                "results": [],
            }
        ],
    }
    sarif_path = tmp_path / "no_rules.sarif"
    sarif_path.write_text(json.dumps(sarif))

    source = MagicMock()
    # Must not crash with KeyError.
    sr = SarifResult(_fake_config(), str(sarif_path), source, session=MagicMock())

    # parsesarifmetadata returned an empty index instead of raising.
    assert sr.rulemetadata == {}


# ---------------------------------------------------------------------------
# 11. Sprint 29 - unknown ruleId in results doesn't crash mid-iteration.
# ---------------------------------------------------------------------------
def test_add_sarif_result_handles_unknown_rule_id(tmp_path):
    """Sprint 29 - a SARIF result referencing a ruleId not in
    rulemetadata should NOT crash mid-iteration.

    When the SARIF tool omits the ``rules`` array (Sprint 28 made that
    branch yield an empty ``rulemetadata`` instead of raising), the
    subsequent ``add_sarif_result_to_db`` loop must still process every
    result row. The previous ``self.rulemetadata[ruleid]`` subscript
    raised ``KeyError`` on the first such row, dropping every later
    finding in the run.
    """
    from libinv.scanners.repository_scanner.sast.SarifResult import SarifResult
    from libinv.scanners.repository_scanner.sast.enums.ValidEnum import ValidEnum

    sarif = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {"driver": {"name": "semgrep"}},  # no `rules` key
                "results": [
                    {
                        "level": "error",
                        "ruleId": "rule-unknown",  # not in rulemetadata
                        "message": {"text": "vuln found"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {
                                        "uri": "/base/app/foo.py"
                                    },
                                    "region": {
                                        "startLine": 42,
                                        "snippet": {
                                            "text": "do_thing(user_input)"
                                        },
                                    },
                                }
                            }
                        ],
                    },
                ],
            }
        ],
    }
    sarif_path = tmp_path / "unknown_rule.sarif"
    sarif_path.write_text(json.dumps(sarif))

    fake_session = MagicMock(name="injected_session")
    # No existing SastResult row -> insert path.
    fake_session.query.return_value.filter_by.return_value.first.return_value = None

    source = MagicMock()
    source.value = "semgrep"

    sr = SarifResult(
        _fake_config(), str(sarif_path), source, session=fake_session
    )

    # rulemetadata is empty (no `rules` key) - the previous code raised
    # KeyError on the first result row's ruleId subscript.
    assert sr.rulemetadata == {}

    # Pre-populate the memo so the insert branch can resolve lob_id without
    # going through add_lob_module (which is exercised in its own tests).
    sr.memo_lob_id["pod-a::sub-a::rule-unknown"] = 1

    # Force the default mode to return predictable values so the insert
    # branch in add_sarif_result_to_db doesn't depend on real semgrep logic.
    fake_module = MagicMock()
    fake_module.get_vuln_paths.return_value = []
    fake_module.get_publicpaths_priority.return_value = (
        MagicMock(value="MEDIUM"),
        {},
    )
    sr.rulesId_ModeParser["default"] = fake_module

    # MUST NOT raise KeyError - the fix is `self.rulemetadata.get(ruleid, {})`.
    sr.add_sarif_result_to_db()

    # The finding was still persisted using default (empty) metadata.
    assert fake_session.add.called, (
        "expected SastResult.add() even when ruleId is absent from rulemetadata"
    )
    assert fake_session.commit.called, (
        "expected commit() even when ruleId is absent from rulemetadata"
    )

    # And the inserted record carried an empty properties dict (the default),
    # NOT a KeyError fallthrough.
    inserted = fake_session.add.call_args[0][0]
    assert inserted.extras["properties"] == {}
    assert inserted.validated == str(ValidEnum.NOTVALIDATED.value)
