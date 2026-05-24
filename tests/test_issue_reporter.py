"""Unit tests for libinv.services.issue_reporter.prepare_git_issue_content."""

import pytest

from libinv.services.issue_reporter import _TABLE_HEADER
from libinv.services.issue_reporter import prepare_git_issue_content


def _row(versionless_id, current_version, suggested_versions, package_url, epss):
    return {
        "versionless_id": versionless_id,
        "current_version": current_version,
        "suggested_versions": list(suggested_versions),
        "full_package_url": package_url,
        "current_version_score": epss,
    }


def _result(rows, commit_id="abc123", jenkins_url="http://jenkins/job/1"):
    return {"results": list(rows), "commit_id": commit_id, "jenkins_url": jenkins_url}


# ---------------------------------------------------------------------------
def test_empty_results_returns_base_no_tables():
    title, body = prepare_git_issue_content(
        _result([], commit_id="", jenkins_url="")
    )
    assert title == "[Security] Immediate package upgrades required"
    # FAQ block always present
    assert "FAQ's" in body
    # No table header rendered
    assert _TABLE_HEADER not in body
    # No P0 or All-issues sections
    assert "Critical Priority" not in body
    assert "All issues" not in body
    # No commit/jenkins blocks because we passed empty strings
    assert "Commit ID" not in body
    assert "Jenkins URL" not in body


# ---------------------------------------------------------------------------
def test_only_p0_renders_critical_section_no_other():
    rows = [
        _row("p1", "1.0.0", ["1.0.1"], "pkg:pypi/django@1.0.0", 0.95),
        _row("p2", "2.0.0", ["2.0.1"], "pkg:pypi/lxml@2.0.0", 0.9),
    ]
    _, body = prepare_git_issue_content(_result(rows))
    assert "Critical Priority (P0)" in body
    assert "Other Priority" not in body
    assert "All issues" not in body
    assert _TABLE_HEADER in body
    assert "django" in body and "lxml" in body


# ---------------------------------------------------------------------------
def test_only_other_renders_all_issues_section():
    rows = [
        _row("p1", "1.0.0", ["1.1.0"], "pkg:pypi/django@1.0.0", 0.3),
        _row("p2", "2.0.0", ["2.1.0"], "pkg:pypi/lxml@2.0.0", 0.5),
    ]
    _, body = prepare_git_issue_content(_result(rows))
    assert "All issues" in body
    assert "Critical Priority" not in body
    assert "Other Priority" not in body
    # Other-only path uses the v3 URL prefix.
    assert "actionable/v3/package_scan" in body


# ---------------------------------------------------------------------------
def test_mixed_renders_both_and_wraps_other_in_details():
    rows = [
        _row("p1", "1.0.0", ["1.0.1"], "pkg:pypi/django@1.0.0", 0.95),  # P0
        _row("p2", "2.0.0", ["2.1.0"], "pkg:pypi/lxml@2.0.0", 0.3),  # other
    ]
    _, body = prepare_git_issue_content(_result(rows))
    assert "Critical Priority (P0)" in body
    # The "Other Priority" section must be wrapped in <details>.
    assert "<details>" in body
    assert "Other Priority Issues" in body
    # Verify that the Other-Priority `<details>` block contains lxml (the
    # non-P0 row), not django.
    details_idx = body.index("Other Priority Issues")
    closing_idx = body.index("</details>", details_idx)
    other_block = body[details_idx:closing_idx]
    assert "lxml" in other_block
    assert "django" not in other_block


# ---------------------------------------------------------------------------
def test_commit_id_and_jenkins_url_appended_when_present():
    _, body = prepare_git_issue_content(
        _result(
            [_row("p1", "1.0", ["1.1"], "pkg:pypi/foo@1.0", 0.1)],
            commit_id="deadbeef",
            jenkins_url="http://j/x",
        )
    )
    assert "**Commit ID:** `deadbeef`" in body
    assert "**Jenkins URL:** http://j/x" in body


@pytest.mark.parametrize("commit_id, jenkins_url", [(None, None), ("", ""), (None, "")])
def test_commit_id_and_jenkins_url_omitted_when_falsy(commit_id, jenkins_url):
    _, body = prepare_git_issue_content(
        _result(
            [_row("p1", "1.0", ["1.1"], "pkg:pypi/foo@1.0", 0.1)],
            commit_id=commit_id,
            jenkins_url=jenkins_url,
        )
    )
    assert "Commit ID" not in body
    assert "Jenkins URL" not in body


# ---------------------------------------------------------------------------
def test_empty_suggested_versions_renders_magnifying_glass_emoji():
    rows = [_row("p1", "1.0", [], "pkg:pypi/foo@1.0", 0.1)]
    _, body = prepare_git_issue_content(_result(rows))
    # Literal magnifying-glass character (U+1F50D).
    assert "\U0001f50d" in body


# ---------------------------------------------------------------------------
def test_table_header_matches_constant_exactly():
    expected = (
        "| Package | Current Version | Suggested Versions |\n"
        "|-------------|----------------|--------------------|\n"
    )
    assert _TABLE_HEADER == expected
    rows = [_row("p1", "1.0", ["1.1"], "pkg:pypi/foo@1.0", 0.1)]
    _, body = prepare_git_issue_content(_result(rows))
    assert expected in body
