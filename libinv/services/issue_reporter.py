"""GitHub-issue rendering helpers, extracted from Actionable.

Public functions:
- prepare_git_issue_content(result) -> tuple[str, str]: returns (title, markdown_body)
  for an Actionable scan result, suitable for posting/updating a GitHub issue.

Note: This module preserves the exact rendering semantics of the original
`Actionable.prepare_git_issue_content` staticmethod in `libinv/models.py`,
including any URL path inconsistencies between the priority sections.
"""

from __future__ import annotations

from typing import Any
from typing import Dict
from typing import List
from typing import Tuple

from packageurl import PackageURL

from libinv.env import LIBINV_SERVER


_TABLE_HEADER = (
    "| Package | Current Version | Suggested Versions |\n"
    "|-------------|----------------|--------------------|\n"
)


def _render_actionable_table(
    action_items: List[Dict[str, Any]],
    url_path: str,
) -> str:
    """Render the rows of a Package / Current Version / Suggested Versions table.

    :param action_items: list of action-item dicts (each has
        ``versionless_id``, ``current_version``, ``suggested_versions``,
        ``full_package_url``).
    :param url_path: relative path under ``LIBINV_SERVER`` used to build the
        ``versions_url`` link target for the suggested-versions cell. The
        original code uses ``actionable/v3/package_scan`` for the P0 and
        all-issues sections, and ``actionable/package_scan`` for the
        other-priority section when P0 issues are also present; callers
        pass the same value through to preserve behaviour.
    :return: markdown table body (rows only — header is added by the caller).
    """
    rows = ""
    for action_item in action_items:
        versions_url = (
            f"{LIBINV_SERVER}/{url_path}?actionable_id={action_item['versionless_id']}"
            f"&version_in_use={action_item['current_version']}"
        )
        suggested_versions = action_item["suggested_versions"]
        package_name = PackageURL.from_string(action_item['full_package_url']).name
        if not suggested_versions:
            suggested_versions = "\U0001f50d"
        else:
            suggested_versions = ", ".join(suggested_versions)
        rows += (
            f"| {package_name} "
            f"| {action_item['current_version']} "
            f"| [{suggested_versions}]({versions_url}) |\n"
        )
    return rows


def prepare_git_issue_content(result: Dict[str, Any]) -> Tuple[str, str]:
    """Render the title and markdown body for an Actionable's GitHub issue.

    Mirrors ``Actionable.prepare_git_issue_content`` — returns a
    ``(title, message)`` tuple ready to be passed to ``repo.vcs.create_issue``
    / ``repo.vcs.update_issue``.
    """
    title = "[Security] Immediate package upgrades required"
    msg = """\
### Following are the packages that require an update

<details>
  <summary><strong>FAQ's</strong></summary>

  <pre><code>
1. Why do we need to upgrade these packages?

   The following packages have introduced vulnerabilities in our codebase—either directly or through their dependencies.
   They are listed below in order of priority.

2. The suggested version upgrades could break the service. What should we do?

   You can click on the suggested version values to open the SupplyShield page. There, you'll find the full list of
   available versions and can manually trigger a vulnerability scan before upgrading.

3. I can't find any vulnerabilities in the given package. Doesn't that mean it's safe?

   Our scans also check transitive (child) dependencies. Even if the package itself appears clean, it may be using
   another package with known vulnerabilities.
  </code></pre>
</details>

"""
    sorted_result = sorted(
        result["results"], key=lambda x: x["current_version_score"], reverse=True
    )

    # Separate P0 issues (epss_score > 0.8) from other issues
    p0_issues = []
    other_issues = []

    for action_item in sorted_result:
        epss_score = action_item.get("current_version_score")
        if epss_score is not None and epss_score > 0.8:
            p0_issues.append(action_item)
        else:
            other_issues.append(action_item)

    # Add P0 issues table if any exist
    if p0_issues:
        msg += "### \U0001f6a8 Critical Priority (P0)\n\n"
        msg += _TABLE_HEADER
        msg += _render_actionable_table(p0_issues, "actionable/v3/package_scan")
        msg += "\n"

    if other_issues:
        if p0_issues:
            msg += "<details>\n"
            msg += "  <summary><strong>Other Priority Issues (P1/P2/P3)</strong></summary>\n\n"
            msg += _TABLE_HEADER
            msg += _render_actionable_table(other_issues, "actionable/package_scan")
            msg += "\n</details>\n\n"
        else:
            msg += "### All issues\n\n"
            msg += _TABLE_HEADER
            msg += _render_actionable_table(other_issues, "actionable/v3/package_scan")
            msg += "\n"

    if result["commit_id"]:
        msg += f"\n**Commit ID:** `{result['commit_id']}`\n"
    if result["jenkins_url"]:
        msg += f"**Jenkins URL:** {result['jenkins_url']}\n"
    return title, msg
