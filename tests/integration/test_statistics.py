"""Smoke + regression test for libinv.api.actionable.statistics._compute_statistics.

Seeds a minimal dataset and asserts the helper returns a dict whose top-level
keys and value types match the contract documented in the helper's docstring.

This locks in the public shape of the dict so Sprint 7's CTE consolidation
(rewriting the 14 serial queries into a single CTE) can be done without
silently dropping or renaming keys the Jinja template relies on.

Skipped at collection when TEST_DATABASE_URL is unset (see
tests/integration/conftest.py: collect_ignore_glob).
"""


# Top-level keys the helper must always return — every one is referenced by
# libinv/api/templates/statistics.html. Keep this list in sync with that
# template.
EXPECTED_TOP_LEVEL_KEYS = {
    "package_stats",
    "vulnerability_stats",
    "repository_stats",
    "environment_stats",
    "pod_stats",
    "organization_stats",
}

# Keys inside statistics["package_stats"] — referenced as
# statistics.package_stats.* in the template.
EXPECTED_PACKAGE_STATS_KEYS = {
    "total_packages",
    "vulnerable_packages",
    "packages_without_vulnerabilities",
    "packages_with_epss",
    "vulnerability_percentage",
    "epss_coverage_percentage",
    "p0_packages",
    "p1_packages",
    "p2_packages",
    "p3_packages",
    "no_epss_packages",
}

# Keys inside statistics["repository_stats"] — referenced as
# statistics.repository_stats.* in the template.
EXPECTED_REPOSITORY_STATS_KEYS = {
    "total_repositories",
    "repositories_with_vulnerabilities",
    "repositories_without_vulnerabilities",
    "vulnerability_percentage",
    "p0_repositories",
    "p1_repositories",
    "p2_repositories",
    "p3_repositories",
    "no_epss_repositories",
}

# Keys inside statistics["vulnerability_stats"].
EXPECTED_VULNERABILITY_STATS_KEYS = {
    "total_vulnerabilities",
    "critical_vulnerabilities",
    "high_vulnerabilities",
    "medium_vulnerabilities",
    "low_vulnerabilities",
    "avg_vulns_per_vulnerable_package",
}


def test_compute_statistics_empty_db_returns_full_contract(db_session):
    """On an empty schema, helper still returns the full keyset with zero counts."""
    from libinv.api.actionable.statistics import _compute_statistics

    stats = _compute_statistics(db_session)

    # Top-level shape.
    assert isinstance(stats, dict)
    missing = EXPECTED_TOP_LEVEL_KEYS - stats.keys()
    assert not missing, f"helper missing expected top-level keys: {missing}"

    # Nested dict shapes.
    assert isinstance(stats["package_stats"], dict)
    assert isinstance(stats["vulnerability_stats"], dict)
    assert isinstance(stats["repository_stats"], dict)

    missing_pkg = EXPECTED_PACKAGE_STATS_KEYS - stats["package_stats"].keys()
    assert not missing_pkg, f"package_stats missing keys: {missing_pkg}"

    missing_repo = EXPECTED_REPOSITORY_STATS_KEYS - stats["repository_stats"].keys()
    assert not missing_repo, f"repository_stats missing keys: {missing_repo}"

    missing_vuln = (
        EXPECTED_VULNERABILITY_STATS_KEYS - stats["vulnerability_stats"].keys()
    )
    assert not missing_vuln, f"vulnerability_stats missing keys: {missing_vuln}"

    # List shapes.
    assert isinstance(stats["environment_stats"], list)
    assert isinstance(stats["pod_stats"], list)
    assert isinstance(stats["organization_stats"], list)

    # On an empty DB every count must be a non-negative int == 0. The two
    # percentage keys and the average ratio are computed with `max(.., 1)` in
    # the denominator (see helper) so they evaluate to 0.0 on an empty DB —
    # accept either int or float for those.
    for key, value in stats["package_stats"].items():
        if key.endswith("_packages") or key in {"total_packages"}:
            assert isinstance(value, int), (
                f"package_stats[{key!r}] is {type(value).__name__}, expected int"
            )
            assert value >= 0, f"package_stats[{key!r}] is negative: {value}"

    for key, value in stats["repository_stats"].items():
        if key.endswith("_repositories") or key in {"total_repositories"}:
            assert isinstance(value, int), (
                f"repository_stats[{key!r}] is {type(value).__name__}, expected int"
            )
            assert value >= 0, f"repository_stats[{key!r}] is negative: {value}"

    for key, value in stats["vulnerability_stats"].items():
        if key.endswith("_vulnerabilities"):
            assert isinstance(value, int), (
                f"vulnerability_stats[{key!r}] is {type(value).__name__}, expected int"
            )
            assert value >= 0, (
                f"vulnerability_stats[{key!r}] is negative: {value}"
            )


def test_compute_statistics_zero_counts_on_empty_repository(db_session):
    """Seeding a Repository with no actionable packages keeps all counts at 0."""
    from libinv.api.actionable.statistics import _compute_statistics
    from libinv.models import Repository

    repo = Repository(
        name="empty-test-repo",
        org="test-org",
        provider="github.com",
        is_public=False,
    )
    db_session.add(repo)
    db_session.flush()

    stats = _compute_statistics(db_session)

    # The seeded repository must be visible in the repository count.
    assert stats["repository_stats"]["total_repositories"] >= 1

    # But every vulnerable / EPSS-priority bucket must remain 0 because no
    # ActionablePackageAvailableVersion rows were seeded.
    assert stats["package_stats"]["total_packages"] == 0
    assert stats["package_stats"]["vulnerable_packages"] == 0
    assert stats["package_stats"]["p0_packages"] == 0
    assert stats["package_stats"]["p1_packages"] == 0
    assert stats["package_stats"]["p2_packages"] == 0
    assert stats["package_stats"]["p3_packages"] == 0
    assert stats["package_stats"]["no_epss_packages"] == 0
    assert stats["repository_stats"]["repositories_with_vulnerabilities"] == 0
    assert stats["repository_stats"]["p0_repositories"] == 0
    assert stats["repository_stats"]["p1_repositories"] == 0
    assert stats["repository_stats"]["p2_repositories"] == 0
    assert stats["repository_stats"]["p3_repositories"] == 0
    assert stats["vulnerability_stats"]["total_vulnerabilities"] == 0

    # pod_stats / environment_stats are derived from the join table, so an
    # empty repository contributes nothing to either.
    assert stats["pod_stats"] == []
    # organization_stats groups by org, so the seeded repo should show up:
    orgs = {row["organization"] for row in stats["organization_stats"]}
    assert "test-org" in orgs
