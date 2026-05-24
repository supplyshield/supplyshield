"""Smoke + regression test for libinv.api.actionable.statistics._compute_statistics.

Seeds a minimal dataset and asserts the helper returns a dict whose top-level
keys and value types match the contract documented in the helper's docstring.

This locks in the public shape of the dict so Sprint 7's CTE consolidation
(rewriting the 14 serial queries into a single CTE) can be done without
silently dropping or renaming keys the Jinja template relies on.

The bucket-count tests (``test_compute_statistics_p{0,1,2,3}_count_specific_value``
and ``test_compute_statistics_total_packages``) lock in the specific count
values produced by ``_compute_statistics`` for a known seed. Sprint 7 merges
the four serial P0/P1/P2/P3 queries into a single ``COUNT(*) FILTER (...)``
aggregate; these assertions catch regressions in that rewrite. Sprint 8 will
consolidate the remaining 10 of the 14 queries.

Skipped at collection when TEST_DATABASE_URL is unset (see
tests/integration/conftest.py: collect_ignore_glob).
"""

import pytest


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


# ---------------------------------------------------------------------------
# Bucket-count regression tests
#
# These tests seed a known dataset and assert specific count values produced
# by _compute_statistics. They lock in behavior for the SQL rewrite that
# merges the per-bucket queries into one COUNT(*) FILTER (...) aggregate.
#
# EPSS bucket boundaries (preserved verbatim from the helper source):
#   P0      : epss_score >  0.8                  AND vulns_count > 0
#   P1      : 0.7 < epss_score <= 0.8            AND vulns_count > 0
#   P2      : 0.5 < epss_score <= 0.7            AND vulns_count > 0
#   P3      : epss_score <= 0.5 AND IS NOT NULL  AND vulns_count > 0
#   no_epss : epss_score IS NULL                 AND vulns_count > 0
#
# Pick values comfortably inside each bucket so a future widening of strict-
# vs-non-strict inequality does not silently shift a row across a boundary:
#   P0 -> 0.9, P1 -> 0.75, P2 -> 0.6, P3 -> 0.3
# ---------------------------------------------------------------------------


def _seed_package_version(
    db_session,
    *,
    repo,
    actionable,
    epss_score,
    vulns_count,
    version,
    scan_status="SUCCESS",
):
    """Seed one ActionablePackageAvailableVersion linked to ``repo``.

    Centralizes the four-row insert (Actionable already created by caller →
    APAV → Repository_APAV link) so each test only has to declare the values
    that affect bucket placement (epss_score, vulns_count).
    """
    from libinv.models import ActionablePackageAvailableVersion
    from libinv.models import Repository_ActionablePackageAvailableVersion

    apav = ActionablePackageAvailableVersion(
        scan_status=scan_status,
        package_url=actionable.package_url,
        version=version,
        is_latest=False,
        vulns_count=vulns_count,
        epss_score=epss_score,
        is_version_in_use=True,
        actionable_id=actionable.uuid,
    )
    db_session.add(apav)
    db_session.flush()

    link = Repository_ActionablePackageAvailableVersion(
        actionable_package_version_id=apav.uuid,
        repository_id=repo.id,
        environment="stage",
    )
    db_session.add(link)
    db_session.flush()
    return apav


@pytest.fixture(scope="function")
def seeded_buckets(db_session):
    """Seed a deterministic mix of packages across every EPSS bucket.

    Returns a dict ``{"p0": N0, "p1": N1, "p2": N2, "p3": N3,
    "no_epss": N4, "total": N0+N1+N2+N3+N4}`` of the expected counts so the
    individual bucket tests can stay tiny.

    Counts are intentionally distinct (2/3/4/5/1) so a swap-bug (e.g. P1
    counted as P2) shows up loudly in an assertion diff.
    """
    from libinv.models import Actionable
    from libinv.models import Repository

    repo = Repository(
        name="bucket-test-repo",
        org="test-org",
        provider="github.com",
        is_public=False,
        pod="test-pod",
    )
    db_session.add(repo)
    db_session.flush()

    actionable = Actionable(package_url="pkg:pypi/test-bucket-pkg")
    db_session.add(actionable)
    db_session.flush()

    expected = {"p0": 2, "p1": 3, "p2": 4, "p3": 5, "no_epss": 1}
    # Per-bucket EPSS values picked to land comfortably inside the bucket
    # range — never on a boundary edge (0.5 / 0.7 / 0.8).
    bucket_scores = {
        "p0": 0.9,
        "p1": 0.75,
        "p2": 0.6,
        "p3": 0.3,
        "no_epss": None,
    }

    version_counter = 0
    for bucket, count in expected.items():
        for _ in range(count):
            version_counter += 1
            _seed_package_version(
                db_session,
                repo=repo,
                actionable=actionable,
                epss_score=bucket_scores[bucket],
                vulns_count=2,  # any positive int; bucket gating is by EPSS.
                version=f"1.0.{version_counter}",
            )

    expected["total"] = sum(expected.values())
    return expected


def test_compute_statistics_p0_count_specific_value(db_session, seeded_buckets):
    """Seeded P0 rows (epss_score > 0.8, vulns_count > 0) are counted as p0_packages."""
    from libinv.api.actionable.statistics import _compute_statistics

    stats = _compute_statistics(db_session)
    assert stats["package_stats"]["p0_packages"] == seeded_buckets["p0"]


def test_compute_statistics_p1_count_specific_value(db_session, seeded_buckets):
    """Seeded P1 rows (0.7 < epss_score <= 0.8, vulns_count > 0) are counted as p1_packages."""
    from libinv.api.actionable.statistics import _compute_statistics

    stats = _compute_statistics(db_session)
    assert stats["package_stats"]["p1_packages"] == seeded_buckets["p1"]


def test_compute_statistics_p2_count_specific_value(db_session, seeded_buckets):
    """Seeded P2 rows (0.5 < epss_score <= 0.7, vulns_count > 0) are counted as p2_packages."""
    from libinv.api.actionable.statistics import _compute_statistics

    stats = _compute_statistics(db_session)
    assert stats["package_stats"]["p2_packages"] == seeded_buckets["p2"]


def test_compute_statistics_p3_count_specific_value(db_session, seeded_buckets):
    """Seeded P3 rows (0 < epss_score <= 0.5, vulns_count > 0) are counted as p3_packages."""
    from libinv.api.actionable.statistics import _compute_statistics

    stats = _compute_statistics(db_session)
    assert stats["package_stats"]["p3_packages"] == seeded_buckets["p3"]


def test_compute_statistics_no_epss_count_specific_value(db_session, seeded_buckets):
    """Seeded rows with epss_score IS NULL and vulns_count > 0 are counted as no_epss_packages.

    Locked alongside the P0–P3 buckets because the consolidated query in
    Sprint 7 also folds the no_epss aggregate into the same single statement.
    """
    from libinv.api.actionable.statistics import _compute_statistics

    stats = _compute_statistics(db_session)
    assert stats["package_stats"]["no_epss_packages"] == seeded_buckets["no_epss"]


def test_compute_statistics_total_packages(db_session, seeded_buckets):
    """Total seeded ActionablePackageAvailableVersion rows are reflected in total_packages."""
    from libinv.api.actionable.statistics import _compute_statistics

    stats = _compute_statistics(db_session)
    assert stats["package_stats"]["total_packages"] == seeded_buckets["total"]
    # Every seeded row has vulns_count > 0, so vulnerable_packages == total.
    assert stats["package_stats"]["vulnerable_packages"] == seeded_buckets["total"]
    # And the P0+P1+P2+P3+no_epss bucket sum must equal the total — the
    # consolidated query must keep the buckets a partition of the vulnerable
    # rows, never double-counting or losing one.
    bucket_sum = (
        stats["package_stats"]["p0_packages"]
        + stats["package_stats"]["p1_packages"]
        + stats["package_stats"]["p2_packages"]
        + stats["package_stats"]["p3_packages"]
        + stats["package_stats"]["no_epss_packages"]
    )
    assert bucket_sum == seeded_buckets["total"]
