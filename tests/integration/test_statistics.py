"""Smoke + regression test for libinv.api.actionable.statistics._compute_statistics.

Seeds a minimal dataset and asserts the helper returns a dict whose top-level
keys and value types match the contract documented in the helper's docstring.

This locks in the public shape of the dict so Sprint 7's CTE consolidation
(rewriting the 14 serial queries into a single CTE) can be done without
silently dropping or renaming keys the Jinja template relies on.

The bucket-count tests (``test_compute_statistics_p{0,1,2,3}_count_specific_value``
and ``test_compute_statistics_total_packages``) lock in the specific count
values produced by ``_compute_statistics`` for a known seed. Sprint 7 merged
the four serial P0/P1/P2/P3 package queries into a single
``COUNT(*) FILTER (...)`` aggregate; Sprint 8 merged the six serial
repository queries (with_vulns + p0/p1/p2/p3/no_epss) into a single
``COUNT(DISTINCT Repository.id) FILTER (...)`` aggregate. The
``test_compute_statistics_repo_*`` and ``test_compute_statistics_{env,pod}_stats_*``
families lock in the post-consolidation behavior.

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


# ---------------------------------------------------------------------------
# Repository-stats regression tests (Sprint 8)
#
# Sprint 8 consolidated the 5 serial repo bucket queries
# (repo_p0/p1/p2/p3/no_epss_count) AND the repositories_with_vulns query into
# a SINGLE filter-aggregate. These tests seed N repos with distinct severity
# profiles and lock in the per-bucket REPOSITORY counts (not package counts).
# ---------------------------------------------------------------------------


@pytest.fixture(scope="function")
def seeded_repo_buckets(db_session):
    """Seed 2 repos, each owning exactly one package in a distinct EPSS bucket.

    Layout:
        repo_high_priority  → 1 P0 package (epss_score=0.9, vulns_count=2)
        repo_low_priority   → 1 P3 package (epss_score=0.3, vulns_count=2)

    Returns the expected repository_stats counts dict for the assertion side
    to consume. The structure mirrors ``seeded_buckets`` but at the repo
    granularity instead of the package granularity.
    """
    from libinv.models import Actionable
    from libinv.models import Repository

    repo_high = Repository(
        name="repo-high-priority",
        org="test-org",
        provider="github.com",
        is_public=False,
        pod="prio-pod",
    )
    repo_low = Repository(
        name="repo-low-priority",
        org="test-org",
        provider="github.com",
        is_public=False,
        pod="prio-pod",
    )
    db_session.add_all([repo_high, repo_low])
    db_session.flush()

    actionable = Actionable(package_url="pkg:pypi/repo-bucket-pkg")
    db_session.add(actionable)
    db_session.flush()

    # repo_high gets one P0-bucket package version.
    _seed_package_version(
        db_session,
        repo=repo_high,
        actionable=actionable,
        epss_score=0.9,
        vulns_count=2,
        version="1.0.0",
    )
    # repo_low gets one P3-bucket package version (epss <= 0.5, not null).
    _seed_package_version(
        db_session,
        repo=repo_low,
        actionable=actionable,
        epss_score=0.3,
        vulns_count=2,
        version="1.0.1",
    )

    return {
        "repo_p0_expected": 1,
        "repo_p1_expected": 0,
        "repo_p2_expected": 0,
        "repo_p3_expected": 1,
        "repo_no_epss_expected": 0,
        "with_vulns_expected": 2,
        "total_repositories_expected": 2,
    }


def test_compute_statistics_repo_p0_count(db_session, seeded_repo_buckets):
    """A repo with at least one P0 package counts as 1 P0 repository."""
    from libinv.api.actionable.statistics import _compute_statistics

    stats = _compute_statistics(db_session)
    assert (
        stats["repository_stats"]["p0_repositories"]
        == seeded_repo_buckets["repo_p0_expected"]
    )


def test_compute_statistics_repo_p3_count(db_session, seeded_repo_buckets):
    """A repo with at least one P3 package counts as 1 P3 repository."""
    from libinv.api.actionable.statistics import _compute_statistics

    stats = _compute_statistics(db_session)
    assert (
        stats["repository_stats"]["p3_repositories"]
        == seeded_repo_buckets["repo_p3_expected"]
    )


def test_compute_statistics_repo_bucket_partition(db_session, seeded_repo_buckets):
    """Both seeded repos show up in repositories_with_vulnerabilities and total counts.

    Locks in the consolidated repo query: the with_vulns aggregate counts
    distinct repos with ANY vulnerable package, while the per-bucket aggregates
    count distinct repos in each EPSS slice. A repo with one P0 and one P3
    would appear in BOTH p0_repositories and p3_repositories — they're not
    a strict partition, so we don't assert sum-equals-with-vulns here.
    """
    from libinv.api.actionable.statistics import _compute_statistics

    stats = _compute_statistics(db_session)
    assert (
        stats["repository_stats"]["repositories_with_vulnerabilities"]
        == seeded_repo_buckets["with_vulns_expected"]
    )
    # Both seeded repos must be visible in total_repositories. Other tests
    # may seed additional repos at the module scope, so use >=.
    assert (
        stats["repository_stats"]["total_repositories"]
        >= seeded_repo_buckets["total_repositories_expected"]
    )
    # Sanity: with both seeded repos having vulns, repositories_without
    # equals total_repositories - 2.
    assert (
        stats["repository_stats"]["repositories_without_vulnerabilities"]
        == stats["repository_stats"]["total_repositories"]
        - stats["repository_stats"]["repositories_with_vulnerabilities"]
    )


def test_compute_statistics_repo_p1_p2_empty_buckets(db_session, seeded_repo_buckets):
    """Repo buckets that nothing was seeded into stay at 0.

    Exercises the empty-bucket leg of the consolidated FILTER aggregate — a
    bucket with no matching joined row must return 0, not NULL or a copy of
    a neighboring bucket's count (the kind of bug a hand-rolled CTE could hit).
    """
    from libinv.api.actionable.statistics import _compute_statistics

    stats = _compute_statistics(db_session)
    assert stats["repository_stats"]["p1_repositories"] == 0
    assert stats["repository_stats"]["p2_repositories"] == 0
    assert stats["repository_stats"]["no_epss_repositories"] == 0


# ---------------------------------------------------------------------------
# Environment & pod stats regression tests (Sprint 8)
#
# env_stats and pod_stats were already efficient (single GROUP BY queries)
# and were left unchanged by Sprint 8 consolidation. These tests verify
# the existing single-query shape still produces correct output after the
# surrounding query rewrites.
# ---------------------------------------------------------------------------


def test_compute_statistics_env_stats_groups_by_environment(db_session, seeded_buckets):
    """env_stats has one row per environment seeded by _seed_package_version.

    ``_seed_package_version`` hard-codes environment="stage" on every join row,
    so the seeded buckets must surface as a single "stage" entry in env_stats.
    Locks in the shape (list of dicts with environment / repository_count /
    package_count keys) the template iterates over.
    """
    from libinv.api.actionable.statistics import _compute_statistics

    stats = _compute_statistics(db_session)
    env_rows = stats["environment_stats"]
    assert isinstance(env_rows, list)
    assert len(env_rows) >= 1
    stage = next((row for row in env_rows if row["environment"] == "stage"), None)
    assert stage is not None, f"expected env 'stage' in env_stats; got {env_rows}"
    # Shape: every row has these keys.
    assert set(stage.keys()) == {"environment", "repository_count", "package_count"}
    # The seeded_buckets fixture creates one repo and (2+3+4+5+1)=15 packages,
    # all linked to the same "stage" environment.
    assert stage["repository_count"] >= 1
    assert stage["package_count"] >= seeded_buckets["total"]


def test_compute_statistics_pod_stats_groups_by_pod(db_session, seeded_buckets):
    """pod_stats has one row per Repository.pod with bucketed vuln counts.

    The seeded_buckets fixture sets pod="test-pod" on its repo, so the
    seeded counts must surface under that pod. Verifies the GROUP BY query
    in pod_stats_query still partitions counts by pod after the surrounding
    consolidation, and that the per-bucket FILTER aggregates inside that
    query return the same numbers the package-level fixture set up.
    """
    from libinv.api.actionable.statistics import _compute_statistics

    stats = _compute_statistics(db_session)
    pods = stats["pod_stats"]
    assert isinstance(pods, list)
    test_pod = next((row for row in pods if row["pod"] == "test-pod"), None)
    assert test_pod is not None, f"expected pod 'test-pod' in pod_stats; got {pods}"
    # Shape: every row has these keys.
    assert set(test_pod.keys()) == {
        "pod",
        "vulnerable_packages",
        "p0",
        "p1",
        "p2",
        "p3",
    }
    # The seeded_buckets fixture puts known counts into each bucket — pod_stats
    # uses COUNT(DISTINCT package), and all seeded rows have distinct uuids, so
    # the pod row's per-bucket counts equal the package-level seeded counts.
    assert test_pod["p0"] == seeded_buckets["p0"]
    assert test_pod["p1"] == seeded_buckets["p1"]
    assert test_pod["p2"] == seeded_buckets["p2"]
    assert test_pod["p3"] == seeded_buckets["p3"]
    # vulnerable_packages = total packages with vulns_count > 0 (all seeded).
    assert test_pod["vulnerable_packages"] == seeded_buckets["total"]
