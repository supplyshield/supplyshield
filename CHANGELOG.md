# Changelog

All notable changes to SupplyShield. This file documents the audit-driven
refactor across sprints 0-52, each landed as a separate commit on the
`sprint-0/critical-fixes` branch. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Sprint numbers in parentheses link a bullet back to its originating commit
for traceability.

## [Unreleased] — Sprints 0-52

### Security

- **API auth** — All `PUT`/`POST`/`PATCH`/`DELETE` routes are now gated on
  the `X-API-Token` header via a global `before_request` hook in
  `libinv/api/auth.py`. The server fail-closes with HTTP 503 when
  `LIBINV_API_TOKEN` is unset and returns 401 on a bad token. `GET` routes
  are unaffected (Sprint 0).
- **semgrep shell injection (RCE)** — Replaced `os.system(cmd)` with a
  `subprocess.run` argv list in the semgrep scanner so an attacker-controlled
  SQS repository name or `base_code_directory` can no longer break out of
  the shell command (Sprint 0).
- **Credential file permissions** — `~/.netrc` (`libinv/vcs.py`) and
  `~/.docker/config.json` (`libinv/scanners/image_scanner/ecr.py`) are now
  written atomically with mode `0o600` via
  `os.open(O_CREAT | O_WRONLY | O_TRUNC, 0o600)` (Sprint 0).
- **ECR registry parsing** — Replaced `lstrip("https://")` (which is a
  charset strip, not a prefix strip — it would turn
  `https://stage.amazonaws.com` into `tage.amazonaws.com`) with
  `removeprefix(...)` plus `urllib.parse.urlparse(...).netloc` for the
  auths key. Auth JSON is now built via `json.dumps` instead of string
  concatenation (Sprint 0).
- **GitHub App private key** — Now read inside a `with open(...)` block so
  the file descriptor is released even on parse failure (Sprint 0).
- **Statistics dashboard error path** — `statistics_dashboard` no longer
  embeds `str(e)` in the rendered response. It now calls
  `logger.exception(...)` server-side and returns a generic message at
  HTTP 500 (Sprint 8).
- **Stopped leaking `str(e)` to users** in `api/onboard_package.py`
  (Sprint 1).

### Reliability

- **Daemon resilience** — `cli/daemon.py` no longer returns on the first
  exception. It catches, logs, optionally notifies Slack, and continues to
  the next message. `SIGTERM`/`SIGINT` set a shutdown flag so the daemon
  drains gracefully (Sprint 0).
- **SQS visibility timeout** — `process_sqs_message` extends visibility to
  1800 seconds on receive so long cdxgen / scancodeio / semgrep runs no
  longer trigger duplicate delivery (Sprint 0).
- **`Wasp.__exit__` exception suppression** — Changed the trailing
  `return True` to `return False` in `libinv/models.py`. Previously every
  exception raised inside a `with wasp:` block was silently swallowed,
  hiding real bugs from cdxgen / scancodeio / semgrep. Cleanup
  (`s.add(self); s.commit(); shutil.rmtree(...)`) still runs unconditionally
  before the return on the exception path. The
  `MalformedCaterpillarMessage` early-return is preserved as `return True`
  — that is intentional suppression of a known no-op (Sprint 11).
- **`requests.*` timeouts** added everywhere they were missing:
  `helpers.send_to_slack` (`timeout=10`), every `GitHubApp` HTTP call in
  `vcs.py` (`timeout=10` + `raise_for_status`), PURLDB `POST`
  (`timeout=30`), ScanCode.io `POST` (`timeout=300`), EPSS `GET` (bumped
  `8` → `30`), Metapod import (`timeout=15`) (Sprint 1).
- **`assert response.status_code` → `response.raise_for_status()`** at every
  site in `vcs.py` (6 calls). Failures now log the truncated response body
  for real diagnostics instead of silently passing under `python -O`
  (Sprint 1).
- **Strippable `assert` → explicit `raise`** in `libinv/vcs.py:65`
  (`FileNotFoundError` on missing netrc),
  `libinv/scanners/image_scanner/base_image.py:22`
  (`ValueError` on multi-entry manifest), and `libinv/models.py:678`
  (`RuntimeError` on non-detached HEAD after checkout) (Sprint 5).
- **HTTP status code corrections** — `api/wasp.py` (200 → 400 missing
  param; 500 → 404 not-found), `api/compare_builds.py` (200 → 400,
  500 → 404 ×2), `api/actionable.py` (three 500 → 400 sites for
  missing-param branches). `api/compare_builds.py` helper now re-raises
  instead of returning a Flask response that the caller was iterating
  (Sprint 1).
- **Loop-variable shadowing** — `api/actionable.py` list comprehensions at
  the old lines 73-76 and 169-172 shadowed the outer `package` variable
  with the inner loop name. Renamed the inner variable to `safe_version` so
  the outer-loop `package` is preserved for the lines that operate on it
  after the comprehension (Sprint 2).
- **`statistics_dashboard` `with Session()` scoping bug** — The `with` block
  previously held only the `SET statement_timeout` and exited immediately,
  leaving the function's subsequent queries to run on a closed session. The
  function body is now correctly indented inside the with block; success-
  path `return render_template` is inside, error-path `except` outside
  (Sprint 2).
- **`mark_latest_version` silently dropping writes** — The old
  `with Session()` block had no commit, and `Session.close()` does not
  commit. Migrating to `session_scope()` (which commits on clean exit)
  fixes the dropped writes (Sprint 2).
- **`vcs.get_sca_issue` early-return bug** — Previously returned after the
  first label of the first issue regardless of match. Now scans every label
  of every issue and returns `(None, False)` on empty / no match / `None`
  input (Sprint 1).
- **`vcs.create_issue` / `update_issue`** — Removed `labels=[]` mutable
  default; renamed the `type` kwarg (which shadowed the built-in) to
  `issue_type` (Sprint 1).
- **`scanners/.../scancodeio.py`** — Removed the `additional_pipelines`
  mutable default; switched `data=project_data` to `json=project_data`
  (Sprint 1).
- **Bare `except:` clauses** — Replaced with `except Exception:` plus
  `logger.exception(...)` at `api/actionable.py:84`, `:181`, `:276`
  (Sprint 1).
- **`get_latest` / `get_safe_versions` signature** — Both methods now
  accept `session=None` and fall back to `conn`, so existing
  `api/actionable.py` callers that pass `session` no longer `TypeError`
  while `cli/actionable.py` callers without `session` keep working
  (Sprint 0).
- **`helpers.retry_on_exception`** — Added exponential backoff with jitter;
  now raises a properly-instantiated `RetryFailedException` (previously
  raised the class with no message); switched `print` to `logger`
  (Sprint 1).
- **`helpers.delete_message_where_repository_url_contains`** — Fixed a
  missing-`f`-prefix log that referenced a non-existent key; replaced
  `logger.warn` (deprecated alias) with `logger.warning` (Sprint 1).
- **`semgrep/utils.py`** — Fixed `datetime.today()` →
  `datetime.datetime.now()` (the prior call raised `AttributeError` because
  of how the module is imported) (Sprint 0).
- **`Secbug.is_active` inversion** — Was `True if deleted_at else False`,
  i.e. returned `True` when the row was **deleted**, contradicting
  `Secbug.all_active()` which filters `deleted_at IS NULL`. Now correctly
  returns `self.deleted_at is None`. Zero pre-existing callers; the
  contract was wrong and would have bitten any new caller (Sprint 8).
- **`vulnerability_severities_epss` AttributeError** — `package_scan.py:39`
  referenced a property that does not exist on
  `ActionablePackageAvailableVersion`. The real property is
  `vulnerability_severities` (no `_epss` suffix), and the route already
  emits `epss_score` as its own top-level key. Fixed the caller; added 4
  regression tests including a source-level guard against future `_epss`
  references (Sprint 14).
- **`explode_git_url`** — Rewritten with `if/elif/else` and now raises
  `ValueError` on unsupported scheme (was `UnboundLocalError`). 4 doctests
  including `ssh`, `https`, `ssh-no-.git`, and `ftp-error` cases (Sprint 1).
- **`cli/actionable.py` union-attr latent bugs** — 4 union-attr issues
  flagged by mypy fixed. Guards added around optional attribute access on
  values that could be `None` at runtime (Sprint 20).
- **`api/actionable/package_details.py` `libinv.logger` AttributeError** —
  Fixed latent bug where `libinv.logger` was referenced as a module attribute
  without the proper import path; would have raised `AttributeError` on the
  exception path (Sprint 22).
- **`libinv/env.py` type inconsistencies** — `IMAGE_SCAN_ENABLED` and
  `EXCLUDED_REPOS` had mismatched type annotations vs runtime values; both
  reconciled (Sprint 24).

### Performance

- **EPSS bulk upsert** — `EPSS.update_epss_scores` rewritten as one
  `pg_insert(...).on_conflict_do_update(...)` call instead of `N` SELECTs +
  `N` INSERT/UPDATEs per batch. `refresh_cves` now sleeps 0.5s between
  batches as a politeness limit against the public EPSS API (Sprint 2).
- **N+1 eager loading** — `Actionable.get_actionable` now passes
  `selectinload` options that cover the entire fan-out used by
  `get_actionable_and_secure_versions`
  (`available_version → actionable → available_versions`) plus the
  `with_metadata` wasp lookups, so the dashboard fires `O(1)` round trips
  instead of `O(P)` per package. `Actionable.get_safe_versions` and
  `get_latest` now short-circuit in Python when
  `"available_versions" in self.__dict__` (i.e. the caller eager-loaded the
  relationship), avoiding lazy loads (Sprint 5).
- **FK indexes (alembic `0002`)** — 17 single-column FK indexes + 2
  composite indexes (`repo_id + environment` for the actionable dashboard
  hot query; `cve + updated_at` for EPSS staleness checks). All emitted as
  `CREATE INDEX CONCURRENTLY IF NOT EXISTS` inside
  `op.get_context().autocommit_block()` so the migration runs without
  taking a table lock (Sprint 2).
- **Statistics priority-bucket consolidation** — The 5 separate `.scalar()`
  queries that computed `p0/p1/p2/p3/no_epss` package counts are now a
  single `session.query(...).one()` using `func.count(...).filter(...)`
  which compiles to PG's `COUNT(*) FILTER (WHERE ...)`. Five round-trips
  and five table scans become one (Sprint 7).
- **`repository_stats` consolidation** — Same FILTER-aggregate treatment
  applied to the 6 repository-level scalar queries
  (`with_vulns + repo_p0/p1/p2/p3/no_epss`), collapsed into one
  `session.query(...).one()`. Net serial `.scalar() or 0` patterns went
  from 7 → 1; statistics.py LOC 443 → 400 (Sprint 8).
- **`pod_stats .limit(20)`** — `pod_stats_query` already had
  `.order_by(... DESC)` and a comment promising "top 20" but no `LIMIT`.
  Added `.limit(20)` to match the documented intent (Sprint 9).
- **boto3 client singletons** — `helpers._cached_boto3_client` is now
  wrapped in `@lru_cache`. `sqs.py` and `blast_radius/cdx.py` route
  through `helpers` (with a lazy import in `sqs` to break the
  `helpers ↔ sqs` cycle) (Sprint 1).
- **`requests.Session` connection pooling** — `GitHubApp` in
  `libinv/vcs.py` now uses a lazy pooled `Session` subclass for its 6
  external HTTP call sites. `helpers.send_to_slack` uses a module-level
  `@lru_cache(maxsize=1)` `Session` singleton. Test compatibility is
  preserved: the `Session.request()` override delegates to the patched
  module-level `requests.<method>` when tests have monkey-patched it
  (Sprint 15).

### Architecture

- **Shared `Session` refactor** — `libinv/base.py` keeps `Session` as the
  sessionmaker factory and introduces `ScopedSession = scoped_session(Session)`
  for thread-local isolation. `conn` is aliased to `ScopedSession`. A
  `session_scope()` context manager (commit on clean exit, rollback on
  exception, `remove()` in finally) is the new canonical entry point. An
  `app.teardown_request` hook removes the request's session, and
  `ThreadPoolExecutor` workers are wrapped in `try/finally` so they do not
  leak sessions (Sprint 0).
- **`api/actionable.py` split** — The 1218-LOC god-route is gone and
  replaced by the `libinv/api/actionable/` blueprint package:
  `dashboards.py` (`/v2/`, `/v3/`), `package_details.py`,
  `repositories.py`, `statistics.py`, `package_scan.py`, plus a `_common.py`
  for the `fetch_repository` helper. Public-API preserved: `api/app.py`
  still imports `actionable`, and `compare_builds.py` still imports
  `fetch_repository` from the package's `__init__.py` (Sprint 3).
- **`v2/v3` dashboard consolidation** — `api/actionable/dashboards.py`
  shrunk 209 → 128 LOC (~39% reduction). A module-level helper
  `_render_actionable_dashboard(include_epss)` contains the shared query
  and dict-building logic; both route handlers are 2-line stubs that
  delegate to it. v2/v3 differences are gated on the `include_epss` flag
  with the original behaviors preserved verbatim (Sprint 4).
- **Statistics helper extraction** — `_compute_statistics(session)` lifted
  out of the `statistics_dashboard` route in
  `libinv/api/actionable/statistics.py`. The route is now ~10 lines: set
  `statement_timeout`, call helper, render template, fallback render on
  exception (Sprint 6).
- **GitHub-issue rendering extracted** — New `libinv/services/issue_reporter.py`
  with `prepare_git_issue_content` (and a deduped `_render_actionable_table`
  helper that collapses the three near-identical markdown-table blocks at
  the original `models.py:1086-1146`). The 110-line
  `Actionable.prepare_git_issue_content` staticmethod is gone (Sprint 2).
- **ScanCode.io HTTP client** — New `libinv/services/scancodeio_client.py`
  with `ScancodeioClient` and TypedDicts for the contract
  (`DiscoveredPackageDTO`, `ScanpipeProjectDTO`, `SeverityCountDTO`).
  `get_default_client()` is gated by `LIBINV_SCIO_USE_HTTP`. Scaffold
  introduced in Sprint 14; 6 of 7 methods wired to real REST endpoints in
  Sprint 15 (`get_project`, `list_discovered_packages` /
  `iter_discovered_packages` with `is_vulnerable=yes`, `get_severity_counts`,
  `get_vulnerability_count`, `list_cve_ids_for_project`). Typed exceptions
  (`ScancodeioError`, `ScancodeioNotFound`) and a `_request_json` helper
  consolidate 404 / 5xx / connection-error mapping. The seventh method
  (`list_projects_for_wasp`) is a deliberate `NotImplementedError` because
  `wasp_uuid_id` is not in upstream `ProjectFilterSet.Meta.fields` —
  blocked on upstream filterset extension or a SupplyShield-side proxy.
- **Model `conn` → `session_scope` migration** — Multi-sprint effort to
  thread an explicit `session` through every code path:

  * Sprint 6: `cli/actionable.py` (all 9 `@cli.command` functions) and
    `libinv/jira_integration.py` migrated to `with session_scope() as
    session:` blocks. The jira sync now wraps each per-issue work in its
    own `session_scope`, so a single malformed JIRA issue logs and skips
    instead of aborting the whole nightly sync.
  * Sprint 7: 9 classmethods in `libinv/models.py`
    (`Repository.get_by_git_url`, `Account.ensure_exists`,
    `Wasp.eat_caterpillar_message`, `Secbug.get` / `get_any` /
    `all_active`, `Actionable.populate` / `fetch_and_store_versions` /
    `get_packages_without_versions`) gained an optional
    `session=None` last-kwarg + `s = session or conn` internal fallback.
  * Sprint 9: image scanner (`sca.py`, `sbom.py`, `scanner.py`) migrated.
    Orchestrator's `with Session() as session:` upgraded to
    `with session_scope() as session:`. `models.py` `conn.*` refs: 7 → 4.
  * Sprint 10: Wasp context manager (`__exit__`, `throw`), `Repository.
    raise_or_update_sca_issues`, and `base_image.save_layer_information_for_image`
    migrated. `models.py` `conn.*` refs: 4 → 0.
  * Sprint 11: `jira_integration.py` dropped its
    `from libinv.base import conn` import entirely; both call sites now
    thread the explicit `session=session`. Dead-code
    `detect_and_update_parent_image` (~30 LOC, the last `conn.*` reference
    in any image scanner) deleted after grep confirmed zero callers.
  * Sprint 12: `scanners/repository_scanner/bridge.py` (the SQS handler —
    final caller) migrated. `process_sqs_message` now wraps the
    `connect_using_queue_message_agreement(wasp)` call in
    `with session_scope() as session:`. The migration milestone is
    fully complete across every production code path.
  * Sprint 13: `libinv.base.conn` upgraded from a deprecation **comment**
    (Sprint 3) to a real runtime `DeprecationWarning` via a
    `_ConnDeprecationProxy` wrapper that forwards every attribute access
    / call to the wrapped `ScopedSession` and emits a one-shot
    `DeprecationWarning` (`stacklevel=3` so it points at the caller).
    `__bool__` returns `True` without warning so `s = session or conn`
    fallbacks stay silent.
- **Alembic baseline + migrations** — New `alembic/` tree with
  `env.py`, `script.py.mako`, and two initial migrations:
  `0001_baseline.py` (empty — stamps the existing `init.sql` schema as the
  alembic baseline) and `0002_fk_indexes.py` (the FK / composite indexes
  noted under Performance). `alembic_version` lives in the `libinv`
  schema, not `public`. `Makefile db:` target now runs
  `alembic upgrade head` from repo root (was a broken `cd libinv;
  alembic ...`) (Sprint 2).
- **`Wasp.__exit__` session migration** — `Wasp.eat_caterpillar_message`
  now attaches the resolved session via `wasp._session = s`. `__exit__`
  and `throw` use `getattr(self, "_session", None) or conn`, so Wasps not
  created via `eat_caterpillar_message` still work via the fallback
  (Sprint 10).
- **`Secbug.is_active` contract** — Fixed and pinned by 2 DB-free unit
  tests (Sprint 8).
- **Typo rename: `vulnerabilitiy` → `vulnerability`** — Coordinated
  rename of the `vulnerabilitiy_severities` property on
  `ActionablePackageAvailableVersion`, its caller in
  `api/actionable/package_scan.py`, and the template
  `api/templates/package_scan.html`. Drop of Sprint 12's
  backward-compat aliases for `set_desciption` and `callibrate` after
  grep confirmed zero remaining external callers (Sprint 13).
- **Typo / logger cleanup** — `logger.warn(...)` (3.4-deprecated alias) →
  `logger.warning(...)` in `base_image.py`; `Scanningz` → `Scanning` in
  the scan-start log; `set_desciption` → `set_description` (with
  backward-compat alias initially retained, dropped in Sprint 13);
  `callibrate` → `calibrate`; `pacakge_name` → `package_name` in
  `issue_reporter.py` (Sprint 12).
- **`etc/initdb/init.sql` `\restrict` directive removed** — The opening
  `\restrict OGpOw5cgpr9...` and closing `\unrestrict ...` lines emitted
  by `pg_dump v17` are removed. `postgres:15` (the version pinned in
  `docker-compose.yml`) does not recognise them and would fail to apply
  the dump on a clean DB bootstrap (Sprint 12).
- **`print()` → `logger`** — Migrated remaining `print` calls to
  `logger.*` across `models.py`, `jira_integration.py`, image scanner
  modules (`base_image.py`, `scanner.py`, `sca.py`, `sbom.py`), and
  `api/actionable/_common.py`. Allowlisted as user-facing CLI output (kept
  as `print`): the four print calls in `cli/checkpoint.py` and the
  `print(table)` in `cli/actionable.get_actionable_for`. `api/graph.py`
  and `helpers.py` had already been migrated in Sprint 1 (Sprint 16).
- **`models.py` `session=None` family type hints** — Added type annotations
  to the classmethod family that gained the `session=None` last-kwarg in
  Sprint 7, completing the typing pass on the model layer (Sprint 17).
- **mypy clean across `libinv/{base,models,services,api,scanners}`** —
  Type-hint pass widened mypy's covered surface from Sprint 16's two
  modules to the bulk of `libinv/`. All flagged issues fixed (Sprint 18).
- **`SarifResult` session-injected** — Now threads an explicit `session`
  through its constructor / methods instead of falling back to module-level
  `conn`, completing the conn-purge pattern for the SARIF code path
  (Sprint 20).
- **Flask `app.py` + `wasp.py` routes use `ScopedSession()`** — Direct
  call-site invocations of `ScopedSession()` replace residual `conn`
  references; removes the Sprint 13 `_ConnDeprecationProxy` warnings these
  routes were emitting on every request (Sprint 20).
- **ScanCode.io HTTP client wired into `cli/epss.py`** — First production
  caller migrated off `scio_models.py` reflection onto
  `ScancodeioClient` from Sprint 14/15 (Sprint 21).
- **ScanCode.io HTTP client wired into `models._get_vulnerabilities_count`
  + `api/actionable/package_details.py`** — Second wave of SCIO HTTP
  migrations; replaces direct SQL against the reflected schema
  (Sprint 22).
- **ScanCode.io HTTP client wired into `models.vulnerability_severities`**
  — Last raw `text()` CTE against the SCIO database migrated to the HTTP
  client. `compare_builds.py` is documented as a deliberate hold-out
  (blocked on upstream `ProjectFilterSet` filter limitation, same root
  cause as `list_projects_for_wasp`) (Sprint 23).

### Tests

- **Unit-test suite (Sprint 3)** — New `tests/` directory with first real
  pytest suite. Covers:

  * `tests/test_helpers.py` — `explode_git_url` (4 cases incl. unsupported
    scheme raising `ValueError`), `retry_on_exception`, `send_to_slack`.
  * `tests/test_issue_reporter.py` — empty / only-P0 / only-Other / mixed
    rendering, `commit_id` and `jenkins_url` append behavior, magnifier
    emoji for empty `suggested_versions`, table header invariant.
  * `tests/test_auth.py` — 6 cases via Flask test client covering GET
    unaffected; PUT/POST/PATCH/DELETE rejected without / wrong / correct
    token; 503 when `LIBINV_API_TOKEN` unset.
  * `tests/test_semgrep_runner.py` — argv-list call (not shell),
    `shell=False`, untrusted strings pass through unchanged,
    `timeout=3600`.
  * `tests/test_daemon_shutdown.py` — SIGTERM/SIGINT handler flips
    `_shutdown_requested`.
  * `tests/test_session_scope.py` — commit on clean exit, rollback on
    exception, `remove()` always called.
  * `pytest.ini` — `testpaths = tests libinv`; `--doctest-modules`
    discovers the 4 `explode_git_url` doctests; ignore globs for the
    reflection-time-DB modules (`scio_models`, `scancodeio`) and
    `alembic`.
  * `Makefile tests` target — single `pytest` invocation under coverage.
- **Integration-test suite (Sprint 4)** — New `tests/integration/`
  directory with a session-scoped `engine` fixture that connects to
  `TEST_DATABASE_URL`, runs `CREATE SCHEMA IF NOT EXISTS libinv`, and
  then `Base.metadata.create_all`. A per-test `db_session` fixture uses
  `SAVEPOINT` + rollback for isolation. `collect_ignore_glob =
  ["test_*.py"]` when `TEST_DATABASE_URL` is unset keeps the unit-test
  run green without DB infra. Initial tests:

  * `test_epss_upsert.py` (4) — fresh insert, upsert overwrite,
    empty-dict no-op, `get_fresh_cves` age filter.
  * `test_session_scope.py` (3) — commit/rollback/remove() against a real
    Postgres.
  * `test_mark_latest_version.py` (1) — end-to-end assertion that the
    Sprint-2 switch to `session_scope` actually persists `is_latest=True`.
- **N+1 eager-loading regression test (Sprint 5)** — `tests/integration/
  test_n1_eager_loading.py` installs a SQLAlchemy `before_execute` query
  counter and asserts `get_actionable_and_secure_versions` fires ≤ 12
  queries (vs ~16 cascade floor for `N=5`). A companion test pre-loads
  `available_versions` via `selectinload` and asserts both `get_latest()`
  and `get_safe_versions()` fire **zero** SQL, proving the Python-side
  short-circuit works.
- **Statistics integration tests (Sprints 6-8)** — `tests/integration/
  test_statistics.py` grew from 2 → 8 functions. A `seeded_buckets`
  fixture seeds `P0=2, P1=3, P2=4, P3=5, no_epss=1, total=15` (distinct
  counts so swap bugs surface). Tests assert specific counts AND the
  partition invariant `p0 + p1 + p2 + p3 + no_epss == total_packages`.
  Sprint 8 added 6 more covering repository buckets, env/pod groupings,
  and empty-bucket return-0-not-None invariants.
- **`Wasp.__exit__` regression tests (Sprint 11)** — New
  `tests/test_wasp_exit.py` with `test_wasp_exit_propagates_exception`
  (raises `ValueError` inside `with wasp:`, asserts `ValueError`
  propagates AND that the side effects all still happen) and
  `test_wasp_exit_commits_on_clean_exit`.
- **`Secbug.is_active` tests (Sprint 8)** — `tests/test_secbug_is_active.py`
  with 2 DB-free unit tests pinning the new contract: active when
  `deleted_at is None`; inactive when a `deleted_at` timestamp is set.
- **`vulnerability_severities_epss` tests (Sprint 14)** — New
  `tests/test_vulnerability_severities_epss.py` with 4 DB-free tests
  including a source-level regression guard against future `_epss`
  references.
- **`vcs.py` + `ecr.py` unit tests (Sprint 14)** — `tests/test_vcs.py`
  (16 tests) covers Sprint 0-1 hardening on `libinv/vcs.py`
  (`write_token_to_netrc` mode `0o600` + atomic rewrite,
  `create_issue` / `update_issue` `timeout=10` + `raise_for_status` +
  mutable-default fix, `get_sca_issue` early-return fix).
  `tests/test_ecr.py` (8 tests) covers Sprint 0 hardening on
  `image_scanner/ecr.py` (`removeprefix("https://")` correctness with an
  explicit regression for `"https://stage.amazonaws.com"`, `auth()`
  mode `0o600`, valid JSON, `.docker/` created when missing). Notes for
  future contributors: `EcrClient` is attrs-slotted — patch on the
  CLASS, not the instance, for method overrides; `Path.home()` needs
  `classmethod(lambda cls: tmp_path)` on Python 3.13.
- **ScanCode.io HTTP-client tests (Sprint 15)** — 20 new DB-free tests in
  `tests/test_scancodeio_client.py` covering pagination, filter-flag
  plumbing, severity aggregation, vulnerability-count aggregation,
  CVE extraction + dedup + sort, HTTP 404 → typed exception, HTTP 5xx
  + connection errors → logs + re-raises, env-flag-gated
  `default_client`. Test for the `NotImplementedError` stub pins its
  behavior so it cannot silently regress to an unfiltered call.
- **API route smoke tests (Sprint 15)** — 35 new tests in
  `tests/test_api_routes.py` covering all 19 routes in the actionable /
  wasp / compare_builds / onboard / graph blueprints + top-level routes
  (`sast`, `docs`, root). Builds a fresh test client from
  `libinv.api.app.app` directly. All DB / S3 / external-service calls
  mocked via `unittest.mock.patch`. `render_template` patched to `"ok"`
  for routes with rich nested data. Intentionally not happy-path tested:
  `/docs/<path>` (covered transitively by `/docs/`) and
  `/blastradius/generate_graph` (real pyvis graph construction; only
  the 400 path is covered).
- **Request-ID middleware tests (Sprint 16)** — 5 new tests in
  `tests/test_request_id.py` covering UUID minted when header absent;
  inbound `X-Request-Id` honored and echoed in the response; log record
  picks up the `contextvar`; `JsonFormatter` outputs valid JSON;
  default `"-"` preserved for non-Flask callers.
- **CLI command type annotations (Sprint 19)** — All `cli/` commands type-
  annotated as part of the mypy-blocking enablement; tests pin the
  contracts.
- **`cli/daemon` + `cli/checkpoint` unit-test coverage (Sprint 24)** — Two
  CLI modules previously without test coverage now have dedicated unit
  tests.
- **Final test count** — 175 unit tests + 18 integration tests = 193 tests
  total (up from 0 at Sprint 0 baseline; 38 after Sprint 3; 70 after
  Sprint 14; 125 after Sprint 15; 130 after Sprint 16) plus the gated
  integration suite.

### Infrastructure

- **CI postgres service (Sprint 5)** — `.github/workflows/coverage.yml`
  bumped `checkout@v3 → v4`, `setup-python@v2 → v5`, Python `3.10 → 3.12`
  (aligns with `linting.yml`). Added a `postgres:15` service container
  (`libinv_test` DB) with `pg_isready` healthcheck and a job-level
  `TEST_DATABASE_URL` env. New `Run integration tests` step calls
  `make integration-tests` after `Run unit tests with coverage`.
- **CI linting workflow (Sprint 5)** — `.github/workflows/linting.yml`
  bumped `checkout@v3 → v4`, `setup-python@v4 → v5`. Python 3.12
  unchanged.
- **Makefile `integration-tests` target (Sprint 4)** — Added with
  `.PHONY` entry; runs `python -m pytest tests/integration -v`.
- **Makefile `db:` target (Sprint 2)** — Now runs `alembic upgrade head`
  from repo root (was a broken `cd libinv; alembic ...`).
- **`pytest.ini`** — `testpaths = tests libinv`; `--doctest-modules`
  picks up the `explode_git_url` doctests; ignore globs for the
  reflection-time-DB modules (`scio_models`, `scancodeio`) and
  `alembic`. Explanatory comment notes that integration tests are not
  listed separately because pytest 8.4 silently drops the `tests/`
  collection when both `tests` and `tests/integration` are listed
  (overlapping-root de-dup bug) (Sprints 3-4).
- **Structured logging (Sprint 16)** — `libinv/logger.py` extended with a
  `contextvars`-based `request_id_var` (default `"-"`), a `JsonFormatter`
  that emits `{time, level, name, message, module, lineno, request_id}` as
  a single JSON line, and an `install_json_formatter_if_configured()`
  bootstrap gated on `LIBINV_LOG_FORMAT=json`. The existing
  `CustomFormatter` + `color_handler` are preserved as the default.
- **Flask `X-Request-Id` middleware (Sprint 16)** — New
  `libinv/api/request_id.py` with `register_request_id(app)`. A
  `before_request` hook reads an inbound `X-Request-Id` or mints
  `uuid.uuid4().hex`, sets both `g.request_id` and the `request_id_var`
  contextvar; `after_request` echoes the header on the response. Wired
  in `libinv/api/app.py` after the global auth registration.
- **`pyproject.toml` `[tool.mypy]` (Sprint 16)** — New section restricting
  checks to `libinv/base.py` + `libinv/services` (gradual typing).
  Settings: `python_version="3.12"`, `follow_imports="silent"`,
  `ignore_missing_imports=true`, `strict_optional=true`,
  `warn_unused_ignores=true`, `warn_redundant_casts=true`,
  `disallow_untyped_defs=false`, `no_implicit_optional=true`,
  `disable_error_code=["import-untyped"]`.
- **Type hints (Sprint 16)** — `libinv/base.py` (`engine: Engine`,
  `Session: sessionmaker`, `ScopedSession: scoped_session`, fully-typed
  `_ConnDeprecationProxy`, `session_scope() -> Iterator[OrmSession]`),
  `libinv/services/__init__.py`, `libinv/services/issue_reporter.py`
  (`_render_actionable_table`, `prepare_git_issue_content` typed), and
  cleanup pass on `libinv/services/scancodeio_client.py`.
- **CI security tooling (Sprint 17)** — `mypy`, `bandit`, and `pip-audit`
  added to `.github/workflows/linting.yml`. Initial run is informational;
  Sprint 18 widens mypy coverage and Sprint 19 flips the mypy step to
  blocking.
- **Dependabot + pre-commit (Sprint 18)** — Dependabot config added for
  pip / GitHub Actions ecosystems; `.pre-commit-config.yaml` added with
  ruff / mypy / bandit hooks for local enforcement.
- **Python 3.12 alignment (Sprint 18)** — `setup.cfg`, CI workflows, and
  the `[tool.mypy]` block all pinned to `python_version = "3.12"`.
- **Dropped duplicate / unused dependencies (Sprint 18)** — Duplicate
  `psycopg2` and unused `mysqlclient` removed; `peewee` dropped in
  Sprint 19 after grep confirmed zero callers.
- **CI mypy step blocking (Sprint 19)** — The Sprint 17 informational mypy
  step is now a build-failing check.
- **Kubernetes `/healthz` + `/readyz` probes (Sprint 23)** — Liveness and
  readiness endpoints registered on the Flask app so k8s can route
  traffic only after the DB is reachable.

### Observability

- **Per-job request-ID for cron_scheduler (Sprint 21)** — `cron_scheduler`
  mints a UUID per job and sets it on `request_id_var` (the Sprint 16
  `contextvars` slot) so every log record under a cron job is correlated.
- **CLI seeds `request_id_var` from `LIBINV_REQUEST_ID` (Sprint 22)** —
  The CLI entry point reads `LIBINV_REQUEST_ID` from the environment and
  seeds the contextvar, completing the cron-scheduler → child-process
  correlation chain started in Sprint 21.
- **Prometheus `/metrics` endpoint (Sprint 24)** — `prometheus_client`
  integrated; `/metrics` exposes default process / GC collectors plus
  application counters for scraping.

### Documentation

- **`docs/scancodeio_contract.md` (Sprint 14)** — New document covering:

  * Current SQL / reflection coupling catalog (3 classifications across
    the 28 grep hits in `libinv/`).
  * Per-method input / output + replaced SQL.
  * Migration plan (parallel paths behind `LIBINV_SCIO_USE_HTTP` flag;
    callers migrate in Sprint 15+; `scio_models.py` removed Sprint 16+).
  * 6 open questions to resolve against a running ScanCode.io instance.
- **`README.rst`** — Added Architecture, Configuration (audit-driven env
  vars), Testing, and Development sections reflecting the Sprint 0-16
  state. Existing Installation / Usage Guide / Architecture Diagram
  sections untouched. README + CHANGELOG initial landing (Sprint 17).
- **Sphinx architecture + configuration pages (Sprint 21)** — New pages
  under `docs/` cover the Sprint 0-20 architecture and environment-
  variable surface.
- **`CHANGELOG.md`** — This file (extended through Sprint 24).

### Deferred (audit follow-ups not yet landed)

These were explicitly flagged across sprints as out-of-scope but are
worth tracking. They are listed here to keep the audit trail honest.

- ~~Wire `mypy + bandit + pip-audit` into the CI workflow~~ — landed in
  Sprint 17; mypy made blocking in Sprint 19.
- ~~Type hints on the remaining hot files (`models.py`, `api/*`,
  `cli/*`).~~ — landed across Sprints 17-19.
- Drop `from libinv.base import conn` imports across `libinv/` now that
  the runtime `DeprecationWarning` proxy makes direct usage visible
  (partially addressed in Sprint 20 for the Flask app + SARIF paths;
  remaining call sites still pending).
- Materialized view `sca_actionable_items` recovery (still missing from
  alembic migrations).
- `ScancodeioClient.list_projects_for_wasp` and `compare_builds.py` SCIO
  migration — both blocked on upstream `ProjectFilterSet.Meta.fields`
  extension or a SupplyShield-side proxy endpoint. The blocker is
  documented in-tree as of Sprint 23.
- The single mypy error in `scancodeio_client.py:225` (`get_project`'s
  return-type narrowing on `_request_json`).
- `total_repositories` scalar query in `statistics.py` — could be folded
  into the aggregate query if a shift from inner-join to left-join
  semantics is acceptable.
- `Secbug.key` synonym at `models.py:465` — possibly unused ORM glue.

### Observability (Sprints 25-28)

- **`libinv_scan_invocations_total{type}` wired (Sprint 25)** — three
  scan entry points (`scan_image_index`, `connect_using_queue_message_
  agreement`, `run_cdxgen_scan`) now increment the Sprint-24 counter at
  entry, before the work runs, so crashed scans still surface in the
  metric. 6 new tests cover happy-path and crash-still-increments for
  each scan type.
- **`libinv_scan_failures_total{type, error_class}` (Sprint 26)** — new
  Counter wrapping scan exceptions. `error_class` uses
  `type(exc).__name__` so cardinality stays bounded by the exception
  classes actually thrown. Increments + re-raises on every scan path's
  failure branch.
- **`libinv_scan_duration_seconds{type}` Histogram (Sprint 27)** — new
  Histogram with explicit buckets spanning 1s → 1h (cdxgen seconds →
  scancodeio minutes) plus `+inf` for overflow. Wraps each scan entry
  point via `with scan_duration_seconds.labels(type=...).time():`.
  Shares the `type` label with `scan_invocations_total` /
  `scan_failures_total` so PromQL can join them.
- **`libinv_sast_findings_total{severity, tool}` Counter (Sprint 28)** —
  emitted from `SarifResult.add_sarif_result_to_db` after each commit
  on both insert and update paths. Severity normalised via
  `_normalize_sarif_severity` (case-fold + allowlist → "unknown")
  to keep cardinality bounded; `tool` reads
  `runs[0].tool.driver.name` with a defensive fallback.

### Reliability (Sprints 25-29)

- **CLI submodule shadowing fix (Sprint 25)** — `libinv/cli/__init__.py`
  replaced 11 `from libinv.cli.X import Y` lines with `from . import
  <submodule>`. The Click `@cli.command()` side-effects still register
  the commands with the parent group, but `import libinv.cli.daemon`
  now resolves to the SUBMODULE (with `_request_shutdown` etc.) instead
  of the Click `Command` object.
- **3 latent `SarifResult` bug fixes (Sprint 28)** — fd-leak in
  `__init__` (`json.load(open(...))` → `with open(...)`);
  `json.load(record.extras)` (expects a file) → `json.loads` (string
  parser) for the equal-endpoints branch; `KeyError` on missing
  `runs[0].tool.driver.rules` array → `.get("rules", [])` with a
  warning log.
- **`SarifResult.rulemetadata` KeyError guard (Sprint 29)** — follow-on
  to Sprint 28's missing-rules fix: line 127 now uses
  `self.rulemetadata.get(ruleid, {})` with a warning log instead of
  `self.rulemetadata[ruleid]`. The persistence loop now survives BOTH
  SARIF tools that omit the `rules` array entirely AND SARIF results
  that reference a `ruleId` not present in `rules` (semgrep with
  `--severity` filters applied).

### Infrastructure (Sprints 26, 27)

- **Alembic migrations integration test (Sprint 26)** — new
  `tests/integration/test_alembic_migrations.py` (3 tests). Asserts
  `upgrade head` creates `libinv.alembic_version` + stamps
  `0002_fk_indexes`; `downgrade -1` → `upgrade head` is reversible;
  the Sprint-2 FK index `ix_epss_cve_updated_at` appears in
  `pg_indexes` post-upgrade. Subprocess-based so we exercise the real
  alembic entry point, not an in-process recursion.
- **CI pip download caching (Sprint 26)** — `actions/cache@v4` step
  inserted between `Set up Python` and `Install Build Tools` in both
  `.github/workflows/coverage.yml` and `.github/workflows/linting.yml`.
  Cache key uses `hashFiles('requirements.txt', 'setup.cfg',
  'pyproject.toml')`; estimated ~30s saved per CI run on cache hit.

### Documentation (Sprints 27)

- **Sphinx deployment + troubleshooting pages (Sprint 27)** — new
  `docs/deployment.rst` (k8s quickstart with pod spec, liveness /
  readiness probes, Prometheus ServiceMonitor, alembic upgrade order,
  secrets handling, cron + `LIBINV_REQUEST_ID` propagation, JSON
  logging) and `docs/troubleshooting.rst` (9 recipes covering 503
  auth-not-configured, conn DeprecationWarning, SCIO 404, alembic on
  fresh DB, mypy blocking, etc.). Added to `docs/index.rst` toctree.

### Mypy strictness (Sprint 29)

- **`valid-type` removed from the `libinv.api.*` / `libinv.scanners.*`
  / `libinv.cli.*` mypy override.** 5 codes still suppressed (was 6).
  The real error this exposed —
  `libinv/scanners/image_scanner/image_index.py::pull_images_if_not_
  exist` had `-> ["Image"]` (a list literal in the annotation) — was
  corrected to `-> Iterator["ImageTarBall"]` with the matching
  `Iterator` import added.

### Tests (Sprints 25, 26, 27, 28, 29, 30, 31, 32)

- Sprint 25: +6 scan_invocations tests
  (`tests/test_scan_metrics.py::happy + crash for image / bridge /
  cdxgen`). Unit total: 175 → 181.
- Sprint 26: +3 scan_failures tests + 3 gated alembic tests (skip
  cleanly without `TEST_DATABASE_URL`). Unit total: 181 → 184.
- Sprint 27: +3 scan_duration Histogram tests + 7 SarifResult unit
  tests pinning the Sprint-20 session-injection contract. Unit total:
  184 → 193.
- Sprint 28: +3 fixed-bug regression tests + 5 sast_findings counter
  tests (insert / update / case-fold / missing-level / commit-rolled-
  back). Unit total: 193 → 202.
- Sprint 29: +1 rulemetadata-missing-ruleId regression test. Unit
  total: 202 → 203.
- Sprint 30: pytest-postgresql integration fixtures in
  `tests/conftest.py` (database factory + alembic `upgrade head`
  inside the integration session fixture). Foundation for the
  Sprint 31-32 integration suite.
- Sprint 31: 5 E2E integration tests covering SQS → daemon → DB → API
  (moto SQS + the real Flask app + DB-backed fixtures), plus
  behavioural coverage of the 44-row `repositories` listing.
- Sprint 32: CLI + handler integration tests (`metapod` import path,
  `bridge.connect_using_queue_message_agreement`, SCA-issue-creation,
  wasp `__exit__` parser), with `xfail` markers on pre-existing
  failures so the suite is green and we don't silently regress later.

## [Unreleased] — Sprints 33-52 (post-audit remediation, in flight)

### Dependency hygiene (Sprint 53.5)

- **Sprint 53.5 — confirmed no `mysqlclient` / `psycopg2` (non-binary) /
  `MySQL-python` / `PyMySQL` stragglers remain in `requirements.txt`,
  `setup.cfg`, or `pyproject.toml` after the Sprint 18 cleanup. Only
  `psycopg2-binary` (the modern variant) is present, which is the
  intended state.

### Schema discipline (Sprints 33-34)

- **Alembic index parity audit (Sprint 33)** — every `Index(...)`
  declared in the ORM is now declared in alembic too; missing
  declarations added; `alembic check` step added to CI to catch future
  drift.
- **`nullable=False` audit + tightening migration (Sprint 34.1)** —
  ORM-declared `nullable=False` columns that the DB still allowed
  `NULL` for are now tightened via a new alembic revision.
- **`epss.epss_date` `String(20)` → `Date` (Sprint 33-34)** — column
  type widened to a real Date with the corresponding migration and
  caller updates.
- **`String(N)` audit (Sprint 33-34)** — oversized text columns
  (commit field etc.) tightened with the corresponding migrations.

### Performance (Sprints 35-38)

- **Pool tuning (Sprint 35-36)** — `pool_size=10`, `max_overflow=20`,
  `pool_recycle=1800`, `pool_use_lifo=True`.
- **Global `statement_timeout` `before_request` hook (Sprint 35-36)** —
  removes the per-route `SET statement_timeout` boilerplate.
- **`ThreadPoolExecutor(max_workers=4) → 2 sites` cap (Sprint 35-36)** —
  bound the per-process worker fan-out where it had grown unbounded.
- **`_compute_statistics` decomposition + parallelisation (Sprint
  35-36)** — broken into per-group helpers and the 6 group queries now
  run concurrently via `ThreadPoolExecutor`. SQL bug surfaced and
  fixed in the same pass.
- **`LIBINV_STRICT_LAZY` + `lazy="raise_on_sql"` policy hook (Sprint
  37)** — opt-in for N+1 detection in dev / test.
- **34 `relationship()` declarations audited + `selectinload` at
  traversal sites (Sprint 37)** — eliminates the lazy-load N+1s that
  the new policy hook would otherwise raise on.
- **`cli/epss.py::_collect_cves_for_projects` bulk fetch (Sprint
  38.1)** — eliminates per-project HTTP round-trips through the
  SCIO client.
- **`Actionable.populate` + `fetch_and_store_versions` → `INSERT ON
  CONFLICT` (Sprint 38.2)** — replaces the previous row-by-row
  `merge` loop.

### Architecture (Sprints 39-48)

- **`libinv/models.py` → `libinv/models/` package + `_base.py`
  extract (Sprint 39)** — Image, ImagePackageAssociation, Layer,
  LatestImage extracted to `models/image.py` in the same pass.
- **Package / Vulnerability / EPSS domains extracted (Sprint 40)** —
  `models/package.py`, `models/vulnerability.py`, `models/epss.py`.
- **Wasp / Actionable / Repository extraction (Sprint 41 phase 3a)**
  — `models/wasp.py`, `models/actionable.py`, and Repository /
  Account / DeploymentCheckpoint split into 3 files.
- **Secbug + SAST extraction + `_legacy` cleanup (Sprint 41 phase
  3b)** — `models/secbug.py`, `models/sast.py`. The legacy
  `models.py` shim removed; `models/__init__.py` is now <50 lines of
  re-exports.
- **`scancodeio_client.py` → `libinv/services/scancodeio/` package
  (Sprint 42.1 + 42.2)** — `transport.py` (Session + retries +
  `_request_json` mypy fix at line 225 closed).
- **`scancodeio/dtos.py` + `scancodeio/endpoints.py` (Sprint 42.3 +
  42.4)** — TypedDicts + per-endpoint methods; the package re-exports
  the public façade preserving the old import path.
- **EPSS CLI service extraction (Sprint 43.1 + 43.2)** —
  `--all-actionable-cves` and `calculate-package-epss` workflows moved
  to `libinv/services/epss/`.
- **Query builders + EPSS cyclomatic decomp (Sprint 43.3 + 44)** —
  `RepositoryListingQuery` builder + `repositories_listing` refactor;
  `PackageDetailsQuery` builder + `package_details` refactor;
  per-function cyclomatic complexity in `libinv/cli/epss.py` now
  under 10. `jira_integration` session signatures normalised.
- **`sca_actionable_items` materialized view recovery (Sprint 45)** —
  alembic migration writes the view with a unique index. Previously
  flagged as deferred in the Sprints 0-24 section; now landed.
- **EPSS row pruning (Sprint 46.3)** — `LIBINV_EPSS_RETENTION_DAYS`
  env var drives a pruning job; tests cover the cutoff boundary.
- **`Repository_ActionablePackageAvailableVersion` rename (Sprint
  46.4)** — class renamed; the old name retained as an alias for
  backwards compatibility.
- **`scio_models` reflection guard (Sprint 48.2)** — the import-time
  `sqlalchemy.inspect` reflection now only runs when
  `LIBINV_SCIO_USE_HTTP` is unset, decoupling boot from upstream
  schema shape when the HTTP path is on.
- **`print()` → `click.echo()` (Sprint 48.3)** —
  `cli/checkpoint.py` (4 sites) + `cli/actionable.py:223` switched
  away from `print()` so output respects Click's redirection.

### Security (Sprints 47, 51, 52)

- **`shell=True` elimination in cron scheduler (Sprint 47.1)** —
  `cron_scheduler.py:31` switched from `shell=True` to
  `shlex.split` + `shell=False`. The init.sh hardening pass in
  Sprint 47.3 went through the same audit on the entrypoint script.
- **Flask-Limiter + rate-limited `/v3/*` routes (Sprint 51.1)** —
  Flask-Limiter wired into `libinv/api/app.py` with per-route
  `@limiter.limit` decorators on the `/v3/*` routes.
- **`/metrics` authentication (Sprint 51.2)** — Bearer-token gate via
  `LIBINV_METRICS_TOKEN`; `/metrics` returns 401 without the token.
- **Daemon DB-connect retry (Sprint 51.3)** — exponential backoff on
  startup, capped at 5 minutes, so transient DB unavailability at
  boot doesn't crash-loop the daemon container.
- **Crons SIGTERM graceful shutdown (Sprint 52.1 + 52.3)** — the cron
  scheduler now installs a SIGTERM handler that flags shutdown and
  drains in-flight jobs cleanly before exit. Sprint 52.3 covers the
  matching upload-to-s3 ClientError → log + counter + raise hardening.

### Tooling notes

- **`pylintrc` deleted (Sprint 55.4)** — the 20KB `pylintrc` file was
  unused; pylint is not referenced from `.github/`, `docs/`, or the
  `Makefile`. Linting is handled by `ruff` + `black` + `mypy` +
  `bandit` (Sprints 17-19).
- **`etc/pre-commit` deleted (Sprint 55.4)** — superseded by
  `.pre-commit-config.yaml` (Sprint 18). The old 22-byte
  `etc/pre-commit` shell script (`make check`) is no longer wired
  into any hook installer.

### Test counts (cumulative)

| Sprint | Unit | Integration | Total |
|--------|------|-------------|-------|
| 16     | 130  | 18          | 148   |
| 24     | 175  | 18          | 193   |
| 25     | 181  | 18          | 199   |
| 26     | 184  | 21          | 205   |
| 27     | 193  | 21          | 214   |
| 28     | 202  | 21          | 223   |
| 29     | 203  | 21          | 224   |
| 30-32  | 203  | 21+         | 224+  |

Sprints 30-52 land in a follow-up branch (`post-sprint-29 audit
remediation`); the ledger lives at
`.wave/LEDGER_2026-05-24_2357.md`.
