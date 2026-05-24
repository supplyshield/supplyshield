# Post-Sprint-29 Audit Remediation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Address every open action item from the post-Sprint-30 assessment (60+ items across architecture, performance, schema, code quality, testing, ops, dependencies, and docs) across Sprints 30–55, with deterministic per-task verification.

**Architecture:** Nine sequential waves, each a small group of related sprints. Tests come first (so every later refactor is observable). Schema discipline next (so migrations stop drifting). Performance, architecture refactors, security/quality, ops, deps and docs follow. Every task ends with a verification command and a `git add <crate>/` commit; sprints stack like the existing pattern (≤4 tasks/sprint, single fast-forward branch).

**Tech Stack:** Python 3.12, SQLAlchemy 2.x (with `db.create_engine` shim), Flask 3.x, PostgreSQL, alembic, pytest + pytest-postgresql, mypy, ruff, bandit, Click CLI, boto3 (SQS / S3), Prometheus client.

**Coverage contract:** Every assessment item maps to at least one task here. See the [Coverage Matrix](#coverage-matrix) at the end — verify before declaring this plan complete.

**Per-task verification gate (applies to every task in this plan):**
1. `pytest -x` on the touched test path passes.
2. `mypy libinv/<touched_module>` is clean (no new errors).
3. `ruff check libinv/<touched_module>` is clean.
4. The commit uses `git add libinv/<touched_path>` only (per repo `git add` discipline).

---

## Table of Sprints

| Wave | Sprint | Title | Items |
| ---- | ------ | ----- | ----- |
| 1 — Tests | 30 | Test infrastructure (pytest-postgresql + CI alembic upgrade) | 5.7, 5.8 |
| 1 — Tests | 31 | E2E + hot-route behavioral tests | 5.1, 5.2 |
| 1 — Tests | 32 | CLI + internal handler tests | 5.3, 5.4, 5.5, 5.6 |
| 2 — Schema discipline | 33 | ORM Index() declarations + alembic check in CI | 3.1, 3.7 |
| 2 — Schema discipline | 34 | nullable=False audit + Column type corrections | 3.2, 3.6, 3.8 |
| 3 — Performance | 35 | Pool tuning + global statement_timeout + ThreadPool cap | 2b, 2c, 2d |
| 3 — Performance | 36 | Statistics parallelism + `_compute_statistics` decomposition | 1.3, 2f |
| 3 — Performance | 37 | `lazy="raise"` policy + selectinload annotations | 2a |
| 3 — Performance | 38 | Bulk-upsert N+1 patterns (EPSS + Actionable.populate) | 2e1, 2e2 |
| 4 — Architecture | 39 | models.py split — Phase 1 (Image domain) | 1.1a |
| 4 — Architecture | 40 | models.py split — Phase 2 (Package/Vuln/EPSS) | 1.1b |
| 4 — Architecture | 41 | models.py split — Phase 3 (Wasp/Actionable/Repository/Account) | 1.1c |
| 4 — Architecture | 42 | scancodeio_client.py split (transport/dtos/endpoints) | 1.2 |
| 4 — Architecture | 43 | epss.py CLI service extraction | 1.5 |
| 4 — Architecture | 44 | RepositoryListingQuery builder + jira_integration signature consistency | 1.4, 1.6 |
| 5 — Schema deepening | 45 | Materialized view `sca_actionable_items` recovery | 3.10 |
| 5 — Schema deepening | 46 | Comma-separated columns → relational + EPSS row pruning + Repository_… rename | 3.3, 3.4, 3.5, 3.9, 4.8 |
| 6 — Security & quality | 47 | `shell=True` elimination + `except Exception` narrowing + init.sh hardening | 4.1, 4.2, 4.7 |
| 6 — Security & quality | 48 | `session=None` removal + scio_models reflection guard + print→click.echo + SCIO HTTP default flip | 4.3, 4.5, 4.6, 6.7 |
| 6 — Security & quality | 49 | mypy tightening Part 1 (return-value, assignment) | 4.4a |
| 6 — Security & quality | 50 | mypy tightening Part 2 (var-annotated, attr-defined, misc/arg-type) | 4.4b |
| 7 — Operations | 51 | Rate limiting + /metrics auth + daemon startup retry | 6.1, 6.2, 6.3 |
| 7 — Operations | 52 | Crons graceful shutdown + S3 upload alerting + SQS DLQ | 6.4, 6.5, 6.6 |
| 8 — Dependencies & tooling | 53 | Dependencies refresh (batched PRs) | 7.1, 7.5 |
| 8 — Dependencies & tooling | 54 | Makefile tool bumps + uv.sources cleanup + dep source-of-truth + bandit baseline | 7.2, 7.3, 7.4, 7.6 |
| 9 — Documentation | 55 | README diagram + scancodeio_contract.md + CHANGELOG + delete pylintrc/etc.pre-commit | 8.1, 8.2, 8.3, 8.4, 8.5 |

---

## Wave 1 — Test Foundation (Sprints 30–32)

### Sprint 30: Test Infrastructure (pytest-postgresql + CI alembic upgrade)

**Goal:** Make integration tests runnable in CI without a manual `TEST_DATABASE_URL` and run them on every push.

**Why first:** Every later refactor in this plan touches code paths under integration tests. If integration tests aren't running in CI, this whole plan is blind.

#### Task 30.1: Add `pytest-postgresql` as a dev dependency

**Files:**
- Modify: `requirements.txt` (or whichever file is canonical for dev deps — see Sprint 54 task 54.3)
- Modify: `tests/conftest.py`
- Modify: `pyproject.toml` (if dev-deps go there)

- [ ] **Step 1:** Add `pytest-postgresql==6.1.1` (latest 6.x at time of writing — pin to the version your Python 3.12 supports) to `requirements.txt` (or a `requirements-dev.txt` if one exists).
- [ ] **Step 2:** In `tests/conftest.py`, add the standard postgresql fixture:

  ```python
  from pytest_postgresql import factories

  postgresql_proc = factories.postgresql_proc(port=None, unixsocketdir="/tmp")
  postgresql = factories.postgresql("postgresql_proc")
  ```

- [ ] **Step 3:** Adapt the existing `test_db_url` (or equivalent) fixture in `tests/conftest.py` to derive its DSN from the `postgresql` fixture when `TEST_DATABASE_URL` is not set in env.

- [ ] **Step 4:** Run `pytest tests/integration -k "alembic" -v`. Expected: tests that previously skipped on missing `TEST_DATABASE_URL` now run.

- [ ] **Step 5:** Commit:

  ```bash
  git add requirements.txt tests/conftest.py pyproject.toml
  git commit -m "test: add pytest-postgresql for hermetic integration test DB

  Allows tests/integration to run without a manually-provisioned
  TEST_DATABASE_URL, unblocking CI integration runs."
  ```

#### Task 30.2: Wire `alembic upgrade head` into the integration test fixture

**Files:**
- Modify: `tests/conftest.py` (or `tests/integration/conftest.py`)

- [ ] **Step 1:** In the test-DB fixture (whichever one yields a session), call `alembic.config.main(["upgrade", "head"])` after the engine is bound. Use `Config` programmatically to point at the in-repo `alembic.ini`.
- [ ] **Step 2:** Verify `tests/integration/test_alembic_upgrade.py` (or equivalent) sees a fully-migrated schema.
- [ ] **Step 3:** Run all integration tests: `pytest tests/integration -v`. They should pass against the pytest-postgresql ephemeral DB.
- [ ] **Step 4:** Commit `tests/conftest.py` + `tests/integration/conftest.py`.

#### Task 30.3: Enable integration tests in CI

**Files:**
- Modify: `.github/workflows/<the-CI-workflow>.yml`

- [ ] **Step 1:** Find the existing CI workflow (Sprint 5 added a Postgres service). Confirm whether the integration tests step exists.
- [ ] **Step 2:** Either remove the Postgres service (now redundant with pytest-postgresql) **or** keep it and configure `TEST_DATABASE_URL` to point at the service container.
- [ ] **Step 3:** Add `pytest tests/integration -v` as a CI step **after** the unit test step. Mark it required (must be a checks gate on PRs).
- [ ] **Step 4:** Push to a throw-away branch, confirm CI integration step runs to completion.
- [ ] **Step 5:** Commit + open PR.

---

### Sprint 31: E2E + hot-route behavioral tests

**Goal:** Cover the two highest-risk surfaces with real behavioral assertions (not smoke tests).

#### Task 31.1: End-to-end test — SQS → daemon → DB → API

**Files:**
- Create: `tests/integration/test_e2e_sqs_daemon_api.py`

- [ ] **Step 1:** Use `moto` (mock AWS) for the SQS surface and the existing pytest-postgresql fixture for the DB. Build an SQS message that mimics a real `Wasp.eat_caterpillar_message` payload (find one in production logs or unit-test fixtures).
- [ ] **Step 2:** Spin the daemon's message-handling function in-process (do not boot the daemon's signal-handling loop — call the handler directly).
- [ ] **Step 3:** Assert: (a) one new `Wasp` row, (b) downstream `Image` + `Package` rows materialized as expected, (c) the API route that surfaces this data (`/v3/repositories` or whichever) returns the new entity.
- [ ] **Step 4:** Run `pytest tests/integration/test_e2e_sqs_daemon_api.py -v`. Iterate until green.
- [ ] **Step 5:** Commit.

#### Task 31.2: Behavioral tests for `api/actionable/repositories.py`

**Files:**
- Create: `tests/integration/test_repositories_route_behavioral.py`

- [ ] **Step 1:** Inventory the 44 branches inside `repositories_listing`. Treat each `having()` filter + each facet aggregate as a separate scenario. Use the route's docstring + parameter list to enumerate query-string permutations.
- [ ] **Step 2:** Build test fixtures (Repository + Package + Vulnerability rows) that exercise:
  - empty result set
  - single-page result
  - multi-page result
  - each `having()` predicate independently
  - each facet aggregate
  - error paths (`?env=does-not-exist`)
- [ ] **Step 3:** Each scenario gets one `def test_<scenario>(client, ...)`. Use the Flask test client.
- [ ] **Step 4:** Run `pytest tests/integration/test_repositories_route_behavioral.py -v`. Aim for at least 1 test per branch (≥44 tests).
- [ ] **Step 5:** Commit.

---

### Sprint 32: CLI + internal handler tests

**Goal:** Close the four named test-coverage gaps from the assessment.

#### Task 32.1: Tests for `cli/bridge.py` connect command

**Files:**
- Create: `tests/integration/test_cli_bridge_connect.py`

- [ ] **Step 1:** Mock the multiprocess + commit-map flow. Cover:
  - happy path: clone + commit-map populated + Repository updated
  - VCS clone failure: graceful error, no Repository state corruption
  - duplicate commit-map entries: deterministic resolution
- [ ] **Step 2:** Use `CliRunner` from `click.testing`.
- [ ] **Step 3:** Run + commit.

#### Task 32.2: Tests for `cli/import_and_improve_from_metapod.py`

**Files:**
- Create: `tests/integration/test_cli_import_and_improve.py`

- [ ] **Step 1:** Mock the metapod HTTP source (use `responses` or `pytest-httpserver`). Cover:
  - happy path: rows imported + transformed
  - upstream HTTP error: clean abort, no partial state
  - duplicate import: idempotent
- [ ] **Step 2:** Run + commit.

#### Task 32.3: Tests for `Wasp.eat_caterpillar_message` (the SQS parser)

**Files:**
- Create: `tests/integration/test_wasp_eat_caterpillar.py`

- [ ] **Step 1:** Curate ≥6 SQS message shapes: well-formed, missing required keys, unknown event type, malformed JSON, dup message-id, very-large payload.
- [ ] **Step 2:** Assert the parser's classification + side effects for each.
- [ ] **Step 3:** Run + commit.

#### Task 32.4: Tests for `Repository.raise_or_update_sca_issues`

**Files:**
- Create: `tests/integration/test_repository_raise_sca_issues.py`

- [ ] **Step 1:** Mock the GitHub Issues API via `responses`. Cover:
  - new vuln → new issue created
  - existing vuln + open issue → no-op
  - existing vuln + closed issue → re-opened
  - GitHub 5xx → graceful retry (or graceful abort, depending on current behavior)
- [ ] **Step 2:** Run + commit.

---

## Wave 2 — Schema Discipline (Sprints 33–34)

### Sprint 33: ORM `Index()` declarations + `alembic check` in CI

**Goal:** Make every alembic-side index visible to `alembic revision --autogenerate`, and stop schema drift from ever shipping again.

#### Task 33.1: Inventory alembic indexes vs. ORM `Index()` declarations

**Files:**
- Read: `alembic/versions/0002_fk_indexes.py`
- Read: `libinv/models.py`

- [ ] **Step 1:** Extract every `op.create_index(...)` from `alembic/versions/0002_fk_indexes.py`. Build a list: index name, table, columns, options.
- [ ] **Step 2:** Diff against `__table_args__` / `Index(...)` declarations in `libinv/models.py`. List the deltas.
- [ ] **Step 3:** Save the diff to a scratch comment in the sprint task tracker (not committed).

#### Task 33.2: Add the missing `Index()` declarations to ORM models

**Files:**
- Modify: `libinv/models.py` (will be split in Sprints 39–41; if this lands before, modify the split files instead)

- [ ] **Step 1:** For each missing index, add to the model class's `__table_args__`:

  ```python
  __table_args__ = (
      Index("ix_<table>_<col>", "<col>"),
      ...
  )
  ```

  Use the **same name** as in alembic so autogenerate detects them as already-present.
- [ ] **Step 2:** Run `alembic upgrade head` then `alembic revision --autogenerate -m "verify no drift"` against a fresh DB. Expected: empty migration body.
- [ ] **Step 3:** If non-empty, the index names or column lists don't match — reconcile.
- [ ] **Step 4:** Commit `libinv/models.py` (or model-split files).

#### Task 33.3: Add `alembic check` to CI

**Files:**
- Modify: `.github/workflows/<the-CI-workflow>.yml`

- [ ] **Step 1:** Add a CI step that runs against the pytest-postgresql DB:

  ```yaml
  - name: Detect schema drift
    run: |
      alembic upgrade head
      alembic check
  ```

  `alembic check` exits non-zero if `--autogenerate` would produce any operations.
- [ ] **Step 2:** Push to a throw-away branch and confirm the step is required.
- [ ] **Step 3:** Commit + open PR.

---

### Sprint 34: `nullable=False` audit + column type corrections

**Goal:** Stop accepting `NULL` where the domain actually disallows it; replace string-typed dates/hex digests with proper types.

#### Task 34.1: Audit `nullable=` discipline across `libinv/models.py`

**Files:**
- Modify: `libinv/models.py` (post-split files if Wave 4 has shipped)
- Create: new alembic revision in `alembic/versions/` for the column-level `ALTER COLUMN ... SET NOT NULL` statements

- [ ] **Step 1:** Generate a report of columns that omit `nullable=`:

  ```bash
  grep -nE "Column\(" libinv/models.py | grep -vE "nullable=|primary_key=True|ForeignKey" > /tmp/audit.txt
  ```

- [ ] **Step 2:** Triage each row in `/tmp/audit.txt`:
  - Required-by-domain → set `nullable=False`
  - Truly optional → set `nullable=True` explicitly (no defaults)
- [ ] **Step 3:** For each column flipped to `nullable=False`, ensure no existing rows are NULL — write a backfill query first if needed.
- [ ] **Step 4:** Generate the migration: `alembic revision -m "tighten nullability"`. Verify it makes sense.
- [ ] **Step 5:** Run `alembic upgrade head` then `pytest tests/integration -v`. Iterate until green.
- [ ] **Step 6:** Commit.

#### Task 34.2: `epss.epss_date` String(20) → `Date`

**Files:**
- Modify: `libinv/models.py:1632` (EPSS class — will move to `libinv/models/epss.py` after Sprint 40)
- Create: alembic revision

- [ ] **Step 1:** Change `epss_date = Column(String(20), nullable=True)` to `epss_date = Column(Date, nullable=True)`.
- [ ] **Step 2:** Generate migration:

  ```sql
  ALTER TABLE epss ALTER COLUMN epss_date TYPE DATE USING epss_date::date;
  ```

  Inspect any rows that fail to cast — write a cleanup step before the type change if needed.
- [ ] **Step 3:** Update every consumer of `epss_date` (search: `grep -rn "epss_date" libinv tests`) for the new type. Likely: `cli/epss.py`, `api/actionable/...`, tests.
- [ ] **Step 4:** Run `pytest tests/integration -v`. Commit.

#### Task 34.3: `String(N)` audit — `commit` column + others

**Files:**
- Modify: relevant model files
- Create: alembic revision

- [ ] **Step 1:** Inventory `String(N)` columns: `grep -nE "Column\(String\(" libinv/models.py`.
- [ ] **Step 2:** For each `String(N)` where N > what the domain produces (e.g. `commit = Column(String(128))` for a 40-char git SHA):
  - Tighten to the real maximum (`String(40)`).
  - Backfill check: `SELECT COUNT(*) FROM <table> WHERE LENGTH(<col>) > <new_max>` must be 0.
- [ ] **Step 3:** Apply migrations; run tests; commit.

---

## Wave 3 — Performance (Sprints 35–38)

### Sprint 35: Pool tuning + global `statement_timeout` + ThreadPool cap

**Goal:** Three small, low-risk ops wins.

#### Task 35.1: Connection pool tuning

**Files:**
- Modify: `libinv/base.py:20`

- [ ] **Step 1:** Change the engine creation:

  ```python
  Engine = db.create_engine(
      DB_STRING,
      pool_pre_ping=True,
      pool_size=10,
      max_overflow=20,
      pool_recycle=1800,
      pool_use_lifo=True,
  )
  ```

- [ ] **Step 2:** Run integration tests: `pytest tests/integration -v`.
- [ ] **Step 3:** Document the new pool sizes in `docs/architecture.rst` (under the runtime topology section).
- [ ] **Step 4:** Commit:

  ```bash
  git add libinv/base.py docs/architecture.rst
  git commit -m "perf: tune SQLAlchemy pool — size=10, overflow=20, recycle=1800, LIFO

  Stock defaults (size=5, overflow=10) can starve under
  4×gunicorn + crons + daemon concurrent workloads.
  LIFO favors warm connections."
  ```

#### Task 35.2: Global `statement_timeout` via `before_request`

**Files:**
- Modify: `libinv/api/app.py` (or wherever Flask app factory lives)
- Modify: `libinv/api/actionable/statistics.py:378` (remove per-route SET — now redundant)

- [ ] **Step 1:** Locate the Flask app factory. Add:

  ```python
  @app.before_request
  def _set_statement_timeout():
      db.session.execute(text("SET LOCAL statement_timeout = '30s'"))
  ```

  Use `SET LOCAL` (per-transaction) so it doesn't leak to the next checked-out connection.
- [ ] **Step 2:** Remove the per-route `SET statement_timeout` from `libinv/api/actionable/statistics.py:378`.
- [ ] **Step 3:** Add a regression test: `tests/integration/test_statement_timeout.py` — make a request to `/v3/repositories` with a crafted slow query (a `pg_sleep(31)` injection won't work; instead, monkeypatch the route to call `pg_sleep` and assert the request raises a query-cancel error inside 31s).
- [ ] **Step 4:** Run + commit.

#### Task 35.3: `ThreadPoolExecutor` `max_workers=4` cap

**Files:**
- Modify: `libinv/cli/actionable.py:58`, `libinv/cli/actionable.py:191`

- [ ] **Step 1:** Both sites: change `ThreadPoolExecutor()` to `ThreadPoolExecutor(max_workers=4)`. Add a one-line comment explaining: "Capped to avoid pool starvation; each worker holds a DB connection."
- [ ] **Step 2:** Run + commit.

---

### Sprint 36: Statistics parallelism + `_compute_statistics` decomposition

**Goal:** 3–5× faster dashboard via parallel group queries, with smaller helper functions per group.

#### Task 36.1: Decompose `_compute_statistics` into per-group helpers

**Files:**
- Modify: `libinv/api/actionable/statistics.py`

- [ ] **Step 1:** Identify the 6 stats groups (env_stats, pod_stats, organization_stats, repository_stats, + 2 others — confirm by reading current code).
- [ ] **Step 2:** Extract each group into a top-level `def _compute_<group>_stats(session) -> Dict`. Each helper opens its own session via `session_scope()` (so it can run in a thread).
- [ ] **Step 3:** `_compute_statistics` becomes a dispatcher calling the helpers serially still (parallelism in next task).
- [ ] **Step 4:** Run `pytest tests/integration -k statistics -v`. Commit.

#### Task 36.2: Parallelize across groups

**Files:**
- Modify: `libinv/api/actionable/statistics.py`

- [ ] **Step 1:** In `_compute_statistics`:

  ```python
  from concurrent.futures import ThreadPoolExecutor
  with ThreadPoolExecutor(max_workers=3) as ex:
      futures = {name: ex.submit(helper) for name, helper in helpers.items()}
      results = {name: f.result() for name, f in futures.items()}
  ```

  `max_workers=3` matches your pool tuning headroom from Sprint 35.
- [ ] **Step 2:** Add a benchmark test: `tests/integration/test_statistics_perf.py` — populates a fixture DB and asserts wall-clock < (sum of individual queries × 0.6).
- [ ] **Step 3:** Run + commit.

---

### Sprint 37: `lazy="raise"` policy + selectinload annotations

**Goal:** Eliminate the 33 default-lazy relationships' silent N+1 risk.

#### Task 37.1: Add a dev-mode `lazy="raise"` toggle

**Files:**
- Modify: `libinv/base.py`
- Modify: `libinv/env.py` (if env-var parsing centralized there)

- [ ] **Step 1:** Add env var `LIBINV_STRICT_LAZY` (default `false`).
- [ ] **Step 2:** In `libinv/base.py`, when `LIBINV_STRICT_LAZY=true`, monkey-patch every relationship on `Base.registry.mappers` to set `lazy="raise"`. Or — cleaner — accept that we'll change each `relationship(...)` declaration manually (next task) and gate the change with a per-relationship `lazy=...` set via env (use `lazy="raise_on_sql" if STRICT else "select"`).

  Recommended: instead of monkey-patch, set each relationship's `lazy=` directly (Task 37.2) and use the env only as a sentinel that the production lazy is `"select"`.
- [ ] **Step 3:** Document in `docs/architecture.rst`: dev sets `LIBINV_STRICT_LAZY=true`; prod leaves default.

#### Task 37.2: Audit every `relationship(...)` in models

**Files:**
- Modify: `libinv/models.py` (or split files post-Wave-4)

- [ ] **Step 1:** `grep -n "relationship(" libinv/models.py` → 34 declarations.
- [ ] **Step 2:** For each, add `lazy="raise_on_sql"` if it's never traversed in a hot path, else `lazy="select"` with a `# Audit: callers must use selectinload(<rel>)` comment.
- [ ] **Step 3:** Find every traversal site:

  ```bash
  grep -rn "\.<rel_name>\b" libinv/api libinv/cli libinv/scanners
  ```

  At each site, add a `selectinload(<rel>)` to the parent query.
- [ ] **Step 4:** Run `LIBINV_STRICT_LAZY=true pytest tests/integration -v`. Any `InvalidRequestError: 'Lazy load operation of attribute … cannot proceed'` is an un-annotated traversal — fix it.
- [ ] **Step 5:** Commit.

---

### Sprint 38: Bulk-upsert N+1 patterns

**Goal:** Two specific hot loops: EPSS CVE collection and Actionable.populate / fetch_and_store_versions.

#### Task 38.1: `cli/epss.py:_collect_cves_for_projects` bulk path

**Files:**
- Modify: `libinv/cli/epss.py:_collect_cves_for_projects`

- [ ] **Step 1:** Currently N projects → N queries. Replace with a single `SELECT … WHERE project_id IN :ids` then a dict-keyed lookup.
- [ ] **Step 2:** Add a regression test: `tests/integration/test_epss_collect_cves_bulk.py` — assert the query count is constant under load (use `sqlalchemy.event` to count `before_cursor_execute`).
- [ ] **Step 3:** Run + commit.

#### Task 38.2: `Actionable.populate` and `fetch_and_store_versions` → `INSERT … ON CONFLICT`

**Files:**
- Modify: `libinv/models.py` (Actionable class — will move post-Sprint 41) — `populate`, `fetch_and_store_versions`

- [ ] **Step 1:** Identify the per-row `get_or_create` + commit pattern. Replace with `postgresql.insert(<table>).values(rows).on_conflict_do_nothing()` (or `do_update` if the existing code updates).
- [ ] **Step 2:** Hoist the loop's `session.commit()` to after the bulk operation.
- [ ] **Step 3:** Regression test: `tests/integration/test_actionable_populate_bulk.py` — populate 1000 rows, assert ≤2 INSERTs at the SQL level.
- [ ] **Step 4:** Run + commit.

---

## Wave 4 — Architecture Refactor (Sprints 39–44)

> **Invariant for Wave 4:** every split MUST keep `libinv/models.py` importable with the old class names (re-export shim) to avoid a Big-Bang breakage. Drop the shim only in a Sprint 56+ cleanup, after everything internal has migrated to the new import paths.

### Sprint 39: models.py split — Phase 1 (Image domain)

**Goal:** Extract Image, ImagePackageAssociation, Layer, LatestImage into `libinv/models/image.py`.

#### Task 39.1: Convert `libinv/models.py` to a package

**Files:**
- Rename: `libinv/models.py` → `libinv/models/__init__.py`
- Create: `libinv/models/_base.py` (re-exports `Base`, `TimestampMixin`, `PackageLicenseAssociation` initially)

- [ ] **Step 1:** Move `Base = declarative_base()` and `class TimestampMixin` to `libinv/models/_base.py`.
- [ ] **Step 2:** Re-export from `__init__.py`:

  ```python
  from libinv.models._base import Base, TimestampMixin  # noqa: F401
  ```

- [ ] **Step 3:** Run `pytest tests/integration -v` — confirm no break.
- [ ] **Step 4:** Commit.

#### Task 39.2: Extract Image domain

**Files:**
- Create: `libinv/models/image.py`
- Modify: `libinv/models/__init__.py` (re-export)

- [ ] **Step 1:** Move `class Image`, `class ImagePackageAssociation`, `class Layer`, `class LatestImage` to `libinv/models/image.py`. Imports: `from libinv.models._base import Base, TimestampMixin`.
- [ ] **Step 2:** Re-export from `libinv/models/__init__.py`:

  ```python
  from libinv.models.image import Image, ImagePackageAssociation, Layer, LatestImage  # noqa: F401
  ```

- [ ] **Step 3:** Run **the full test suite** (`pytest -v`). Any `ImportError` is a missed re-export.
- [ ] **Step 4:** Commit.

---

### Sprint 40: models.py split — Phase 2 (Package, Vulnerability, License, EPSS)

#### Task 40.1: Extract Package + License domain

**Files:**
- Create: `libinv/models/package.py`
- Modify: `libinv/models/__init__.py`

- [ ] **Step 1:** Move `class Package`, `class PackageLicenseAssociation`, `class License`.
- [ ] **Step 2:** Re-export.
- [ ] **Step 3:** Test + commit.

#### Task 40.2: Extract Vulnerability domain

**Files:**
- Create: `libinv/models/vulnerability.py`
- Modify: `libinv/models/__init__.py`

- [ ] **Step 1:** Move `class Vulnerability`, `class VulnerabilityPackageAssociation`.
- [ ] **Step 2:** Re-export.
- [ ] **Step 3:** Test + commit.

#### Task 40.3: Extract EPSS

**Files:**
- Create: `libinv/models/epss.py`
- Modify: `libinv/models/__init__.py`

- [ ] **Step 1:** Move `class EPSS`.
- [ ] **Step 2:** Re-export.
- [ ] **Step 3:** Test + commit.

---

### Sprint 41: models.py split — Phase 3 (Wasp, Actionable, Repository, Account, Secbug, Sast)

#### Task 41.1: Extract Wasp + SQS handling

**Files:**
- Create: `libinv/models/wasp.py`

- [ ] **Step 1:** Move `class Wasp`. Audit any module-level helpers used only by Wasp; co-locate them.
- [ ] **Step 2:** Re-export + test + commit.

#### Task 41.2: Extract Actionable family

**Files:**
- Create: `libinv/models/actionable.py`

- [ ] **Step 1:** Move `class Actionable`, `class ActionablePackageAvailableVersion`, `class Repository_ActionablePackageAvailableVersion` (rename in Sprint 46.4).
- [ ] **Step 2:** Re-export + test + commit.

#### Task 41.3: Extract Repository / Account / DeploymentCheckpoint

**Files:**
- Create: `libinv/models/repository.py`, `libinv/models/account.py`, `libinv/models/deployment.py`

- [ ] **Step 1:** Move per file. Repository pulls along its many helpers; move them to a sibling `repository_helpers.py` if they bloat the file.
- [ ] **Step 2:** Re-export + test + commit.

#### Task 41.4: Extract Secbug + Sast

**Files:**
- Create: `libinv/models/secbug.py`, `libinv/models/sast.py`

- [ ] **Step 1:** Move `class Secbug`, `class SastLobMetaData`, `class SastResult`.
- [ ] **Step 2:** Re-export + test + commit.

#### Task 41.5: Empty `libinv/models/__init__.py` apart from re-exports

**Files:**
- Modify: `libinv/models/__init__.py`

- [ ] **Step 1:** Confirm `libinv/models/__init__.py` is now <50 lines, all imports. Anything still in there belongs in a domain file.
- [ ] **Step 2:** `mypy libinv/models` clean.
- [ ] **Step 3:** Commit.

---

### Sprint 42: scancodeio_client.py split (transport / dtos / endpoints)

#### Task 42.1: Convert to a package

**Files:**
- Rename: `libinv/services/scancodeio_client.py` → `libinv/services/scancodeio/__init__.py`

- [ ] **Step 1:** Move the existing file content into the new `__init__.py`. Run tests; nothing should change.
- [ ] **Step 2:** Commit.

#### Task 42.2: Extract `transport.py`

**Files:**
- Create: `libinv/services/scancodeio/transport.py`
- Modify: `libinv/services/scancodeio/__init__.py`

- [ ] **Step 1:** Move `requests.Session` creation, retry/backoff logic, and `_request_json` to `transport.py`.
- [ ] **Step 2:** Re-export from `__init__.py` so `ScancodeioClient(...)` still works at the top level.
- [ ] **Step 3:** Tests + commit. Address the open mypy `return-value` error on `get_project` (`scancodeio_client.py:225` per CHANGELOG) here — `_request_json` should return `dict[str, Any]` with a `cast(...)` if mypy complains.

#### Task 42.3: Extract `dtos.py` (TypedDict)

**Files:**
- Create: `libinv/services/scancodeio/dtos.py`

- [ ] **Step 1:** Move all TypedDicts to `dtos.py`.
- [ ] **Step 2:** Update `__init__.py` to re-export.
- [ ] **Step 3:** Tests + commit.

#### Task 42.4: Extract `endpoints.py`

**Files:**
- Create: `libinv/services/scancodeio/endpoints.py`

- [ ] **Step 1:** Move all endpoint-handler methods (list_projects, get_project, ...).
- [ ] **Step 2:** `ScancodeioClient` becomes a thin façade that composes Transport + Endpoints.
- [ ] **Step 3:** Tests + commit. Also: address the `list_projects_for_wasp` + `compare_builds.py` blocker noted in the CHANGELOG — document the upstream `ProjectFilterSet.Meta.fields` extension required, file the issue if not filed.

---

### Sprint 43: epss.py CLI service extraction

**Goal:** Extract the multi-page workflows in `--all-actionable-cves` and `calculate-package-epss` to service functions.

#### Task 43.1: Extract `--all-actionable-cves` to `libinv/services/epss/all_actionable_cves.py`

**Files:**
- Create: `libinv/services/epss/__init__.py`, `libinv/services/epss/all_actionable_cves.py`
- Modify: `libinv/cli/epss.py`

- [ ] **Step 1:** Move the inline workflow to a service function. CLI command becomes:

  ```python
  @cli.command()
  @click.option(...)
  def all_actionable_cves(...):
      run_all_actionable_cves(...)
  ```

- [ ] **Step 2:** Add unit tests for `run_all_actionable_cves`.
- [ ] **Step 3:** Tests + commit.

#### Task 43.2: Extract `calculate-package-epss`

**Files:**
- Create: `libinv/services/epss/calculate_package_epss.py`
- Modify: `libinv/cli/epss.py`

- [ ] **Step 1:** Same pattern.
- [ ] **Step 2:** Tests + commit.

#### Task 43.3: Verify cyclomatic complexity dropped

**Files:**
- N/A (verification)

- [ ] **Step 1:** Run `radon cc libinv/cli/epss.py -a -s -nc` (or equivalent). Expected per-function complexity <10.
- [ ] **Step 2:** If still >10, decompose further. Commit when clean.

---

### Sprint 44: RepositoryListingQuery builder + jira_integration signature consistency

#### Task 44.1: `RepositoryListingQuery` builder

**Files:**
- Create: `libinv/api/actionable/queries/repository_listing.py`
- Modify: `libinv/api/actionable/repositories.py`

- [ ] **Step 1:** Extract the 7 chained `.having(...)` filters + 3 facet aggregates + pagination into a `RepositoryListingQuery(session, params)` class with:
  - `.having_<filter>()` chainable methods
  - `.with_facet(<name>)` for aggregates
  - `.paginate(page, size)` terminal
  - `.execute() -> Tuple[List[Row], FacetMap]`
- [ ] **Step 2:** Refactor `repositories_listing` to use the builder.
- [ ] **Step 3:** **Critical:** all the new behavioral tests from Sprint 31 must still pass — no behavior change.
- [ ] **Step 4:** Commit.

#### Task 44.2: `PackageDetailsQuery` builder

**Files:**
- Create: `libinv/api/actionable/queries/package_details.py`
- Modify: `libinv/api/actionable/package_details.py`

- [ ] **Step 1:** Same pattern as 44.1.
- [ ] **Step 2:** Tests + commit.

#### Task 44.3: `jira_integration.py` session signature consistency

**Files:**
- Modify: `libinv/jira_integration.py`

- [ ] **Step 1:** Audit every helper for its `session=` parameter position. Make them all positional `def helper(session, …)` or all keyword `def helper(*, session, …)`.
- [ ] **Step 2:** Update callers.
- [ ] **Step 3:** Tests + commit.

---

## Wave 5 — Schema Deepening (Sprints 45–46)

### Sprint 45: Materialized view `sca_actionable_items` recovery

**Goal:** Recover the missing materialized view, add it to alembic, automate refresh.

#### Task 45.1: Recover the SQL

**Files:**
- Create: `alembic/versions/0003_sca_actionable_items_mat_view.py`

- [ ] **Step 1:** Find any historical reference to `sca_actionable_items` (search `git log -p -- "*.sql"` and `etc/metabase_cron.sh`). If no SQL exists, reconstruct from the columns that Metabase reads — interview the Metabase dashboard owner to enumerate columns + joins.
- [ ] **Step 2:** Write the `CREATE MATERIALIZED VIEW sca_actionable_items AS …` SQL.
- [ ] **Step 3:** Add `CREATE UNIQUE INDEX ON sca_actionable_items (id)` so `REFRESH CONCURRENTLY` works.
- [ ] **Step 4:** Add `DROP MATERIALIZED VIEW IF EXISTS` to the downgrade.

#### Task 45.2: Automate refresh

**Files:**
- Modify: `etc/metabase_cron.sh` or wherever the refresh would live
- Possibly: a new cron job in the crons container

- [ ] **Step 1:** Add a cron schedule: `*/15 * * * * REFRESH MATERIALIZED VIEW CONCURRENTLY sca_actionable_items`.
- [ ] **Step 2:** Verify under load.
- [ ] **Step 3:** Commit.

#### Task 45.3: (Optional) Partitioning evaluation for `repository_actionable_package_versions_association`

**Files:**
- Read-only

- [ ] **Step 1:** Run `SELECT pg_relation_size('repository_actionable_package_versions_association')` and `SELECT count(*)`.
- [ ] **Step 2:** **Gate:** only if rows > 50M or table > 20GB.
- [ ] **Step 3:** If gated in: write a follow-up plan (separate sprint Sprint 56+) for `PARTITION BY LIST (environment)`. If gated out: document the gate in `docs/architecture.rst`.

---

### Sprint 46: Comma-separated columns → relational + EPSS pruning + class rename

#### Task 46.1: `vulnerability_fix_versions` table

**Files:**
- Create: `alembic/versions/0004_vulnerability_fix_versions.py`
- Modify: `libinv/models/vulnerability.py`

- [ ] **Step 1:** New table `vulnerability_fix_versions` with `(vuln_id, package_id, fix_version)` and PK. Migration backfills by parsing the existing `fix` string on `vulnerability_package_association`.
- [ ] **Step 2:** Add ORM relationship `Vulnerability.fix_versions`.
- [ ] **Step 3:** Update every reader of `vulnerability_package_association.fix` to use the new relation. Search: `grep -rn "\.fix\b" libinv/`.
- [ ] **Step 4:** Drop the `fix` column in a follow-up migration (defer to a later sprint until all readers are migrated). For now, leave it readable but stop writing it.
- [ ] **Step 5:** Tests + commit.

#### Task 46.2: `vulnerability_related` table

**Files:**
- Create: `alembic/versions/0005_vulnerability_related.py`
- Modify: `libinv/models/vulnerability.py`

- [ ] **Step 1:** Same shape as 46.1, replacing `Vulnerability.related` string.
- [ ] **Step 2:** Tests + commit.

#### Task 46.3: EPSS row pruning

**Files:**
- Modify: `libinv/models/epss.py` (`EPSS.refresh_cves`)
- Or: new `libinv/services/epss/prune.py`

- [ ] **Step 1:** After the upsert, DELETE rows whose `epss_date` is older than the freshly-imported feed's most-recent `epss_date` minus a retention window (e.g. 90 days). Or — simpler — DELETE rows whose CVE is no longer in the latest feed.
- [ ] **Step 2:** Make retention configurable: `LIBINV_EPSS_RETENTION_DAYS` (default 90).
- [ ] **Step 3:** Add a test: populate 200 EPSS rows, refresh with 100, assert table shrinks.
- [ ] **Step 4:** Commit.

#### Task 46.4: Rename `Repository_ActionablePackageAvailableVersion`

**Files:**
- Modify: `libinv/models/actionable.py`

- [ ] **Step 1:** Rename **the Python class** to `RepositoryActionablePackageAvailableVersion`. Keep the table name (`repository_actionable_package_versions_association` or whatever it actually is) — only Python identifier changes.
- [ ] **Step 2:** Add a deprecated alias in `libinv/models/__init__.py`:

  ```python
  from libinv.models.actionable import RepositoryActionablePackageAvailableVersion
  # Deprecated; remove in Sprint 56+
  Repository_ActionablePackageAvailableVersion = RepositoryActionablePackageAvailableVersion
  ```

- [ ] **Step 3:** Update all internal imports to the new name.
- [ ] **Step 4:** Tests + commit.

---

## Wave 6 — Security & Code Quality (Sprints 47–50)

### Sprint 47: `shell=True` elimination + `except Exception` narrowing + init.sh hardening

#### Task 47.1: `cron_scheduler.py` `shell=True` → argv list

**Files:**
- Modify: `libinv/cron_scheduler.py:31` (the `Popen(command, shell=True, …)` call)

- [ ] **Step 1:** Replace with:

  ```python
  import shlex
  process = subprocess.Popen(
      shlex.split(command),
      shell=False,
      stdout=subprocess.PIPE,
      stderr=subprocess.STDOUT,
      universal_newlines=True,
      bufsize=1,
      env=env,
  )
  ```

- [ ] **Step 2:** Inventory the `JOBS` env values that get passed in production. Any value that depends on shell features (pipes, env-var expansion, `&&`) must be re-written as either an explicit argv list (preferred) or a small wrapper script in `etc/`.
- [ ] **Step 3:** Add a regression test: `tests/unit/test_cron_scheduler_no_shell.py` — assert `Popen` is called with `shell=False`.
- [ ] **Step 4:** Commit:

  ```bash
  git add libinv/cron_scheduler.py tests/unit/test_cron_scheduler_no_shell.py
  git commit -m "security: cron_scheduler — replace shell=True with shlex.split + shell=False

  Closes the last Sprint-0-class S0 audit finding. shell=True is
  RCE-shaped if JOBS becomes untrusted."
  ```

#### Task 47.2: `except Exception` narrowing in `libinv/models.py`

**Files:**
- Modify: per-class files post-Wave-4 (e.g. `libinv/models/repository.py`, `libinv/models/actionable.py`)

- [ ] **Step 1:** For each of the 8 `except Exception` sites (per assessment: lines 694, 877, 1209, 1249, 1386, 1512, 1609, 1711 in the pre-split file — re-locate post-split):
  - Trace which exceptions the protected code can actually raise (SQLAlchemy, requests, S3, JSON, GitHub).
  - Replace with the narrowest valid type-union: `except (SQLAlchemyError, requests.RequestException) as e: …`.
- [ ] **Step 2:** Keep `Exception` only at the **top of a daemon/cron loop** (legitimate guard). Each remaining `Exception` gets a `# noqa: BLE001` + comment explaining why.
- [ ] **Step 3:** Tests + commit.

#### Task 47.3: `init.sh` GitHub App private-key hardening

**Files:**
- Modify: `init.sh`
- Modify: Kubernetes manifests (if they live in this repo; otherwise, document the migration)

- [ ] **Step 1:** Option A (preferred): mount the GitHub App private key as a file via Kubernetes Secret. `init.sh` reads the file path from `GITHUB_APP_PRIVATE_KEY_PATH`.
- [ ] **Step 2:** Option B (fallback): base64-encode the env var; `init.sh` decodes.
- [ ] **Step 3:** Remove the `@@` → newline expansion logic.
- [ ] **Step 4:** Test in a staging env. Commit.

---

### Sprint 48: `session=None` removal + scio_models reflection guard + print→click.echo + SCIO HTTP default flip

#### Task 48.1: Remove `s = session or conn` fallback (17 sites)

**Files:**
- Modify: `libinv/models/*.py` (12 sites post-split), `libinv/scanners/repository_scanner/bridge.py` (2 sites), `libinv/scanners/.../SarifResult.py` (1 site), `libinv/base.py` (the proxy)

- [ ] **Step 1:** Change every helper signature from `def helper(..., session=None)` to `def helper(..., session)` (required positional).
- [ ] **Step 2:** Audit callers (search `grep -rn "\.helper(" libinv/`). For each caller that omitted `session`, add the explicit `session=session` argument.
- [ ] **Step 3:** Delete `_ConnDeprecationProxy` from `libinv/base.py`. Delete the `conn` alias if it's no longer used.
- [ ] **Step 4:** Run `mypy libinv` — any new errors are missed callers.
- [ ] **Step 5:** Tests + commit.

#### Task 48.2: Guard `scio_models.py` reflection behind `LIBINV_SCIO_USE_HTTP`

**Files:**
- Modify: `libinv/scio_models.py`
- Modify: `libinv/env.py`

- [ ] **Step 1:** At the top of `scio_models.py`, wrap the `inspect(engine).has_table(...)` reflection in:

  ```python
  if not LIBINV_SCIO_USE_HTTP:
      # existing reflection logic
      ...
  else:
      # define stub classes that raise on access, so that any caller in HTTP mode fails loud if it accidentally reaches into scio_models
      ...
  ```

- [ ] **Step 2:** Tests + commit.

#### Task 48.3: `print()` → `click.echo()` in CLI commands

**Files:**
- Modify: `libinv/cli/checkpoint.py:25,37,39,40`, `libinv/cli/actionable.py:223`

- [ ] **Step 1:** Replace each `print(...)` with `click.echo(...)`.
- [ ] **Step 2:** Tests + commit.

#### Task 48.4: `LIBINV_SCIO_USE_HTTP` default flip to `true`

**Files:**
- Modify: `libinv/env.py` (or wherever the env-var default lives)
- Modify: `docs/configuration.rst`

- [ ] **Step 1:** **Gate:** the new default ships only after the HTTP path has been stable for 2 sprints (Sprints 14–46 cover this).
- [ ] **Step 2:** Change the default. Update `docs/configuration.rst`.
- [ ] **Step 3:** Tests + commit.

---

### Sprint 49: mypy tightening — Part 1 (return-value, assignment)

**Goal:** Follow the Sprint-29 pattern: drop one suppression code per mini-step, fix the resulting errors.

#### Task 49.1: Drop `return-value` suppression from `libinv.models`

**Files:**
- Modify: `pyproject.toml:80` (`disable_error_code = ["return-value", "assignment", "var-annotated", "attr-defined", "misc"]` for `libinv.models`)
- Modify: `libinv/models/*.py` to fix the resulting errors

- [ ] **Step 1:** Remove `"return-value"` from the list.
- [ ] **Step 2:** Run `mypy libinv/models`. Fix every error — typically adds explicit `cast(...)` or fixes the annotation.
- [ ] **Step 3:** Tests + commit.

#### Task 49.2: Drop `assignment` suppression from `libinv.models`

**Files:**
- Same as 49.1

- [ ] **Step 1:** Remove `"assignment"`.
- [ ] **Step 2:** Fix errors. Common: SQLAlchemy `Column` → `Mapped[T]` declaration cleanup.
- [ ] **Step 3:** Tests + commit.

---

### Sprint 50: mypy tightening — Part 2 (var-annotated, attr-defined, misc/arg-type)

#### Task 50.1: Drop `var-annotated`

- [ ] **Step 1:** Remove. Fix.
- [ ] **Step 2:** Tests + commit.

#### Task 50.2: Drop `attr-defined`

- [ ] **Step 1:** Remove. Fix (typically `Mapped[]` annotations, or `Any` for legacy dynamic attrs with a comment).
- [ ] **Step 2:** Tests + commit.

#### Task 50.3: Drop `misc` (and `arg-type` in `libinv.api.*` / `libinv.scanners.*` / `libinv.cli.*`)

**Files:**
- Modify: `pyproject.toml:90` (the second override block)

- [ ] **Step 1:** Read the full `disable_error_code` list in the second override (Sprint 18+'s suppressions). It's `[`return-value, assignment, var-annotated, attr-defined, arg-type, misc`]` or similar.
- [ ] **Step 2:** Drop `misc`, then `arg-type`. Fix the resulting errors (Optional propagation is the common one).
- [ ] **Step 3:** Tests + commit per code.

---

## Wave 7 — Operations (Sprints 51–52)

### Sprint 51: Rate limiting + /metrics auth + daemon startup retry

#### Task 51.1: Rate limiting on API routes

**Files:**
- Modify: `requirements.txt` (add `Flask-Limiter==<latest 3.x>`)
- Modify: `libinv/api/app.py`

- [ ] **Step 1:** Initialize a `Limiter` with `key_func=get_remote_address` and `storage_uri="memory://"` (or Redis if you have it).
- [ ] **Step 2:** Apply `@limiter.limit("60/minute")` (tune per route) to `/v3/repositories`, `/v3/packages`, etc.
- [ ] **Step 3:** Leave `/healthz` and `/readyz` unlimited.
- [ ] **Step 4:** Decide on `/metrics`: either limit it heavily or fold it into Task 51.2's auth gate.
- [ ] **Step 5:** Tests + commit.

#### Task 51.2: `/metrics` authentication

**Files:**
- Modify: `libinv/api/metrics.py`

- [ ] **Step 1:** Choose: (a) Basic auth with a `LIBINV_METRICS_TOKEN` env var, or (b) network-level allowlist documented and enforced at ingress.
- [ ] **Step 2:** If (a): require an `Authorization: Bearer <token>` header. Compare with `hmac.compare_digest`. Return 401 on mismatch.
- [ ] **Step 3:** Update Prometheus scrape config example in `docs/deployment.rst`.
- [ ] **Step 4:** Tests + commit.

#### Task 51.3: Daemon startup retry on DB connect

**Files:**
- Modify: `libinv/cli/daemon.py`
- Possibly: `libinv/base.py` (lazy-init the engine)

- [ ] **Step 1:** Make engine creation lazy (move from import-time to first-use, or guard with `try/except OperationalError`).
- [ ] **Step 2:** Daemon's main wraps the first DB connect in a retry loop with exponential backoff (max 5 min).
- [ ] **Step 3:** Test by spinning the daemon against a not-yet-ready Postgres — should retry, not crash.
- [ ] **Step 4:** Tests + commit.

---

### Sprint 52: Crons graceful shutdown + S3 upload alerting + SQS DLQ

#### Task 52.1: Crons graceful shutdown on SIGTERM

**Files:**
- Modify: `libinv/cron_scheduler.py`

- [ ] **Step 1:** Install a `signal.signal(SIGTERM, …)` handler that:
  - sets a shutdown flag
  - waits for the currently-running job's subprocess to exit (up to a timeout)
  - then exits 0
- [ ] **Step 2:** Add a test: `tests/integration/test_cron_graceful_shutdown.py` — spawn the scheduler, SIGTERM it mid-job, assert no orphan subprocess.
- [ ] **Step 3:** Commit.

#### Task 52.2: `upload_to_s3` alerting on ClientError

**Files:**
- Modify: `libinv/helpers.py:121` (the `upload_to_s3` function)

- [ ] **Step 1:** Currently returns `False` on `ClientError`. Change to:
  - log at `ERROR` level with the bucket + key + boto3 error code
  - emit a Prometheus counter `libinv_s3_upload_failures_total{bucket=..., error_code=...}`
  - raise (preferred) or return False **with a comment naming each caller and confirming they check the return value**.
- [ ] **Step 2:** Audit callers: `grep -rn "upload_to_s3" libinv/`. Confirm each handles `False` (or migrate them to handle a raise).
- [ ] **Step 3:** Tests + commit.

#### Task 52.3: SQS dead-letter queue handling

**Files:**
- Modify: the daemon's message-loop module (probably `libinv/cli/daemon.py` or `libinv/sqs.py`)
- Possibly: Terraform/CDK config if AWS infra lives in this repo

- [ ] **Step 1:** Confirm with infra owners whether a DLQ already exists at the SQS-queue level (most likely yes). If not, document the required `RedrivePolicy: {deadLetterTargetArn, maxReceiveCount: 5}`.
- [ ] **Step 2:** On the daemon side: when a message handler raises, do NOT silently `continue` — let it bubble so SQS's visibility timeout + maxReceiveCount → DLQ flow works. Sprint 0's resilience change may have over-corrected; reconcile.
- [ ] **Step 3:** Add a `libinv_sqs_messages_failed_total{reason=…}` Prometheus counter and a structured log line for any handler failure.
- [ ] **Step 4:** Tests + commit.

---

## Wave 8 — Dependencies & Tooling (Sprints 53–54)

### Sprint 53: Dependencies refresh (batched PRs)

**Goal:** Apply Dependabot's batched updates in a controlled order.

#### Task 53.1: Cryptography + Requests batch

**Files:**
- Modify: `requirements.txt`

- [ ] **Step 1:** Bump `cryptography==43.0.1` → latest 43.x or current LTS. `requests==2.31.0` → latest 2.32.x.
- [ ] **Step 2:** Run full test suite. Read each library's release notes for breaking changes.
- [ ] **Step 3:** Commit.

#### Task 53.2: Flask + Werkzeug batch

- [ ] **Step 1:** Bump `Flask==3.0.3` → 3.1.x, `Werkzeug==3.0.3` → matching pair.
- [ ] **Step 2:** Tests + commit.

#### Task 53.3: boto3 + botocore batch

- [ ] **Step 1:** Bump together (they're co-versioned). `1.34.45` → latest 1.3x.
- [ ] **Step 2:** Tests + commit.

#### Task 53.4: semgrep batch

- [ ] **Step 1:** Bump `semgrep==1.61.1` → latest. Run a smoke `semgrep --config=auto` to verify rule compatibility.
- [ ] **Step 2:** Tests + commit.

#### Task 53.5: mysqlclient/psycopg2 stragglers audit

- [ ] **Step 1:** `grep -nE "(mysqlclient|psycopg2)" requirements.txt setup.cfg pyproject.toml`. Sprint 18 cleaned these; confirm nothing crept back.
- [ ] **Step 2:** Document the audit result in CHANGELOG.

---

### Sprint 54: Makefile tool bumps + uv.sources cleanup + dep source-of-truth + bandit baseline

#### Task 54.1: Makefile tool versions

**Files:**
- Modify: `Makefile:2-4`

- [ ] **Step 1:** Bump:
  - `GRYPE_VERSION=v0.54.0` → current v0.86.x or later
  - `SYFT_VERSION=v0.60.3` → current v1.x
  - `CRANE_VERSION=v0.12.1` → current v0.20.x or later
- [ ] **Step 2:** Pin `BAZEL_VERSION` and `GO_VERSION` explicitly (currently bare/loose).
- [ ] **Step 3:** Build + smoke-test each tool.
- [ ] **Step 4:** Commit.

#### Task 54.2: Remove `[tool.uv.sources]` from `pyproject.toml`

**Files:**
- Modify: `pyproject.toml:31-34`

- [ ] **Step 1:** Delete the `[tool.uv.sources]` and `[dependency-groups]` blocks.
- [ ] **Step 2:** Confirm no tooling references them.
- [ ] **Step 3:** Commit.

#### Task 54.3: Single source of truth for dependencies

**Files:**
- Decision needed: keep `requirements.txt` OR migrate to `pyproject.toml [project] + uv.lock` OR `setup.cfg`.

- [ ] **Step 1:** Pick ONE. The most modern choice is `pyproject.toml [project.dependencies]` + a lockfile (`uv lock` produces `uv.lock`, or `pip-compile` produces `requirements.txt`).
- [ ] **Step 2:** Move every dependency declaration there. Delete the other(s).
- [ ] **Step 3:** Update `Dockerfile*` `RUN pip install …` lines accordingly.
- [ ] **Step 4:** Tests + commit.

#### Task 54.4: Bandit baseline file

**Files:**
- Create: `.bandit` (or `bandit.yaml`)

- [ ] **Step 1:** Run `bandit -r libinv -f json -o /tmp/bandit.json`. Triage every finding:
  - real issue → fix
  - intentional → add to `# nosec` with a comment
  - false positive → exclude in baseline
- [ ] **Step 2:** Generate baseline: `bandit -r libinv --baseline /tmp/bandit_baseline.json`.
- [ ] **Step 3:** Make bandit blocking in CI (currently non-blocking per Sprint 17).
- [ ] **Step 4:** Commit.

---

## Wave 9 — Documentation (Sprint 55)

### Sprint 55: Documentation closure

#### Task 55.1: README architecture diagram refresh

**Files:**
- Modify: `README.rst`
- Modify: `docs/images/<architecture-diagram>.png` (or whatever it references)

- [ ] **Step 1:** Re-render the diagram from `docs/architecture.rst` (Sprint 21's correct version). Export to PNG/SVG; replace the stale file.
- [ ] **Step 2:** Update README reference path.
- [ ] **Step 3:** Commit.

#### Task 55.2: `docs/scancodeio_contract.md` — resolve 6 open questions

**Files:**
- Modify: `docs/scancodeio_contract.md`

- [ ] **Step 1:** For each of the 6 open questions, write the resolution determined during Sprints 15–23.
- [ ] **Step 2:** If any are still open, mark them `STATUS: BLOCKED on <X>` with the actual blocker (e.g. upstream `ProjectFilterSet.Meta.fields`).
- [ ] **Step 3:** Commit.

#### Task 55.3: CHANGELOG.md — append Sprints 25–29 (and as we go: every sprint 30+)

**Files:**
- Modify: `CHANGELOG.md`

- [ ] **Step 1:** Add entries for Sprints 25, 26, 27, 28, 29 mirroring git log.
- [ ] **Step 2:** Going forward: every sprint's last commit appends its own CHANGELOG entry. Add a `make changelog-check` target that fails if HEAD's commit doesn't touch CHANGELOG.md.
- [ ] **Step 3:** Commit.

#### Task 55.4: Delete `pylintrc` (20KB unused) and `etc/pre-commit` (superseded)

**Files:**
- Delete: `pylintrc`
- Delete: `etc/pre-commit`

- [ ] **Step 1:** Confirm pylint is not referenced anywhere: `grep -rn "pylint" .github/ docs/ Makefile`.
- [ ] **Step 2:** Confirm `.pre-commit-config.yaml` exists and is the canonical config.
- [ ] **Step 3:** `git rm pylintrc etc/pre-commit`. Commit.

---

## Coverage Matrix

This table is the contract: every action item from the post-Sprint-30 assessment maps to a sprint/task. Tick the right column as work lands.

| Section | Item | Sprint.Task | Status |
| ------- | ---- | ----------- | ------ |
| 1.1 | models.py split (3 phases) | 39.1, 39.2, 40.1, 40.2, 40.3, 41.1, 41.2, 41.3, 41.4, 41.5 | ☐ |
| 1.2 | scancodeio_client.py split | 42.1, 42.2, 42.3, 42.4 | ☐ |
| 1.3 | statistics.py `_compute_statistics` decomposition | 36.1 | ☐ |
| 1.4 | jira_integration.py session signature consistency | 44.3 | ☐ |
| 1.5 | cli/epss.py CLI service extraction | 43.1, 43.2, 43.3 | ☐ |
| 1.6 | RepositoryListingQuery / PackageDetailsQuery builders | 44.1, 44.2 | ☐ |
| 2a | `lazy="raise"` policy + selectinload | 37.1, 37.2 | ☐ |
| 2b | Global `statement_timeout` | 35.2 | ☐ |
| 2c | Connection pool tuning | 35.1 | ☐ |
| 2d | `ThreadPoolExecutor max_workers=4` | 35.3 | ☐ |
| 2e1 | EPSS bulk-fetch | 38.1 | ☐ |
| 2e2 | Actionable.populate / fetch_and_store_versions ON CONFLICT | 38.2 | ☐ |
| 2f | Statistics group queries parallelization | 36.2 | ☐ |
| 3.1 | ORM `Index()` declarations | 33.1, 33.2 | ☐ |
| 3.2 | `nullable=False` audit | 34.1 | ☐ |
| 3.3 | Repository_… composite index review / partition gate | 45.3, 46.4 | ☐ |
| 3.4 | `vulnerability_package_association.fix` → table | 46.1 | ☐ |
| 3.5 | `Vulnerability.related` → table | 46.2 | ☐ |
| 3.6 | `String(N)` audit | 34.3 | ☐ |
| 3.7 | `alembic check` in CI | 33.3 | ☐ |
| 3.8 | `epss.epss_date` String → Date | 34.2 | ☐ |
| 3.9 | EPSS row pruning | 46.3 | ☐ |
| 3.10 | Materialized view `sca_actionable_items` recovery | 45.1, 45.2 | ☐ |
| 4.1 | `shell=True` → shlex.split | 47.1 | ☐ |
| 4.2 | `except Exception` narrowing (8 sites) | 47.2 | ☐ |
| 4.3 | `print()` → `click.echo()` | 48.3 | ☐ |
| 4.4a | mypy `return-value` + `assignment` | 49.1, 49.2 | ☐ |
| 4.4b | mypy `var-annotated` + `attr-defined` + `misc`/`arg-type` | 50.1, 50.2, 50.3 | ☐ |
| 4.5 | `session=None` fallback removal (17 sites) | 48.1 | ☐ |
| 4.6 | scio_models.py reflection guard | 48.2 | ☐ |
| 4.7 | init.sh GitHub App key hardening | 47.3 | ☐ |
| 4.8 | Repository_ActionablePackageAvailableVersion rename | 46.4 | ☐ |
| 5.1 | E2E test (SQS → daemon → DB → API) | 31.1 | ☐ |
| 5.2 | Behavioral tests for api/actionable/repositories.py | 31.2 | ☐ |
| 5.3 | cli/bridge.py connect tests | 32.1 | ☐ |
| 5.4 | cli/import_and_improve_from_metapod.py tests | 32.2 | ☐ |
| 5.5 | Wasp.eat_caterpillar_message tests | 32.3 | ☐ |
| 5.6 | Repository.raise_or_update_sca_issues tests | 32.4 | ☐ |
| 5.7 | pytest-postgresql / testcontainers | 30.1, 30.2 | ☐ |
| 5.8 | CI integration tests with alembic upgrade head | 30.3 | ☐ |
| 6.1 | Rate limiting (flask-limiter) | 51.1 | ☐ |
| 6.2 | /metrics authentication | 51.2 | ☐ |
| 6.3 | Daemon startup retry | 51.3 | ☐ |
| 6.4 | Crons graceful shutdown (SIGTERM) | 52.1 | ☐ |
| 6.5 | upload_to_s3 alerting | 52.2 | ☐ |
| 6.6 | SQS dead-letter queue handling | 52.3 | ☐ |
| 6.7 | `LIBINV_SCIO_USE_HTTP` default flip | 48.4 | ☐ |
| 7.1 | Dependency batch refresh | 53.1, 53.2, 53.3, 53.4 | ☐ |
| 7.2 | `pyproject.toml [tool.uv.sources]` cleanup | 54.2 | ☐ |
| 7.3 | Makefile tool version bumps | 54.1 | ☐ |
| 7.4 | Dependency source-of-truth consolidation | 54.3 | ☐ |
| 7.5 | mysqlclient/psycopg2 stragglers audit | 53.5 | ☐ |
| 7.6 | Bandit baseline file | 54.4 | ☐ |
| 8.1 | README architecture diagram refresh | 55.1 | ☐ |
| 8.2 | docs/scancodeio_contract.md open questions | 55.2 | ☐ |
| 8.3 | CHANGELOG.md Sprints 25–29 catch-up | 55.3 | ☐ |
| 8.4 | Delete `pylintrc` | 55.4 | ☐ |
| 8.5 | Delete `etc/pre-commit` | 55.4 | ☐ |

**Audit gate before declaring this plan complete:** every row must be either marked done in this matrix or explicitly deferred with a written reason (e.g. partitioning gate not tripped → 45.3 deferred).

---

## Execution

Plan complete and saved to `docs/superpowers/plans/2026-05-24-post-audit-remediation-plan.md`. Two execution options:

**1. Subagent-Driven (recommended)** — Dispatch a fresh subagent per sprint (or per task within a sprint), with two-stage review between tasks (spec-compliance then code-quality). Best for the architecture-refactor waves where each task is independent and you want clean blast-radius control. Required sub-skill: `superpowers:subagent-driven-development`.

**2. Inline Execution** — Execute tasks in this session using `superpowers:executing-plans`. Best for the early waves (30–34) where state needs to flow between tasks (test infrastructure, CI changes, schema migrations).

**Recommendation:** Mix the two. Inline for Waves 1–2 (Sprints 30–34) so test infra and schema discipline land coherently. Subagent-driven for Waves 3–9 (Sprints 35–55) — each sprint there is independent enough to delegate.

**Which approach?**
