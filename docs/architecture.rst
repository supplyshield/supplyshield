============
Architecture
============

This page documents the SupplyShield codebase layout after the
Sprint 0-20 audit-driven refactor. It is intended as a reading
companion to the source tree: every module mentioned below is a
real directory or file on disk.

********
Overview
********

SupplyShield is a Python application built around three long-lived
processes that share a single PostgreSQL database and a common
``libinv`` package:

#. **daemon** — polls deployment messages off SQS, then orchestrates
   SBOM / SCA / SAST scans against the codebase that was deployed.
#. **cron** — a ``schedule``-driven runner (``libinv/cron_scheduler.py``)
   that fires periodic jobs (EPSS refresh, safe-version discovery,
   metapod sync, etc.).
#. **api** — the Flask web app under ``libinv/api/`` that serves the
   actionables dashboard, the SAST triage UI, and a small set of
   integration APIs.

All three processes import ``libinv.base`` for the engine + scoped
session, ``libinv.env`` for configuration, ``libinv.models`` for the
ORM, and ``libinv.logger`` for the optional JSON formatter.

**********
Module map
**********

The following table summarises the top-level packages under
``libinv/`` and the supporting directories at the repository root.

+-----------------------------------+---------------------------------------------------+
| Path                              | Role                                              |
+===================================+===================================================+
| ``libinv/api/``                   | Flask web app: blueprints, auth, request-id       |
|                                   | middleware, SAST triage routes.                   |
+-----------------------------------+---------------------------------------------------+
| ``libinv/api/actionable/``        | Post-Sprint-3 blueprint package. Replaces the     |
|                                   | original 1218-LOC ``actionable.py`` single file.  |
|                                   | Submodules: ``dashboards``, ``repositories``,     |
|                                   | ``statistics``, ``package_details``,              |
|                                   | ``package_scan``, ``_common``.                    |
+-----------------------------------+---------------------------------------------------+
| ``libinv/services/``              | Service layer extracted from ``models.py``        |
|                                   | (Sprints 2, 14, 15). Hosts                        |
|                                   | ``issue_reporter`` (renders GitHub issue          |
|                                   | content) and ``scancodeio_client`` (typed HTTP    |
|                                   | client for ScanCode.io's REST API).               |
+-----------------------------------+---------------------------------------------------+
| ``libinv/models.py``              | SQLAlchemy ORM. Classmethods now accept an        |
|                                   | explicit ``session=`` kwarg (Sprints 7, 10) so    |
|                                   | callers can pass a request-scoped session         |
|                                   | instead of relying on the module-level ``conn``.  |
+-----------------------------------+---------------------------------------------------+
| ``libinv/base.py``                | Engine, ``sessionmaker``, ``ScopedSession``,      |
|                                   | the ``session_scope()`` context manager, and the  |
|                                   | deprecated ``conn`` proxy (Sprint 13). The engine |
|                                   | is created with a tuned pool (Sprint 35.1):       |
|                                   | ``pool_size=10``, ``max_overflow=20``,            |
|                                   | ``pool_recycle=1800``, ``pool_use_lifo=True``,    |
|                                   | ``pool_pre_ping=True``. A global Flask            |
|                                   | ``before_request`` hook in ``libinv/api/app.py``  |
|                                   | sets ``statement_timeout = '30s'`` on every       |
|                                   | request (Sprint 35.2).                            |
+-----------------------------------+---------------------------------------------------+
| ``libinv/cli/``                   | Click-based CLI entry points: ``actionable``,    |
|                                   | ``daemon``, ``bridge``, ``epss``, ``checkpoint``, |
|                                   | ``query``, ``secbugs``,                           |
|                                   | ``import_and_improve_from_metapod``,              |
|                                   | ``process_message``,                              |
|                                   | ``update_all_images_with_base_image``,            |
|                                   | ``scan_stage_ecr_image``.                         |
+-----------------------------------+---------------------------------------------------+
| ``libinv/scanners/``              | Scanner orchestrators split into                  |
|                                   | ``image_scanner/`` (ECR / SBOM / SCA /            |
|                                   | base-image) and ``repository_scanner/``           |
|                                   | (``bridge.py`` SQS handler, ``cdx_scanner``,      |
|                                   | ``scancodeio`` driver, ``sast/`` semgrep          |
|                                   | runner).                                          |
+-----------------------------------+---------------------------------------------------+
| ``libinv/logger.py``              | Coloured ``CustomFormatter``, opt-in              |
|                                   | ``JsonFormatter`` (Sprint 16), and the            |
|                                   | ``request_id_var`` ``ContextVar`` consumed by     |
|                                   | both the Flask middleware and the cron runner.   |
+-----------------------------------+---------------------------------------------------+
| ``libinv/cron_scheduler.py``      | ``schedule``-driven cron runner. Each job is      |
|                                   | assigned a fresh UUID and that id is propagated   |
|                                   | both into ``request_id_var`` (for log records)    |
|                                   | and into the child process via                    |
|                                   | ``LIBINV_REQUEST_ID`` (Sprint 21).                |
+-----------------------------------+---------------------------------------------------+
| ``alembic/``                      | Schema migrations. ``0001_baseline`` stamps the   |
|                                   | ``etc/initdb/init.sql`` schema; ``0002_fk_index`` |
|                                   | adds 17 FK indexes + 2 composite indexes using    |
|                                   | ``CREATE INDEX CONCURRENTLY`` (Sprint 2).         |
+-----------------------------------+---------------------------------------------------+
| ``tests/``                        | Unit tests + doctests (Sprint 3). No database     |
|                                   | required.                                         |
+-----------------------------------+---------------------------------------------------+
| ``tests/integration/``            | Database-backed integration tests (Sprint 4).     |
|                                   | Gated on ``TEST_DATABASE_URL``; skipped cleanly   |
|                                   | when the variable is unset.                       |
+-----------------------------------+---------------------------------------------------+

*****************
Session lifecycle
*****************

Pre-audit, every call site used a single module-level ``conn`` bound
to the engine at import time. That global is now an explicit
deprecation surface, and four patterns coexist while the migration
finishes:

#. ``libinv.base.conn`` — a ``_ConnDeprecationProxy`` (Sprint 13) that
   wraps the scoped session. Direct attribute access (e.g.
   ``conn.query(...)``) emits a one-shot ``DeprecationWarning``. The
   ``or conn`` fallback used inside ``session=None`` methods is the
   only sanctioned use of this symbol; it is preserved precisely so
   the ~30 remaining call sites keep working.

#. ``libinv.base.ScopedSession`` — a ``scoped_session`` factory bound
   to a thread-local registry. The Flask app installs a
   ``teardown_request`` hook in ``libinv/api/app.py`` that calls
   ``ScopedSession.remove()`` after every request (Sprint 0), so a
   gunicorn worker thread never carries a stale identity map across
   requests.

#. ``libinv.base.session_scope()`` — a context manager (Sprint 2)
   that yields a thread-scoped ``Session``, commits on clean exit,
   rolls back on exception, and removes the session in ``finally``.
   New code should prefer this over either of the above.

#. **Explicit ``session=`` parameter** — model classmethods such as
   ``Actionable.get_latest`` and ``Actionable.get_safe_versions``
   accept an optional ``session`` kwarg (Sprints 7, 10). The body
   uses ``s = session or conn`` so callers can pass a request-scoped
   session in tests and from new code paths, while legacy callers
   keep working unmodified.

*************
Observability
*************

Structured logging is opt-in. The defaults remain unchanged so
existing log scrapers continue to work.

* ``libinv/logger.py`` exposes a ``JsonFormatter`` and an
  ``install_json_formatter_if_configured()`` helper. The helper is a
  no-op unless ``LIBINV_LOG_FORMAT=json`` is set (Sprint 16); when
  enabled, every log record is emitted as a single JSON object with
  a ``request_id`` field sourced from the ``ContextVar``.
* ``libinv/api/request_id.py`` installs Flask ``before_request`` /
  ``after_request`` hooks that read the inbound ``X-Request-Id``
  header (or mint a fresh UUID), bind it to both Flask's ``g`` and
  the ``request_id_var`` ``ContextVar``, and echo it back on the
  response header so callers can correlate logs across services
  (Sprint 16).
* ``libinv/cron_scheduler.py::execute_command`` mints a UUID per
  cron job, sets ``request_id_var`` for the duration of the job, and
  forwards the same id into the child process via the
  ``LIBINV_REQUEST_ID`` environment variable (Sprint 21). The
  contextvar is restored to its prior value in ``finally``.

************
CI hardening
************

Continuous integration runs from the workflows under
``.github/workflows/``:

* ``coverage.yml`` runs the unit suite and the integration suite
  against a ``postgres:15`` service container, with
  ``TEST_DATABASE_URL`` pointing at the service (Sprint 5).
* ``linting.yml`` runs ``make check`` (``ruff`` + ``black --check``),
  then ``mypy --config-file pyproject.toml``, ``bandit -r libinv/``
  and ``pip-audit -r requirements.txt`` (Sprint 17). The ``mypy``
  step is enforcing; ``bandit`` and ``pip-audit`` are advisory.
* ``.github/dependabot.yml`` schedules weekly pip and GitHub-Actions
  updates with grouping for SQLAlchemy / Flask / lint tools
  (Sprint 18).
* ``.pre-commit-config.yaml`` installs the same lint/format hooks
  locally so contributors can run ``pre-commit run --all-files``
  before pushing (Sprint 18).

******************
Materialized views
******************

``libinv.sca_actionable_items``
  Denormalises ``repository_actionable_package_versions_association``
  joined to ``repositories``, ``wasps``,
  ``actionable_package_available_versions``, and ``safe_actionable``
  into one row per actionable finding (one per
  ``(repository, environment, package, version)``). Defined by alembic
  revision ``0006_sca_actionable_view`` (Sprint 45.1) and carries a
  ``UNIQUE INDEX (id)`` derived from the association row's ``uuid``
  so ``REFRESH … CONCURRENTLY`` is safe.

  Backs the Metabase actionable-package dashboard — Metabase reads the
  view directly so a single ``SELECT`` replaces the four-table join
  each question would otherwise emit. ``etc/scripts/metabase_cron.sh``
  runs ``REFRESH MATERIALIZED VIEW CONCURRENTLY
  libinv.sca_actionable_items`` on a ``*/15 * * * *`` cadence
  (Sprint 45.2). Staleness tradeoff: a finding ingested at HH:01
  becomes visible to Metabase at HH:15 (worst case); shorten the
  cadence in the host crontab if the dashboard needs to be fresher
  — the unique index makes CONCURRENTLY safe at any cron tick width.

************************
Partitioning evaluation
************************

(Sprint 45.3) ``repository_actionable_package_versions_association`` is the
fact table behind the SCA dashboard and grows in proportion to
``repositories × packages × environments``. Whether to partition it is a
gated decision: partitioning has non-trivial operational cost (per-partition
indexes, refresh windows, query planner attach/detach) so it should be
deferred until the table actually exceeds the thresholds at which a single
heap starts to bite.

**Gate.** Partition only when EITHER of the following holds on the
production database, observed for two consecutive weeks:

* ``pg_relation_size`` > **20 GB**, OR
* approximate row count (``pg_class.reltuples`` after a recent
  ``ANALYZE``) > **50 000 000** (50M).

Operators can sample the gate with::

    SELECT
      pg_size_pretty(pg_relation_size('repository_actionable_package_versions_association')) AS heap_size,
      (SELECT reltuples::bigint FROM pg_class
        WHERE relname = 'repository_actionable_package_versions_association') AS approx_rows;

Below the gate, the existing FK + composite indexes (declared in alembic
``0002_fk_indexes``) are sufficient and partition overhead is net-negative.

**Proposed scheme.** When the gate trips, the recommended layout is
``PARTITION BY LIST (environment)``. ``environment`` is a low-cardinality,
high-selectivity column (most dashboard queries already filter on it via
``having()``), so list partitioning yields immediate partition pruning on
the hot Metabase query path without forcing a hash-mod redistribution.
Each environment becomes one child partition; a ``DEFAULT`` partition
absorbs unknown / newly added environments until a follow-up migration
splits them out.

**Status.** Skeleton revision landed
(``alembic/versions/0009_partition_stub.py`` — no-op until gate trips).
When operator stats trip the gate, expand the ``upgrade()`` body using
the SQL sketch in the migration's docstring (``CREATE TABLE ... LIKE ...
INCLUDING ALL PARTITION BY LIST (environment)``, per-environment
``CREATE TABLE ... PARTITION OF ...``, then an ``ALTER TABLE`` rename
swap). The pytest-postgresql ephemeral DB used in CI never crosses the
50M / 20 GB threshold, so we cannot meaningfully exercise the real
partition migration from this repo — the no-op is intentional and
re-evaluation tracks the next quarterly inventory snapshot.

************
Test layout
************

* ``tests/`` — unit tests and doctests. Runs without a database. Covers
  helpers, auth, semgrep, the daemon shutdown loop, ``session_scope``,
  the issue reporter, the request-id middleware, the VCS / ECR
  clients, the ScanCode.io HTTP client, and the cron correlation-id
  contract.
* ``tests/integration/`` — DB-backed tests. Exercises EPSS bulk
  upsert, ``session_scope`` commit / rollback semantics,
  ``mark_latest_version`` persistence, N+1 eager-loading guards on
  the actionable dashboard, and the statistics aggregates. Skipped
  cleanly when ``TEST_DATABASE_URL`` is unset (see
  ``tests/integration/conftest.py`` and ``pytest.ini``'s
  ``collect_ignore_glob``).
