===============
Troubleshooting
===============

A cookbook of the failure modes the Sprint 0-26 audit work has
already produced in development and CI, plus the resolution for
each. Sprint numbers in parentheses point at the change that
introduced (or hardened) the behaviour; see :doc:`configuration`
for the environment-variable reference and :doc:`deployment` for
the production wiring.

******************************************
API returns 503 ``auth not configured``
******************************************

**Symptom** — ``PUT`` / ``POST`` / ``PATCH`` / ``DELETE`` requests
return HTTP 503 with the body ``auth not configured on server``.
``GET`` / ``HEAD`` / ``OPTIONS`` requests succeed.

**Cause** — ``LIBINV_API_TOKEN`` is unset. Sprint 0 made the API
fail closed instead of silently allowing mutations, so an unset
token deliberately blocks writes.

**Fix** — set ``LIBINV_API_TOKEN`` to a 32-byte random string and
restart all API pods. See :doc:`deployment` for the recommended
``Secret`` wiring.

***************************************************
Tests pass in CI but integration tests are skipped
***************************************************

**Symptom** — ``tests/integration/`` reports ``no tests ran`` or
each integration test is marked ``SKIPPED``.

**Cause** — ``TEST_DATABASE_URL`` is unset. Sprint 4's
``conftest.py`` and ``pytest.ini``'s ``collect_ignore_glob`` skip
the entire integration tree cleanly when the variable is missing,
so the suite never fails — it simply does not run.

**Fix** — point the variable at a writable PostgreSQL database
and re-run:

.. code-block:: bash

   export TEST_DATABASE_URL=postgresql://postgres:postgres@localhost:5432/libinv_test
   make integration-tests

CI sets the same variable against a ``postgres:15`` service
container in ``.github/workflows/coverage.yml`` (Sprints 5, 24).

**********************************************************
``DeprecationWarning: libinv.base.conn is deprecated``
**********************************************************

**Symptom** — a one-shot ``DeprecationWarning`` is emitted from
``libinv/base.py`` when code reads attributes off ``conn``.

**Cause** — Sprint 13 replaced the module-level ``conn`` with a
``_ConnDeprecationProxy``. Direct attribute access (e.g.
``conn.query(Model)``) still works but is on the migration path
to removal.

**Fix** — pick one of:

* New CLI / scanner code: open a context manager.

  .. code-block:: python

     from libinv.base import session_scope

     with session_scope() as session:
         ...

* Model methods: pass an explicit session.

  .. code-block:: python

     Actionable.get_latest(session=session, ...)

The ``or conn`` fallback inside model methods is the only
sanctioned use of the proxy; see :doc:`architecture` for the four
coexisting session patterns.

***************************************************************************
``ImportError: cannot import name 'connect_using_queue_message_agreement'``
***************************************************************************

**Symptom** — import-time ``ImportError`` referencing the SQS
handler.

**Cause** — Sprint 3 split ``libinv/api/actionable.py`` into a
package, but the SQS bridge in
``libinv/scanners/repository_scanner/bridge.py`` is unchanged. An
out-of-date import (or a stale ``.pyc``) is pointing at a path
that never existed.

**Fix** — verify the import is

.. code-block:: python

   from libinv.scanners.repository_scanner.bridge import (
       connect_using_queue_message_agreement,
   )

and delete any cached ``__pycache__`` directories under the
scanner package.

*****************************************************************
SCIO HTTP client fails: 404 on ``/api/projects/.../packages/``
*****************************************************************

**Symptom** — ``ScancodeioClient`` raises ``HTTPError: 404`` for
``GET /api/projects/<uuid>/packages/``. The SQL path
(``LIBINV_SCIO_USE_HTTP`` unset) still works.

**Cause** — the upstream ScanCode.io REST API path changed in a
release newer than the one Sprints 14-15 verified against.

**Fix** — pin the ``scancodeio`` deployment to a known-good tag
(see ``docs/scancodeio_contract.md``) or patch
``libinv/services/scancodeio_client.py`` to call the renamed
endpoint. As a stopgap, flip ``LIBINV_SCIO_USE_HTTP=false`` to
fall back to the legacy SQL reflection path
(``libinv/scio_models.py``).

.. note::

   A future change will expose an ``LIBINV_SCIO_BASE_PATH``
   override so the prefix can be tuned without a code patch. It
   is not implemented yet.

*****************************************
Cron job logs missing ``request_id``
*****************************************

**Symptom** — log records emitted by a cron-spawned child process
have no ``request_id`` field even though the parent scheduler
logs them correctly.

**Cause** — one of the two halves of the Sprint 21 / Sprint 22
chain is missing: either the child is not running with
``LIBINV_LOG_FORMAT=json`` (so ``JsonFormatter`` is not installed
and the contextvar is never serialised), or the child binary did
not inherit ``LIBINV_REQUEST_ID`` from the scheduler.

**Fix** —

#. Confirm ``LIBINV_LOG_FORMAT=json`` is set on the ``crons``
   container, not just on ``api``.
#. Confirm the child command does not strip the env (``env -i``,
   ``sudo -i`` without ``--preserve-env``, etc.).
#. Confirm the child's entry point calls
   ``libinv.logger.bind_request_id_from_env()`` early
   (Sprint 22); the standard CLI entry points already do.

******************************************
``alembic upgrade head`` fails on a fresh DB
******************************************

**Symptom** — ``alembic upgrade head`` against an empty database
fails with ``relation "libinv.<table>" does not exist`` or
``schema "libinv" does not exist``.

**Cause** — the Sprint 2 baseline is intentionally empty; it
stamps whatever schema ``etc/initdb/init.sql`` produced. On a
completely empty database, alembic has nothing to attach the
baseline to.

**Fix** — bootstrap the schema first, then stamp and upgrade:

.. code-block:: bash

   psql "$DB_STRING" -f etc/initdb/init.sql
   alembic stamp 0001_baseline
   alembic upgrade head

The integration test ``tests/integration/test_alembic_upgrade.py``
(Sprint 26) runs exactly this path in CI.

******************************************
``pytest`` fails with ``mypy: 1 error``
******************************************

**Symptom** — the linting job in CI fails on the ``mypy`` step,
or ``make check`` reports a type error locally.

**Cause** — Sprint 19 promoted ``mypy`` to CI-blocking. Any new
type error fails the build instead of being warned about.

**Fix** — reproduce locally before pushing:

.. code-block:: bash

   mypy --config-file pyproject.toml

then fix the reported error. ``bandit`` and ``pip-audit`` are
deliberately non-blocking (Sprint 17) so they print findings but
do not fail CI.

****************************************
``bandit`` / ``pip-audit`` fail in CI
****************************************

**Symptom** — the linting job prints ``bandit`` or ``pip-audit``
findings.

**Cause** — Sprint 17 wires both tools as **advisory** signals.
They report new findings but do not fail the build.

**Fix** — triage each finding in PR review; suppress false
positives via the tool's standard mechanisms (``# nosec`` for
bandit, ``--ignore-vuln`` for pip-audit). If the build is
actually red because of these tools, double-check the workflow
file — they are not supposed to be blocking yet.

*****************************************************
``scan_invocations_total`` counter does not increment
*****************************************************

**Symptom** — ``libinv_scan_invocations_total`` stays at zero
even though scans are running.

**Cause** — Sprint 25 instruments three scan paths:
``scan_image_index`` (image scanner),
``connect_using_queue_message_agreement`` (SQS bridge), and
``run_cdxgen_scan`` (CycloneDX). Any other scan entry point is
not instrumented.

**Fix** — confirm scans are flowing through one of the three
instrumented paths. If a new scan path was added, wrap the entry
point with the ``observe_scan`` helper in
``libinv/api/metrics.py`` (Sprint 25 / 26) so successes and
failures both update the counters.
