==========
Deployment
==========

This page collects the audit-driven deployment notes for the
``api``, ``daemon``, and ``cron`` processes. It assumes a Kubernetes
target, but the env-var / probe / metrics conventions apply equally
to ``docker compose``. See :doc:`configuration` for the full variable
reference and :doc:`troubleshooting` when something misbehaves.

*****************
Quickstart (k8s)
*****************

The three long-lived processes share one image but differ in the
command they run. The pod spec below shows the API deployment with
the audit-mandated environment variables, liveness / readiness
probes, and a Prometheus scrape annotation. Adapt the ``command``
field for ``daemon`` and ``cron``.

.. code-block:: yaml

   apiVersion: apps/v1
   kind: Deployment
   metadata:
     name: supplyshield-api
   spec:
     replicas: 2
     selector:
       matchLabels:
         app: supplyshield-api
     template:
       metadata:
         labels:
           app: supplyshield-api
         annotations:
           prometheus.io/scrape: "true"
           prometheus.io/port: "8000"
           prometheus.io/path: "/metrics"
       spec:
         containers:
         - name: api
           image: ghcr.io/supplyshield/libinv:latest
           command: ["make", "startserver"]
           ports:
           - containerPort: 8000
           env:
           - name: LIBINV_API_TOKEN          # Sprint 0 — required, fail-closed
             valueFrom:
               secretKeyRef:
                 name: supplyshield-secrets
                 key: api-token
           - name: LIBINV_LOG_FORMAT         # Sprint 16 — JSON logs
             value: "json"
           - name: LIBINV_SCIO_USE_HTTP      # Sprints 14/15/22/23 — opt-in
             value: "true"
           - name: DB_HOSTNAME
             value: "postgres.svc"
           - name: DB_USERNAME
             valueFrom:
               secretKeyRef:
                 name: supplyshield-secrets
                 key: db-username
           - name: DB_PASSWORD
             valueFrom:
               secretKeyRef:
                 name: supplyshield-secrets
                 key: db-password
           livenessProbe:                    # Sprint 23 — process-liveness only
             httpGet:
               path: /healthz
               port: 8000
             initialDelaySeconds: 10
             periodSeconds: 10
           readinessProbe:                   # Sprint 23 — also verifies DB
             httpGet:
               path: /readyz
               port: 8000
             initialDelaySeconds: 15
             periodSeconds: 10
             failureThreshold: 3

``/healthz`` is always 200 once the Flask app has started; it does
**not** touch the database, so it is safe as a liveness probe and
will not flap during a transient DB outage. ``/readyz`` runs
``SELECT 1`` against the engine and returns 503 if the database is
unreachable — keep it as the readiness probe so traffic is shifted
away from a pod that has lost its DB connection (Sprint 23).

``/metrics`` is GET-only and exempt from the ``X-API-Token`` auth
(Sprint 24). Either rely on the pod annotations above for a
node-exporter-style scrape job, or define an explicit
``ServiceMonitor`` resource if you run the Prometheus Operator:

.. code-block:: yaml

   apiVersion: monitoring.coreos.com/v1
   kind: ServiceMonitor
   metadata:
     name: supplyshield-api
   spec:
     selector:
       matchLabels:
         app: supplyshield-api
     endpoints:
     - port: http
       path: /metrics
       interval: 30s

The exported counters / histograms include
``libinv_http_requests_total``, ``libinv_http_request_duration_seconds``
(Sprint 24) and ``libinv_scan_invocations_total`` /
``libinv_scan_failures_total`` (Sprints 25-26).

**********
Migrations
**********

Schema changes are managed by ``alembic``. The baseline revision
``0001_baseline`` (Sprint 2) is intentionally empty — it stamps
whatever schema ``etc/initdb/init.sql`` produced when the database
was created. The follow-up revision ``0002_fk_indexes`` (Sprint 2)
adds 17 foreign-key indexes and 2 composite indexes using
``CREATE INDEX CONCURRENTLY IF NOT EXISTS``, so applying it does
**not** take an ``ACCESS EXCLUSIVE`` lock and is safe to run against
a live database.

The recommended deployment sequence is:

#. **Fresh database** — bootstrap the schema with the raw SQL once,
   then let alembic stamp it:

   .. code-block:: bash

      psql "$DB_STRING" -f etc/initdb/init.sql
      alembic stamp 0001_baseline
      alembic upgrade head

#. **Existing database** — run alembic on every deploy as part of
   the rollout's ``initContainer`` or pre-deploy job:

   .. code-block:: bash

      alembic upgrade head

The integration test ``tests/integration/test_alembic_upgrade.py``
(Sprint 26) exercises ``alembic upgrade head`` against an empty
PostgreSQL container on every CI run, so a broken migration cannot
reach ``master``.

*******
Secrets
*******

Store the following as Kubernetes ``Secret`` resources and mount
them through ``secretKeyRef`` (as shown above). Restarting all pods
is the rotation path — no in-process refresh is supported.

* ``LIBINV_API_TOKEN`` — 32-byte random string (e.g.
  ``openssl rand -hex 32``). Sprint 0 made the API fail closed if
  this is unset, so the secret must exist before the first pod
  starts. Rotate by writing the new value to the ``Secret`` and
  doing a ``kubectl rollout restart deployment/supplyshield-api``.
* ``GITHUB_APP_PRIVATE_KEY`` — the PEM file contents with newlines
  replaced by ``@@``. ``init.sh`` expands the ``@@`` markers back to
  real newlines and writes ``${HOME_DIR}/.github_app.pem`` on
  container start. Storing the key on a single line keeps it
  shell-safe for ``docker.env`` and Kubernetes ``Secret``
  ``stringData``.
* ``SCANCODEIO_API_KEY`` — optional. Set it when the upstream
  ScanCode.io instance enforces token auth; the HTTP client
  (Sprint 14) sends it as ``Authorization: Token <key>``.
* ``JIRA_TOKEN`` — optional, consumed only by the ``secbug-sync``
  cron job. Leave it unset on deployments that do not run that job.

***********************
Cron / scheduled jobs
***********************

The ``crons`` service reads its job list from the ``JOBS`` env var,
a JSON object of the form
``{ "<name>": {"command": "...", "interval": "10m", "timeout": 600} }``.
``libinv/cron_scheduler.py`` mints a fresh UUID per job invocation,
binds it to the ``request_id_var`` ``ContextVar`` for the duration
of the job, and forwards the same id into the child process via
``LIBINV_REQUEST_ID`` (Sprint 21). The child CLI inherits the env
var and ``logger.bind_request_id_from_env()`` (Sprint 22) re-binds
it to the contextvar so JSON log records on the child side carry
the same correlation id as the parent scheduler's records.

See :doc:`cron` for the metapod sync contract; the correlation-id
behaviour applies to every job in ``JOBS``, not just the syncs.

*************
Observability
*************

* **Structured logs** — set ``LIBINV_LOG_FORMAT=json`` (Sprint 16)
  and ``libinv.logger.JsonFormatter`` is installed on the root
  logger. Each record is a single JSON object with
  ``time``, ``level``, ``name``, ``message``, ``module``,
  ``lineno`` and ``request_id``. Pair with a log aggregator (Loki,
  CloudWatch Logs, Elastic, etc.); ``request_id`` is the join key
  across the API, daemon, and cron streams.
* **Metrics** — Prometheus scrapes ``/metrics`` (see above).
  Configure recording / alerting rules against the
  ``libinv_*`` series.
* **Correlation id, end to end** — the API middleware
  (``libinv/api/request_id.py``, Sprint 16) reads or mints
  ``X-Request-Id``, binds it to ``request_id_var`` and echoes it
  back on the response. The cron scheduler (Sprint 21) mints a
  UUID per job and forwards it to the child via
  ``LIBINV_REQUEST_ID``. Both code paths write to the same
  ``ContextVar`` consumed by ``JsonFormatter``, so log lines from
  the API, the cron parent, and the cron child can all be joined
  on a single ``request_id``.
