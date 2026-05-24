=============
Configuration
=============

SupplyShield is configured exclusively through environment variables.
The Docker Compose stack reads them from ``docker.env`` (copy
``docker.env.sample`` to get a starting point); manual installs can
export them in the shell or via a ``.env`` file picked up by
``python-dotenv`` from ``libinv/env.py``.

This page lists every variable read at runtime, grouped by concern,
plus the audit-driven additions from Sprints 0-16.

.. note::
   The README's *Installation & Setup → Required Configuration
   Variables* section is the authoritative example for a working
   docker.env. This page documents the semantics, defaults, and the
   sprint that introduced each setting.

***********
Audit-driven
***********

The following four variables were introduced or hardened during the
Sprint 0-16 audit. Set the required ones before starting any of the
``api``, ``daemon``, or ``cron`` processes.

+---------------------------+--------+--------------+--------+-------------------------------------------------+
| Variable                  | Type   | Default      | Sprint | Description                                     |
+===========================+========+==============+========+=================================================+
| ``LIBINV_API_TOKEN``      | string | unset        | 0      | Shared secret enforced by                       |
|                           |        |              |        | ``libinv/api/auth.py``. Required on every       |
|                           |        |              |        | ``PUT`` / ``POST`` / ``PATCH`` / ``DELETE``     |
|                           |        |              |        | request via the ``X-API-Token`` header. If the  |
|                           |        |              |        | variable is unset, mutating requests fail       |
|                           |        |              |        | closed with HTTP 503 ``auth not configured``.   |
|                           |        |              |        | GET / HEAD / OPTIONS are unaffected.            |
+---------------------------+--------+--------------+--------+-------------------------------------------------+
| ``LIBINV_SCIO_USE_HTTP``  | bool   | ``false``    | 14/15  | Opt-in flag for                                 |
|                           |        |              |        | ``libinv.services.scancodeio_client``. When     |
|                           |        |              |        | set to ``true`` / ``1`` / ``yes``, the          |
|                           |        |              |        | ScanCode.io client routes calls through the     |
|                           |        |              |        | REST API instead of the legacy SQL reflection   |
|                           |        |              |        | path in ``libinv/scio_models.py``. Any other    |
|                           |        |              |        | value keeps the SQL path.                       |
+---------------------------+--------+--------------+--------+-------------------------------------------------+
| ``LIBINV_LOG_FORMAT``     | string | unset        | 16     | When set to ``json``,                           |
|                           |        |              |        | ``install_json_formatter_if_configured()``      |
|                           |        |              |        | swaps the root logger's formatter for           |
|                           |        |              |        | ``libinv.logger.JsonFormatter``. Each record is |
|                           |        |              |        | emitted as one JSON object containing           |
|                           |        |              |        | ``time``, ``level``, ``name``, ``message``,     |
|                           |        |              |        | ``module``, ``lineno`` and the current          |
|                           |        |              |        | ``request_id``. Any other value keeps the       |
|                           |        |              |        | default colored ``CustomFormatter``.            |
+---------------------------+--------+--------------+--------+-------------------------------------------------+
| ``TEST_DATABASE_URL``     | string | unset        | 4      | SQLAlchemy URL used by ``tests/integration/``.  |
|                           |        |              |        | When unset, the integration suite is skipped    |
|                           |        |              |        | cleanly via ``pytest.ini``'s                    |
|                           |        |              |        | ``collect_ignore_glob`` and the                 |
|                           |        |              |        | ``conftest.py`` skip marker. CI sets it to      |
|                           |        |              |        | ``postgres://postgres:postgres@localhost:5432/  |
|                           |        |              |        | libinv_test`` against a ``postgres:15``         |
|                           |        |              |        | service container.                              |
+---------------------------+--------+--------------+--------+-------------------------------------------------+

********
Database
********

+---------------------------+--------+--------------+--------------------------------------------------+
| Variable                  | Type   | Default      | Description                                      |
+===========================+========+==============+==================================================+
| ``DB_HOSTNAME``           | string | unset        | PostgreSQL host used by ``libinv.base``.         |
+---------------------------+--------+--------------+--------------------------------------------------+
| ``DB_NAME``               | string | scancodeio   | PostgreSQL database name.                        |
+---------------------------+--------+--------------+--------------------------------------------------+
| ``DB_USERNAME``           | string | unset        | PostgreSQL username.                             |
+---------------------------+--------+--------------+--------------------------------------------------+
| ``DB_PASSWORD``           | string | unset        | PostgreSQL password.                             |
+---------------------------+--------+--------------+--------------------------------------------------+

These four values are combined into ``DB_STRING`` in
``libinv/env.py`` and passed to ``sqlalchemy.create_engine`` in
``libinv/base.py``.

***
AWS
***

+-------------------------------+--------+--------------------------------------------------+
| Variable                      | Type   | Description                                      |
+===============================+========+==================================================+
| ``AWS_DEFAULT_REGION``        | string | Used for the SQS / S3 clients in                 |
|                               |        | ``libinv/sqs.py`` and ``libinv/helpers.py``.     |
+-------------------------------+--------+--------------------------------------------------+
| ``AWS_ACCESS_KEY_ID``         | string | Standard AWS credential pair.                    |
+-------------------------------+--------+--------------------------------------------------+
| ``AWS_SECRET_ACCESS_KEY``     | string | Standard AWS credential pair.                    |
+-------------------------------+--------+--------------------------------------------------+
| ``SQS_QUEUE_NAME``            | string | Name of the SQS queue polled by the daemon.      |
+-------------------------------+--------+--------------------------------------------------+
| ``S3_BUCKET_NAME``            | string | Bucket for uploaded SBOMs / artefacts.           |
+-------------------------------+--------+--------------------------------------------------+

***
Git
***

+-------------------------------------+--------------------------------------------------+
| Variable                            | Description                                      |
+=====================================+==================================================+
| ``GIT_PROVIDER``                    | ``github`` or ``bitbucket``.                     |
+-------------------------------------+--------------------------------------------------+
| ``GIT_ORG``                         | Default organisation / workspace.                |
+-------------------------------------+--------------------------------------------------+
| ``GIT_SSH_KEY``                     | Optional path to an SSH key for cloning.         |
+-------------------------------------+--------------------------------------------------+
| ``GITHUB_APP_APP_ID``               | GitHub App id used by ``libinv/vcs.py`` for the  |
|                                     | JWT signing flow.                                |
+-------------------------------------+--------------------------------------------------+
| ``GITHUB_APP_INSTALLATION_ID``      | GitHub App installation id.                      |
+-------------------------------------+--------------------------------------------------+
| ``GITHUB_APP_PRIVATE_KEY_FILE``     | Path to the App's PEM private key. Default       |
|                                     | ``${HOME_DIR}/.github_app.pem``.                 |
+-------------------------------------+--------------------------------------------------+
| ``BITBUCKET_APP_TOKEN``             | Bitbucket personal access token (alternative to  |
|                                     | the GitHub App flow).                            |
+-------------------------------------+--------------------------------------------------+

************
Service URLs
************

+-------------------------------+--------------------------------------------------+
| Variable                      | Description                                      |
+===============================+==================================================+
| ``SCANCODEIO_URL``            | Base URL of the ScanCode.io service. Required    |
|                               | when ``LIBINV_SCIO_USE_HTTP=true``.               |
+-------------------------------+--------------------------------------------------+
| ``SCANCODEIO_API_KEY``        | Token used as ``Authorization: Token <key>``     |
|                               | by ``ScancodeioClient``.                         |
+-------------------------------+--------------------------------------------------+
| ``LIBINV_WEB_URL``            | Public URL of the SupplyShield web app. Used by  |
|                               | ``services/issue_reporter.py`` to build links    |
|                               | back to actionables.                             |
+-------------------------------+--------------------------------------------------+
| ``PURLDB_API_URL``            | PurlDB API endpoint.                             |
+-------------------------------+--------------------------------------------------+
| ``SERVICE_METADATA_URL``      | Optional metapod endpoint for pod / subpod sync. |
+-------------------------------+--------------------------------------------------+
| ``SLACK_URL``                 | Incoming webhook for daemon error notifications. |
+-------------------------------+--------------------------------------------------+

****
Jira
****

+--------------------+--------------------------------------------------+
| Variable           | Description                                      |
+====================+==================================================+
| ``JIRA_URL``       | Base URL of the Atlassian Jira instance synced   |
|                    | by ``libinv/jira_integration.py``.               |
+--------------------+--------------------------------------------------+
| ``JIRA_USER``      | Jira user.                                       |
+--------------------+--------------------------------------------------+
| ``JIRA_TOKEN``     | Jira API token.                                  |
+--------------------+--------------------------------------------------+

**********
Toolchains
**********

+----------------------------------------+--------------------------------------------------+
| Variable                               | Default                                          |
+========================================+==================================================+
| ``HOME_DIR``                           | ``$HOME``                                        |
+----------------------------------------+--------------------------------------------------+
| ``SYFT_BIN``                           | ``etc/third_party/syft``                         |
+----------------------------------------+--------------------------------------------------+
| ``GRYPE_BIN``                          | ``etc/third_party/grype``                        |
+----------------------------------------+--------------------------------------------------+
| ``CRANE_BIN``                          | ``etc/third_party/crane``                        |
+----------------------------------------+--------------------------------------------------+
| ``CDXGEN_BIN``                         | ``etc/third_party/node_modules/.bin/cdxgen``     |
+----------------------------------------+--------------------------------------------------+
| ``NPM_CONFIG_PREFIX``                  | ``etc/third_party/node_modules``                 |
+----------------------------------------+--------------------------------------------------+
| ``API_DOCS_FOLDER``                    | ``/app/docs/_build/html``                        |
+----------------------------------------+--------------------------------------------------+
| ``LIBINV_TEMP_DIR``                    | ``${HOME_DIR}/scans``                            |
+----------------------------------------+--------------------------------------------------+
| ``JAVA_HOME``                          | ``{}`` (JSON; per-base-image map)                |
+----------------------------------------+--------------------------------------------------+
| ``BASE_IMAGE_JAVA_VERSION_MAPPING``    | ``{}`` (JSON; image -> Java version map)         |
+----------------------------------------+--------------------------------------------------+
| ``IMAGE_SCAN_ENABLED``                 | ``False``                                        |
+----------------------------------------+--------------------------------------------------+
| ``GO_PRIVATE``                         | unset; forwarded to ``go env GOPRIVATE``.        |
+----------------------------------------+--------------------------------------------------+
| ``EXCLUDED_REPOS``                     | ``[]``                                           |
+----------------------------------------+--------------------------------------------------+

****
Cron
****

+--------------+--------------------------------------------------+
| Variable     | Description                                      |
+==============+==================================================+
| ``JOBS``     | JSON object of ``{name: {command, interval,      |
|              | timeout}}`` consumed by                          |
|              | ``libinv/cron_scheduler.py``. Default ``{}``     |
|              | (no jobs scheduled).                             |
+--------------+--------------------------------------------------+

The cron scheduler also exports ``LIBINV_REQUEST_ID`` into each child
process at run time (Sprint 21) so child loggers can correlate with
the parent's job id; this value is set by the scheduler itself and is
not a user-facing knob.
