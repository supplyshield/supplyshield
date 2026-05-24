########
Overview
########

*****
Tools
*****

SupplyShield primarily leverages the following tools:

#. `cdxgen <https://github.com/CycloneDX/cdxgen>`_ - For generating codebase SBOM
#. `osv <https://osv.dev/>`_ - SCA database for cdxgen
#. `syft <https://github.com/anchore/syft/>`_ - For generating docker container SBOM
#. `grype <https://github.com/anchore/grype/>`_ - For generating docker container SCA
#. `scancodeio <https://github.com/supplyshield/scancodeio/>`_ - Pipeline for SupplyShield scans
#. `semgrep <https://semgrep.dev/>`_ - For performing SAST
#. `Metabase <https://github.com/metabase/metabase>`_ - Provides a dashboard for visualisation.

******************
Core Services
******************

SupplyShield runs in a multi-service mode to optimize for respective use cases: 

#. daemon: Polls deployment events from SQS queue to trigger scans.
#. cron: Cron job to sync Atlassian Jira with SupplyShield dashboard
#. api: Provides the actionable dashboard and other relevant SupplyShield APIs

.. warning::
    SupplyShield is under active development, releases are available under the "releases" section on github

SupplyShield tech stack is Python, Flask, PostgreSQL, Docker and several libraries.

For a deeper walk-through of the codebase layout — including the
``libinv/api/actionable/`` blueprint split, the ``libinv/services/`` layer,
the session lifecycle, and CI hardening — see :doc:`architecture`. For a
catalogue of every environment variable, including the audit-driven
additions (``LIBINV_API_TOKEN``, ``LIBINV_SCIO_USE_HTTP``,
``LIBINV_LOG_FORMAT``, ``TEST_DATABASE_URL``), see :doc:`configuration`.

.. include:: daemon.rst
.. include:: cron.rst
.. include:: api.rst

Copyright notice
-----------------

Copyright (c) SupplyShield and others. All rights reserved.
