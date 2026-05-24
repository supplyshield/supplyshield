Web Service
^^^^^^^^^^^

The SupplyShield Web service is a Flask-based Web application that hosts:

#. Actionables dashboard
#. A triager dashboard
#. APIs for 3rd party integrations
#. This documentation

The APIs are meant for anything that could require a web app frontend in SupplyShield.

Actionables Dashboard
*********************

This dashboard helps development teams to trace a vulnerable dependency chain. It can be found at
``http://<host>/actionable/``. The dashboard is populated by the ScanCode.io pipeline.

Internally the dashboard routes live in the ``libinv/api/actionable/`` blueprint
package (Sprint 3). The original single-file ``libinv/api/actionable.py`` was
split into focused modules — ``dashboards.py``, ``repositories.py``,
``statistics.py``, ``package_details.py``, ``package_scan.py`` and a shared
``_common.py`` — registered against a single ``actionable`` Flask blueprint.
External callers that imported helpers such as ``fetch_repository`` from
``libinv.api.actionable`` continue to work because the package's ``__init__``
re-exports them.

Global ``X-API-Token`` auth (``libinv/api/auth.py``, Sprint 0) is enforced for
every ``PUT`` / ``POST`` / ``PATCH`` / ``DELETE`` request. The ``X-Request-Id``
middleware (``libinv/api/request_id.py``, Sprint 16) mints or echoes a
correlation id on every request; see :doc:`architecture` for the full flow.

Triager Dashboard
*****************

SAST components deployed in SupplyShield might detect false positives, thus they are required to be verified
by a triager. The SAST Triage dashboard can be found at: 
``http://<host>/libinv/sast/<SAST_REPORT_UNIQUE_IDENTIFIER>``

Documentation
*************

This documentation is available at ``http://<host>/docs``. 
