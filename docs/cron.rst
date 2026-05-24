Cron
^^^^

SupplyShield cron helps in syncing with existing Jira tracker and ingests the security metrics in order to show them on a
unified dashboard.

The cron functionality is also leveraged by other syncing methods such as getting all pod/subpod
mappings from a specific external endpoint called the metapod.

Each scheduled job invocation (``libinv/cron_scheduler.py::execute_command``)
mints a UUID and sets it on the ``request_id_var`` ``ContextVar`` for the
duration of the job (Sprint 21). The same id is forwarded into the child
process via the ``LIBINV_REQUEST_ID`` environment variable, so any log
formatter that reads the contextvar (notably ``JsonFormatter``, enabled via
``LIBINV_LOG_FORMAT=json`` — see :doc:`configuration`) emits a stable
correlation id across the parent scheduler and the child command. The
contextvar is restored to its prior value in ``finally``, so nested or
sequential job invocations remain isolated.

SupplyShield expects the following contract from metapod to sync pod and subpod. 

.. code-block:: python

    {
        "details": [
            {
            "name": "repository_name",
            "subpod": {
                "name": "subpod_name",
                "pod": {
                "name": "pod_name"
                }
            }
            },
            ...
        ]
    }
