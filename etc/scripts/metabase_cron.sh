#!/usr/bin/env bash
#
# Sprint 45.2 — refresh the ``libinv.sca_actionable_items`` materialized
# view that backs the Metabase actionable dashboard.
#
# Schedule (set on the host crontab in the crons container):
#
#     */15 * * * * /opt/supplyshield/etc/scripts/metabase_cron.sh
#
# REFRESH MATERIALIZED VIEW CONCURRENTLY requires a unique index over
# the view (created by alembic revision 0006_sca_actionable_view).
# CONCURRENTLY means readers running Metabase questions against the view
# during the refresh see the previous snapshot — never a partially-rebuilt
# table — at the cost of holding two copies on disk for the duration of
# the refresh. The 15-minute cadence keeps the dashboard sufficiently
# fresh for SCA triage while bounding refresh CPU to <= ~7% of an hour.
#
# Staleness tradeoff: a finding ingested at HH:01 is visible to Metabase
# at HH:15 (worst case). Tighten by lowering the cron cadence if needed;
# the unique index keeps CONCURRENTLY safe to run more often.
set -euo pipefail

export PGDATABASE="scancodeio"
export PGPASSWORD=$DB_PASSWORD
export PGHOST=$DB_HOSTNAME
export PGUSER=$DB_USERNAME

psql -c "REFRESH MATERIALIZED VIEW CONCURRENTLY libinv.sca_actionable_items;"
