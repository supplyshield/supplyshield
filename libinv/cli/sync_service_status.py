import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone

import click
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import insert as pg_insert

from libinv.base import Session
from libinv.cli.cli import cli
from libinv.models import Repository, ServiceStatus, Wasp
from libinv.scripts.deployment_status import fetch_service_status

logger = logging.getLogger(__name__)

DEFAULT_MONTHS = 12
DEFAULT_WORKERS = 25


def _get_services(months: int, environment: str | None, services: tuple[str]) -> list[dict]:
    """
    Return a list of {repository_id, repo_name, environment} dicts.

    Uses explicit --services list if provided, otherwise queries Wasps from the
    last N months. When --environment is set, results are filtered to that env.
    """
    with Session() as session:
        cutoff = datetime.now(tz=timezone.utc) - timedelta(days=months * 30)

        if services:
            # Explicit list: look up repository_id for each name
            rows = (
                session.query(Repository.id, Repository.name, Wasp.environment)
                .join(Wasp, Wasp.repository_id == Repository.id)
                .filter(Repository.name.in_(services))
                .filter(Wasp.created_at >= cutoff)
                .distinct()
                .all()
            )
        else:
            rows = (
                session.query(Repository.id, Repository.name, Wasp.environment)
                .join(Wasp, Wasp.repository_id == Repository.id)
                .filter(Wasp.created_at >= cutoff)
                .distinct()
                .all()
            )

        results = [
            {"repository_id": row[0], "repo_name": row[1], "environment": row[2]}
            for row in rows
            if row[1] and row[2]
        ]

    if environment:
        results = [r for r in results if r["environment"] == environment]

    return results


def _fetch_all(service_records: list[dict], workers: int) -> list[dict]:
    """Fan out provider fetch requests concurrently, return normalized records with repository_id."""
    now = datetime.now(tz=timezone.utc)
    results = []

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(fetch_service_status, r["repo_name"], r["environment"]): r
            for r in service_records
        }
        done = 0
        total = len(futures)
        for future in as_completed(futures):
            record = futures[future]
            try:
                normalized = future.result()
            except Exception as exc:
                normalized = {
                    "repo_name": record["repo_name"],
                    "environment": record["environment"],
                    "status": "error",
                    "error": str(exc),
                }

            normalized["repository_id"] = record["repository_id"]
            normalized["captured_at"] = now
            results.append(normalized)

            done += 1
            if done % 100 == 0:
                logger.info(f"  {done}/{total} fetched...")

    return results


def _upsert(results: list[dict]) -> tuple[int, int]:
    """Bulk upsert into service_statuses. Returns (upserted, skipped)."""
    rows = [
        {
            "repository_id": r["repository_id"],
            "environment": r["environment"],
            "status": r.get("status"),
            "health_status": r.get("health_status"),
            "error": r.get("error"),
            "running_count": r.get("running_count"),
            "desired_count": r.get("desired_count"),
            "healthy_targets": r.get("healthy_targets"),
            "total_targets": r.get("total_targets"),
            "task_definition": r.get("task_definition"),
            "cluster_name": r.get("cluster_name"),
            "compute_type": r.get("compute_type"),
            "downtime_risk": r.get("downtime_risk"),
            "downtime_reason": r.get("downtime_reason"),
            "rate_4xx": r.get("error_rate_4xx"),
            "rate_5xx": r.get("error_rate_5xx"),
            "total_requests": r.get("total_requests"),
            "captured_at": r.get("captured_at"),
            "last_updated_dashboard": r.get("last_updated"),
        }
        for r in results
        if r.get("repository_id")
    ]

    skipped = len(results) - len(rows)
    if not rows:
        return 0, skipped

    update_cols = [
        "status",
        "health_status",
        "error",
        "running_count",
        "desired_count",
        "healthy_targets",
        "total_targets",
        "task_definition",
        "cluster_name",
        "compute_type",
        "downtime_risk",
        "downtime_reason",
        "rate_4xx",
        "rate_5xx",
        "total_requests",
        "captured_at",
        "last_updated_dashboard",
    ]

    stmt = pg_insert(ServiceStatus).values(rows)
    set_dict = {col: stmt.excluded[col] for col in update_cols}
    set_dict["last_healthy_at"] = sa.case(
        (stmt.excluded["health_status"] == "HEALTHY", stmt.excluded["captured_at"]),
        else_=ServiceStatus.last_healthy_at,
    )
    stmt = stmt.on_conflict_do_update(
        constraint="uq_service_status_repo_env",
        set_=set_dict,
    )

    with Session() as session:
        session.execute(stmt)
        session.commit()

    return len(rows), skipped


@cli.command("sync-service-status")
@click.option(
    "--months",
    default=DEFAULT_MONTHS,
    show_default=True,
    metavar="N",
    help="Lookback window: services with a wasp in the last N months.",
)
@click.option(
    "--environment",
    default=None,
    metavar="ENV",
    help="Restrict to a single environment (e.g. prod, stage).",
)
@click.option(
    "--services",
    multiple=True,
    metavar="NAME",
    help="Sync specific service names only (repeatable).",
)
@click.option(
    "--workers",
    default=DEFAULT_WORKERS,
    show_default=True,
    metavar="N",
    help="Concurrent status provider connections.",
)
@click.option("--dry-run", is_flag=True, help="Fetch statuses but do not write to the database.")
def sync_status(months: int, environment: str, services: tuple, workers: int, dry_run: bool):
    """
    Fetch live service statuses from the deployment status provider and upsert into service_statuses.

    Queries Wasp records from the last MONTHS months to build the service list,
    then fetches status from the configured provider concurrently and persists results.
    """
    logger.info(f"Resolving services (last {months} months)...")
    service_records = _get_services(months, environment, services)

    if not service_records:
        click.echo("No services matched — nothing to do.")
        return

    env_label = environment or "all environments"
    click.echo(
        f"Fetching status for {len(service_records)} services [{env_label}] ({workers} workers)..."
    )

    results = _fetch_all(service_records, workers)

    active = sum(1 for r in results if r.get("status") == "active")
    no_cfn = sum(1 for r in results if r.get("status") == "no_tracking_data")
    errors = sum(1 for r in results if r.get("status") == "error")

    click.echo(f"Fetched: {active} active, {no_cfn} no tracking data, {errors} errors")

    if dry_run:
        click.echo("Dry run — skipping database write.")
        return

    upserted, skipped = _upsert(results)
    click.echo(f"Upserted {upserted} rows ({skipped} skipped — missing repository_id).")
