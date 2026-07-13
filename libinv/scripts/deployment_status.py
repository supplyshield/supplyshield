"""
Fetch deployment statuses for repositories recently scanned by libinv.

Queries Wasp records from the last N months to get distinct (repo_name, environment)
pairs, then delegates to the configured DeploymentStatusProvider to collect health,
running counts, task definition, and downtime risk for each service.

Usage:
    # From DB (wasps scanned in last N months):
    python -m libinv.scripts.deployment_status [--months 3] [--environment prod]

    # From provider service list directly (no DB):
    python -m libinv.scripts.deployment_status --from-dashboard [--environment prod]

    # For a specific list of services:
    python -m libinv.scripts.deployment_status --services my-service-a my-service-b

Future: check_deployment_statuses() can be registered as a cron job in libinv-crons
by adding it to the JOBS config.
"""

import argparse
import importlib
import json
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone

from libinv import env
from libinv.deployment_provider import DeploymentStatusProvider, NullDeploymentStatusProvider

logger = logging.getLogger(__name__)

SSE_TIMEOUT_SECONDS = 10
MAX_WORKERS = 20

_provider: DeploymentStatusProvider | None = None


def get_provider() -> DeploymentStatusProvider:
    """Return the configured deployment status provider (singleton)."""
    global _provider
    if _provider is not None:
        return _provider

    cls_path = env.DEPLOYMENT_STATUS_PROVIDER
    if cls_path:
        module_path, cls_name = cls_path.rsplit(".", 1)
        module = importlib.import_module(module_path)
        _provider = getattr(module, cls_name)()
    else:
        _provider = NullDeploymentStatusProvider()

    return _provider


def fetch_service_status(service_name: str, environment: str) -> dict:
    """Fetch and return a normalized status dict for a single service."""
    return get_provider().fetch(service_name, environment)


def get_scanned_services(months: int = 3, environment: str = None) -> list:
    """
    Return distinct (repo_name, environment) tuples from Wasp records in the last N months.
    Lazily imports DB session to avoid startup cost when using --from-dashboard or --services.
    """
    from libinv.base import Session
    from libinv.models import Repository, Wasp

    session = Session()
    try:
        cutoff = datetime.now(tz=timezone.utc) - timedelta(days=months * 30)
        query = (
            session.query(Repository.name, Wasp.environment)
            .join(Wasp, Wasp.repository_id == Repository.id)
            .filter(Wasp.created_at >= cutoff)
            .distinct()
        )
        if environment:
            query = query.filter(Wasp.environment == environment)
        return [(name, svc_env) for name, svc_env in query.all() if name and svc_env]
    finally:
        session.close()


def _run_concurrent(services: list, environment: str) -> list:
    """Fan out fetch requests concurrently, return results sorted by name."""
    results = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = {pool.submit(fetch_service_status, name, environment): name for name in services}
        for future in as_completed(futures):
            name = futures[future]
            try:
                result = future.result()
            except Exception as exc:
                result = {
                    "repo_name": name,
                    "environment": environment,
                    "status": "error",
                    "error": str(exc),
                }
            results.append(result)
    return sorted(results, key=lambda r: r.get("repo_name", ""))


def check_deployment_statuses(months: int = 3, environment: str = "prod") -> list:
    """
    Query wasps from DB, fetch deployment status for each service concurrently.
    Primary entry point for cron integration.
    """
    services_with_env = get_scanned_services(months=months, environment=environment)
    logger.info(
        f"Querying deployment status for {len(services_with_env)} services (last {months} months)"
    )

    results = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = {
            pool.submit(fetch_service_status, repo_name, svc_env): (repo_name, svc_env)
            for repo_name, svc_env in services_with_env
        }
        for future in as_completed(futures):
            repo_name, svc_env = futures[future]
            try:
                result = future.result()
            except Exception as exc:
                result = {
                    "repo_name": repo_name,
                    "environment": svc_env,
                    "status": "error",
                    "error": str(exc),
                }
            results.append(result)

    return sorted(results, key=lambda r: (r.get("environment", ""), r.get("repo_name", "")))


def print_table(results: list) -> None:
    active = [r for r in results if r.get("status") == "active"]
    no_cfn = [r for r in results if r.get("status") == "no_tracking_data"]
    errored = [r for r in results if r.get("status") == "error"]

    if active:
        col = "{:<38} {:<12} {:<10} {:<10} {:<6} {:<28} {}"
        print(
            col.format(
                "Service", "Health", "Run/Des", "Risk", "5xx%", "Task Definition", "Last Updated"
            )
        )
        print("-" * 135)
        for r in active:
            running = (
                f"{r['running_count']}/{r['desired_count']}"
                if r.get("running_count") is not None
                else "?"
            )
            err5xx = (
                f"{r['error_rate_5xx']:.3f}" if isinstance(r.get("error_rate_5xx"), float) else "?"
            )
            print(
                col.format(
                    r["repo_name"],
                    r.get("health_status") or "?",
                    running,
                    r.get("downtime_risk") or "?",
                    err5xx,
                    r.get("task_definition") or "?",
                    r.get("last_updated") or "?",
                )
            )

    if no_cfn:
        print(f"\nRegistered but no tracking data ({len(no_cfn)}):")
        names = [r["repo_name"] for r in no_cfn]
        for i in range(0, len(names), 6):
            print("  " + "  ".join(f"{n:<30}" for n in names[i : i + 6]))

    if errored:
        print(f"\nFetch errors ({len(errored)}):")
        for r in errored:
            print(f"  {r['repo_name']:<35} [{r.get('error')}]")

    print(f"\nTotal: {len(active)} active, {len(no_cfn)} no tracking data, {len(errored)} errors")


def main():
    parser = argparse.ArgumentParser(
        description="Fetch deployment statuses for repos recently scanned by libinv"
    )
    source = parser.add_mutually_exclusive_group()
    source.add_argument(
        "--months",
        type=int,
        default=3,
        metavar="N",
        help="Query wasps from last N months in DB (default: 3)",
    )
    source.add_argument(
        "--from-dashboard",
        action="store_true",
        help="Use provider service list instead of DB (no DB connection needed)",
    )
    source.add_argument(
        "--services", nargs="+", metavar="NAME", help="Check specific service names directly"
    )
    parser.add_argument(
        "--environment", default="prod", help="Environment to query (default: prod)"
    )
    parser.add_argument(
        "--json", action="store_true", dest="as_json", help="Output raw JSON instead of a table"
    )
    parser.add_argument("--verbose", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(message)s",
    )

    environment = args.environment

    if args.services:
        logger.info(f"Checking {len(args.services)} specified services")
        results = _run_concurrent(args.services, environment)
    elif args.from_dashboard:
        services = get_provider().list_services(environment)
        logger.info(f"Found {len(services)} services for {environment}")
        results = _run_concurrent(services, environment)
    else:
        results = check_deployment_statuses(months=args.months, environment=environment)

    if args.as_json:
        print(json.dumps(results, indent=2))
    else:
        print_table(results)


if __name__ == "__main__":
    main()
