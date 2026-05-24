from __future__ import annotations

import json
import logging
import signal
import time
import traceback
from typing import Any

import click
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from libinv import poll
from libinv import process_message
from libinv.cli.cli import cli
from libinv.helpers import send_to_slack

logger = logging.getLogger(__name__)

_shutdown_requested = False

# Sprint 51.3 — startup-retry tunables. The daemon polls the database
# with ``SELECT 1`` before entering the SQS loop so a not-yet-ready
# Postgres (k8s init-order race) does not crash the pod. The schedule
# is exponential: 1s, 2s, 4s, 8s, ... capped at ``_RETRY_MAX_INTERVAL``
# (5 min) per attempt, with a total budget of ``_RETRY_TOTAL_BUDGET``
# (10 min). Past that, the daemon exits non-zero so the orchestrator
# can restart and surface the failure.
_RETRY_INITIAL_INTERVAL_S = 1.0
_RETRY_MAX_INTERVAL_S = 300.0  # 5 min
_RETRY_TOTAL_BUDGET_S = 600.0  # 10 min


def _request_shutdown(signum: int, frame: Any) -> None:
    global _shutdown_requested
    _shutdown_requested = True
    logger.warning("Shutdown signal %s received; will exit after current batch.", signum)


def _wait_for_db(
    *,
    initial_interval: float = _RETRY_INITIAL_INTERVAL_S,
    max_interval: float = _RETRY_MAX_INTERVAL_S,
    total_budget: float = _RETRY_TOTAL_BUDGET_S,
) -> None:
    """Block until ``SELECT 1`` succeeds against the engine.

    Retries with exponential backoff (1s, 2s, 4s, ...) capped at
    ``max_interval`` between attempts, for up to ``total_budget``
    cumulative wall-clock seconds. Raises ``RuntimeError`` if the budget
    is exhausted so the daemon exits non-zero and the orchestrator can
    log + restart.

    Each attempt emits a structured log line including the resolved DB
    host (parsed from the SQLAlchemy URL so the password is never
    surfaced).
    """
    # Lazy-import so test patches against ``libinv.cli.daemon.get_engine``
    # / ``libinv.cli.daemon.reset_engine_cache`` work via the module
    # binding scope rather than ``libinv.base.*``.
    from libinv.base import get_engine
    from libinv.base import reset_engine_cache

    start = time.monotonic()
    attempt = 0
    interval = initial_interval
    while True:
        attempt += 1
        engine = get_engine()
        host = engine.url.host or "<unknown>"
        try:
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            logger.info(
                "daemon DB connect succeeded host=%s attempt=%d", host, attempt
            )
            return
        except SQLAlchemyError as exc:
            elapsed = time.monotonic() - start
            if elapsed >= total_budget:
                logger.error(
                    "daemon DB connect exhausted budget host=%s attempt=%d "
                    "elapsed=%.1fs error=%s",
                    host,
                    attempt,
                    elapsed,
                    exc.__class__.__name__,
                )
                raise RuntimeError(
                    f"Daemon failed to reach Postgres after {attempt} attempts "
                    f"({elapsed:.1f}s); giving up."
                ) from exc
            logger.warning(
                "daemon waiting for DB host=%s attempt=%d next_retry_s=%.1f "
                "error=%s",
                host,
                attempt,
                interval,
                exc.__class__.__name__,
            )
            # Dispose the cached engine so the next attempt re-resolves
            # DNS + reopens the pool (mirrors how k8s services come up
            # behind a new cluster IP).
            reset_engine_cache()
            time.sleep(interval)
            interval = min(interval * 2, max_interval)


@cli.command()
@click.option("--slack/--no-slack", is_flag=True, default=True)
@click.pass_context
def daemon(ctx: click.Context, slack: bool) -> None:
    """Poll messages from sqs queue and populate libinv database."""
    click.echo("starting service")
    if not ctx.obj["slack_logging"]:
        click.echo("Overriding slack logs. Disabled")
        slack = False

    signal.signal(signal.SIGTERM, _request_shutdown)
    signal.signal(signal.SIGINT, _request_shutdown)

    # Sprint 51.3 — block on DB readiness before entering the SQS loop.
    # A k8s pod started before Postgres is ready would otherwise crash on
    # the first ``session_scope()`` inside ``process_message``.
    _wait_for_db()

    while not _shutdown_requested:
        click.echo("polling for new messages")
        try:
            messages = poll()
        except Exception:
            logger.exception("Failed to poll SQS; sleeping briefly before retry")
            continue

        for message in messages:
            if _shutdown_requested:
                logger.info("Shutdown requested; stopping after in-flight messages.")
                break
            try:
                process_message(message)
            except Exception as exc:
                # Sprint 52.3 — record the failure for Prometheus + DLQ
                # visibility. We DO NOT delete the message here: that
                # lets the SQS visibility timeout expire so the queue
                # re-delivers it. Once ``maxReceiveCount`` is hit (set
                # via the queue's RedrivePolicy at the AWS infra layer,
                # documented in docs/deployment.rst), SQS forwards the
                # message to the configured dead-letter queue.
                reason = exc.__class__.__name__
                logger.exception(
                    "Error processing message; surfacing for SQS redrive "
                    "(reason=%s)",
                    reason,
                )
                try:
                    from libinv.api.metrics import sqs_messages_failed_total

                    sqs_messages_failed_total.labels(reason=reason).inc()
                except Exception:
                    # Metrics path must never mask the original failure.
                    logger.debug("metrics increment skipped", exc_info=True)
                if slack:
                    _notify_slack(message)
                # Continue to next message; do NOT delete this one.
                # The SQS visibility timeout will re-deliver it; once
                # ``maxReceiveCount`` is reached the queue's
                # RedrivePolicy forwards it to the DLQ.

    click.echo("daemon exited cleanly")


def _notify_slack(message: Any) -> None:
    try:
        body = json.dumps(message)
    except Exception:
        body = repr(message)
    chunk_size = 3900
    send_to_slack(":alert: *Error while handling message:*\n```" + body[:chunk_size] + "```\n")
    trace = traceback.format_exc()
    send_to_slack("*Stack trace:*\n```" + trace[:chunk_size] + "```")
    for start in range(chunk_size, len(trace), chunk_size):
        send_to_slack("```" + trace[start : start + chunk_size] + "```")
