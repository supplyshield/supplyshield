import logging
import os
import shlex
import signal
import subprocess
import sys
import time
import uuid

import schedule

from libinv.env import JOBS
from libinv.logger import request_id_var

logging.basicConfig(
    level=logging.DEBUG, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)

logger = logging.getLogger("libinv.cron-scheduler")

JOBS = JOBS

# Sprint 52.1 — graceful shutdown plumbing.
#
# When the cron container receives SIGTERM (k8s pod deletion, deploy
# rollover), we want to:
#   1. Let the currently-running child subprocess finish — up to
#      ``_SHUTDOWN_WAIT_S``. Killing it mid-flight would leave a partial
#      sync in flight (e.g. a half-imported repository row), so we
#      give it a bounded grace period.
#   2. Stop scheduling further jobs (``_shutdown_requested = True`` is
#      checked between jobs by the main loop).
#   3. Exit 0 so the orchestrator records a clean shutdown.
#
# Implementation note: ``subprocess.Popen`` is invoked from
# ``execute_command`` (which holds a reference to the process in a
# local variable). To let the signal handler poll that process we keep a
# module-level ``_current_process`` reference that is set/cleared
# around the Popen lifetime.
_shutdown_requested = False
_current_process: subprocess.Popen | None = None
_SHUTDOWN_WAIT_S = 30


def _shutdown_handler(signum: int, frame) -> None:
    """SIGTERM handler — drain running job + exit cleanly.

    Sets the module-level ``_shutdown_requested`` flag so the scheduler
    main loop bails between jobs. If a subprocess is currently running,
    polls it for up to ``_SHUTDOWN_WAIT_S`` seconds; if it has not exited
    by then we forward a SIGTERM to the child so a misbehaving job
    eventually goes away.
    """
    global _shutdown_requested
    _shutdown_requested = True
    logger.warning(
        "cron scheduler received signal=%s; draining running job (max %ds)",
        signum,
        _SHUTDOWN_WAIT_S,
    )
    proc = _current_process
    if proc is not None:
        deadline = time.monotonic() + _SHUTDOWN_WAIT_S
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                logger.info("running job exited cleanly during shutdown drain")
                break
            time.sleep(0.5)
        else:
            # Loop completed without ``break`` — still running past the
            # grace window. Forward SIGTERM to the child; if it ignores
            # the signal entirely, the container runtime's eventual
            # SIGKILL will take it down.
            logger.warning(
                "running job did not exit within %ds; sending SIGTERM",
                _SHUTDOWN_WAIT_S,
            )
            try:
                proc.terminate()
            except Exception:
                logger.exception("failed to terminate running job")
    logger.info("cron scheduler shutting down (signum=%s)", signum)
    sys.exit(0)


def execute_command(command, timeout):
    global _current_process
    job_id = uuid.uuid4().hex
    token = request_id_var.set(job_id)
    try:
        # Sprint 52.1 — short-circuit if shutdown has already been
        # requested (e.g. SIGTERM arrived while ``run_all_once`` was
        # iterating ``JOBS``). Avoids starting a new subprocess we'd
        # immediately have to abandon.
        if _shutdown_requested:
            logger.info("shutdown requested; skipping job %s", command)
            return
        logger.info("Executing command [%s]: %s", job_id, command)
        try:
            env = dict(os.environ)
            env["LIBINV_REQUEST_ID"] = job_id
            # Sprint 47.1: shell=False + shlex.split closes the audit's
            # last S0 finding. JOBS values must be plain argv-shaped command
            # strings — no shell metacharacters (|, &&, $VAR, etc.). If a
            # cron job needs shell features, wrap it in a small etc/ script
            # and call that script's path here.
            process = subprocess.Popen(
                shlex.split(command),
                shell=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,  # Merge stderr with stdout for real-time output
                universal_newlines=True,
                bufsize=1,  # Line buffered
                env=env,
            )
            _current_process = process

            # Read output line by line in real-time
            start_time = time.time()
            while True:
                output = process.stdout.readline()
                if output == "" and process.poll() is not None:
                    break
                if output:
                    # Log each line immediately as it's received
                    logger.info(f"[{command.split()[0]}] {output.strip()}")

                # Check for timeout
                if time.time() - start_time > timeout:
                    process.kill()
                    logger.error(f"Failed: {command} timed out after {timeout} seconds.")
                    return

            # Wait for process to complete and get return code
            return_code = process.poll()
            if return_code == 0:
                logger.debug(f"Command completed successfully: {command}")
            else:
                logger.error(f"Command failed with return code {return_code}: {command}")

        except Exception as e:
            logger.error(f"Error executing command '{command}': {e}")
            if "process" in locals():
                process.kill()
        finally:
            _current_process = None
    finally:
        request_id_var.reset(token)


def run_all_once():
    for job_name, job_details in JOBS.items():
        if _shutdown_requested:
            logger.info("shutdown requested; halting run_all_once before job '%s'", job_name)
            return
        logger.debug(f"Running job '{job_name}'")
        execute_command(job_details["command"], job_details["timeout"])


def schedule_jobs():
    for job_name, job_details in JOBS.items():
        schedule.every(job_details["interval"]).seconds.do(
            execute_command, command=job_details["command"], timeout=job_details["timeout"]
        )
        logger.debug(f"Scheduled job '{job_name}' every {job_details['interval']} seconds.")


def main():
    logger.debug("Starting cron scheduler")
    # Sprint 52.1 — install SIGTERM/SIGINT handlers BEFORE scheduling
    # any jobs so a signal arriving mid-startup still routes through
    # the drain path.
    signal.signal(signal.SIGTERM, _shutdown_handler)
    signal.signal(signal.SIGINT, _shutdown_handler)
    run_all_once()
    if _shutdown_requested:
        logger.info("shutdown requested before scheduler loop; exiting")
        return
    schedule_jobs()
    while not _shutdown_requested:
        schedule.run_pending()
        time.sleep(1)
    logger.info("cron scheduler exited cleanly")


if __name__ == "__main__":
    main()
