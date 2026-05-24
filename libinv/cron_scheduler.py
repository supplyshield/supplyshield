import logging
import os
import shlex
import subprocess
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


def execute_command(command, timeout):
    job_id = uuid.uuid4().hex
    token = request_id_var.set(job_id)
    try:
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
        request_id_var.reset(token)


def run_all_once():
    for job_name, job_details in JOBS.items():
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
    run_all_once()
    schedule_jobs()
    while True:
        schedule.run_pending()
        time.sleep(1)


if __name__ == "__main__":
    main()
