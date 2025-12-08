import logging
import os
import subprocess
import time

import schedule

from libinv.env import JOBS

logging.basicConfig(
    level=logging.DEBUG, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)

logger = logging.getLogger("libinv.cron-scheduler")

JOBS = JOBS


def execute_command(command, timeout):
    logger.debug(f"Executing command: {command}")
    try:
        process = subprocess.Popen(
            command,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,  # Merge stderr with stdout for real-time output
            universal_newlines=True,
            bufsize=1,  # Line buffered
            env=dict(os.environ),
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
