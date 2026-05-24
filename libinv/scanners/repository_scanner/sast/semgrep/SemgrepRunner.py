import logging
import shlex
import subprocess

logger = logging.getLogger("libinv.helpers")


class SemgrepRunner:
    def __init__(self, config):
        self.config = config
        self.rules = [
            "auto"
        ]
        self.output_file = (
            str(config.wasp.project_dir)
            + f"/output/semgrep_result/out_{config.wasp.repository.name}_latest"
        )

    def run_semgrep(self):
        """
        executes the  RULES inside self.rules with semgrep
        this will mostly be same for all Modes.py
        executes the semgrep command and saves the result in output folder
        """

        # Build argv list to avoid shell injection from untrusted config values
        # (e.g. repository name, base code directory).
        argv = ["semgrep", "--no-git-ignore"]
        for r in self.rules:
            argv.extend(["--config", r])
        argv.extend([
            "--sarif",
            "--timeout", "300",
            "--output", self.output_file,
            str(self.config.base_code_directory),
        ])

        logger.info("[INFO] EXEC Running:: " + shlex.join(argv))

        result = subprocess.run(
            argv,
            check=False,
            capture_output=True,
            text=True,
            timeout=3600,
        )
        if result.stderr:
            logger.info("[INFO] semgrep stderr:: " + result.stderr)

        return self.output_file

    def run(self):
        self.run_semgrep()
        return
