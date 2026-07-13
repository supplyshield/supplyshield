import logging
import os
import re
import time
from pathlib import Path

from libinv.env import BASE_IMAGE_JAVA_VERSION_MAPPING
from libinv.env import CDXGEN_BIN
from libinv.env import FETCH_LICENSE
from libinv.env import GO_PRIVATE
from libinv.env import JAVA_HOME
from libinv.env import GONOSUMCHECK
from libinv.env import GONOSUMDB
from libinv.env import NPM_CONFIG_PREFIX
from libinv.helpers import SubprocessError
from libinv.helpers import subprocess_run
from libinv.logger import CustomFormatter
from libinv.logger import color_handler
from libinv.models import Wasp

# Color logging
color_handler.setFormatter(CustomFormatter())
logger = logging.getLogger("libinv.cdxgen")
logger.propagate = False
logger.addHandler(color_handler)
logger.setLevel(logging.DEBUG)


blacklist = []

whitelist = ["go-service"]


def get_java_version_from_gradle(project_dir: Path):
    if not os.path.exists(f"{project_dir}/gradlew"):
        return None

    try:
        properties = subprocess_run(
            ["./gradlew", "properties", "-q", "--no-daemon", "--console=plain"], cwd=project_dir
        ).stdout
    except SubprocessError:
        return
    for property in properties.split("\n"):
        key, _, value = property.partition(": ")
        if key == "sourceCompatibility":
            return value


def get_base_image(dockerfile: Path):
    with open(dockerfile) as df:
        lines = df.readlines()
        for line in lines:
            if line.startswith("FROM"):
                _, _, base_image = line.partition("FROM")
                return base_image.strip()


def guess_java_version_by_base_image(base_image: str):
    match = re.search("(jre|jdk).*?([0-9]+)", base_image)
    if not match:
        return None
    version = match.group(2)
    return version


def get_java_version_by_base_image(base_image: str):
    base_image, _, label = base_image.partition(":")
    version = BASE_IMAGE_JAVA_VERSION_MAPPING.get(base_image)
    if not version:
        version = guess_java_version_by_base_image(base_image)
        if version:
            logger.warning(f"Guessing java version: {version} from base image: {base_image}")
    if not version:
        # raise ValueError(f"Invalid java version in base image: {base_image}")
        return None
    return version


def detect_java_version_from_subdir_gradle(repo_dir: Path):
    pattern = re.compile(r"sourceCompatibility\s*=\s*['\"]?(\d+)['\"]?")
    versions = []
    for gradle_file in repo_dir.rglob("build.gradle"):
        try:
            for line in gradle_file.read_text(errors="ignore").splitlines():
                match = pattern.search(line)
                if match:
                    versions.append(int(match.group(1)))
        except OSError:
            continue
    return str(max(versions)) if versions else None


def get_java_env(base_image, repo_dir):
    java_version = None
    if base_image:
        java_version = get_java_version_by_base_image(base_image)

    if not java_version:
        java_version = get_java_version_from_gradle(repo_dir)

    if not java_version:
        java_version = detect_java_version_from_subdir_gradle(repo_dir)
        if java_version:
            logger.info(f"Detected java version {java_version} from subdir build.gradle files")

    if not java_version:
        java_version = "21"
        logger.warning(f"Could not detect java version, defaulting to {java_version}")

    java_path = JAVA_HOME.get(java_version)
    if not java_path:
        logger.warning(f"No JAVA_HOME configured for version {java_version}, skipping java env")
        return {}

    logger.info(f"Detected java: {java_version}")
    return {
        "JAVA_HOME": java_path,
        "PATH": f"/usr/local/go/bin:{os.environ.get('PATH', '')}:{java_path}/bin",
    }


def get_go_env(base_image, repo_dir):
    # go_version = None

    # TODO: Ideally SRE should tell go version based on base image
    if base_image:
        ...


def get_env(repo_dir):
    base_image = None
    env = {
        "PATH": f"/usr/local/go/bin:{os.environ.get('PATH', '')}",
        "HOME": os.environ["HOME"],
        "GOPATH": os.environ.get("GOPATH", f"{os.environ['HOME']}/go"),
        "GOPRIVATE": GO_PRIVATE or "",
        "GOFLAGS": "-mod=mod",
        "CDXGEN_DEBUG_MODE": "debug",
        "FETCH_LICENSE": FETCH_LICENSE,
        "GONOSUMCHECK": GONOSUMCHECK or "",
        "GONOSUMDB": GONOSUMDB or "",
        "NPM_CONFIG_PREFIX": NPM_CONFIG_PREFIX,
        "CDXGEN_PLUGINS_DIR": NPM_CONFIG_PREFIX + "/@cyclonedx/cdxgen-plugins-bin/plugins/",
        "PIP_CONFIG_FILE": str(repo_dir / "pip.conf"),
        "MVN_CMD": "/root/.sdkman/candidates/maven/3.9.8/bin/mvn",
    }
    logger.info(f"Detected go: {env['GOPATH']}")
    logger.info(f"Go env: GOPRIVATE={GO_PRIVATE!r} GONOSUMDB={GONOSUMDB!r} GONOSUMCHECK={GONOSUMCHECK!r} GOFLAGS=-mod=mod")

    netrc = Path(os.environ.get("HOME", "/root")) / ".netrc"
    if netrc.exists():
        logger.info(f"~/.netrc present ({netrc.stat().st_size} bytes)")
    else:
        logger.warning("~/.netrc NOT found — private Go modules will fail auth")

    try:
        base_image = get_base_image(repo_dir / "Dockerfile")
    except FileNotFoundError:
        with open("no-dockerfile", "a") as f:
            f.write(f"No docker image for: {repo_dir}\n")
            # print(f"No docker image for: {repo_dir}")

    env.update(get_java_env(base_image=base_image, repo_dir=repo_dir))

    return env


class CdxScanner:
    def __init__(self, repo_dir: Path):
        self.output_filename_suffix = ""
        self.purls_to_exclude = []
        self.anomalies = {"NO_GRADLE_WRAPPER": False, "NO_GO_SUM": False}
        self.repo_dir = repo_dir
        self.env = get_env(repo_dir)
        self.errors = ""

    def detect_anomalies(self):
        repo_name = self.repo_dir.name

        if (self.repo_dir / "build.gradle").exists():
            if not (self.repo_dir / "gradle/wrapper/gradle-wrapper.jar").exists():
                self.anomalies["NO_GRADLE_WRAPPER"] = True
                logger.error(f"{repo_name}: Gradle project but Gradle wrapper not present")

        if (self.repo_dir / "go.mod").exists():
            if not (self.repo_dir / "go.sum").exists():
                self.anomalies["NO_GO_SUM"] = True
                logger.warning(f"{repo_name}: Go project but go.sum file not present")

    def fix_detected_anomalies(self):
        repo_name = self.repo_dir.name
        if self.anomalies["NO_GO_SUM"]:
            logger.info("Generating go.sum file")
            subprocess_run(
                ["go", "mod", "tidy", f"-compat={self.get_go_version()}", "-e"],
                env=self.env,
                cwd=self.repo_dir,
            )
            if not (self.repo_dir / "go.sum").exists():
                logger.error(f"{repo_name}: go.sum creation falied")

            # if run.stderr: # Doesn't work.
            #    logger.warning(run.stderr)
            #    logger.warning("Go mod tidy errored, BOM could be incomplete")

    def get_go_version(self):
        go_mod = self.repo_dir / "go.mod"
        with open(go_mod) as file:
            pattern = re.compile(r"go (\d\.\d\d)")
            for line in file:
                match = pattern.match(line)
                if match:
                    return match.group(1)

    def exclude_purls(self, purls: list):
        if purls == []:
            return
        self.output_filename_suffix = "_no_commons"
        self.purls_to_exclude = purls

    def run(self, output_dir: Path):
        repo_dir = self.repo_dir
        output_filename = Path(
            output_dir, f"{repo_dir.name}{self.output_filename_suffix}.sbom.cdx.json"
        )
        command = [
            CDXGEN_BIN,
            repo_dir,
            "--spec-version",
            "1.4",
            "-o",
            output_filename,
            "--filter",
            *self.purls_to_exclude,
        ]

        logger.debug(f"{repo_dir.name}: running cdxgen command: {' '.join(str(c) for c in command)}")
        t0 = time.time()
        run = subprocess_run(
            command,
            env=self.env,
        )
        elapsed = time.time() - t0
        logger.info(f"{repo_dir.name}: cdxgen finished in {elapsed:.1f}s")
        if run.stdout:
            for line in run.stdout.splitlines()[:200]:
                logger.debug(f"[cdxgen stdout] {line}")
        if run.stderr:
            with open("errors", "a") as f:
                f.write(f"{self.repo_dir} \n")
                f.write(run.stderr)
                f.write("\n=========\n")
            logger.error(f"{repo_dir.name} errored")
            self.errors += run.stderr
        logger.debug(f"Created sbom file for {repo_dir.name} => {output_filename}")
        return output_filename


def run_cdxgen_scan(wasp: Wasp, exclude: list = []):
    """
    Return generated cdx filename after scanning given repo_dir
    """
    logger.debug("Running cdxgen scan")
    repo_dir = wasp.repo_dir
    scanner = CdxScanner(repo_dir)
    scanner.detect_anomalies()
    scanner.fix_detected_anomalies()
    scanner.exclude_purls(exclude)
    output_filename = scanner.run(output_dir=wasp.project_dir)
    if scanner.errors:
        wasp.throw(scanner.errors)
    return output_filename
