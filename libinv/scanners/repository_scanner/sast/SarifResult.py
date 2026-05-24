import json
import logging

from sqlalchemy.orm import Session as OrmSession

from libinv.base import conn
from libinv.models import SastLobMetaData
from libinv.models import SastResult
from libinv.scanners.repository_scanner.sast.enums.ConfidenceEnum import ConfidenceEnum
from libinv.scanners.repository_scanner.sast.enums.PriorityEnum import PriorityEnum
from libinv.scanners.repository_scanner.sast.enums.ValidEnum import ValidEnum
from libinv.scanners.repository_scanner.sast.semgrep import utils
from libinv.scanners.repository_scanner.sast.semgrep.modes.DefaultMode import DefaultMode

logger = logging.getLogger("libinv.SarifResult")


class SarifResult:
    """
    parse sarif result
    """

    def __init__(self, config, sariffile, source, session: OrmSession | None = None) -> None:
        self.sarifjson = json.load(open(sariffile, "r"))
        self.config = config
        self.source = source
        self._session = session
        default_module = DefaultMode(config)

        self.rulesId_ModeParser = {
            "default": default_module
        }
        self.memo_lob_id = {}  # { pod::subpod::module :  lob_id from sast_meta db} cache
        self.rulemetadata = self.parsesarifmetadata()

    @property
    def _s(self):
        """Return the active session: caller-provided or the legacy ``conn`` fallback."""
        return self._session or conn

    def add_lob_module(self):
        """
        add :  POD | SUBPOD | module(idor/sqli) | submodeul(libinv.idor.rule-1)
        into db if not exist
        """

        for i, sarif_row in enumerate(self.sarifjson["runs"][0]["results"]):
            pod = self.config.wasp.repository.pod
            subpod = self.config.wasp.repository.subpod
            ruleid = sarif_row["ruleId"]
            key = self.make_memo_key(pod, subpod, ruleid)

            if key in self.memo_lob_id:
                continue

            res = (
                self._s.query(SastLobMetaData)
                .filter_by(repository_id=self.config.wasp.repository_id, sub_module=ruleid)
                .first()
            )

            module = (
                self.rulesId_ModeParser[ruleid]
                if ruleid in self.rulesId_ModeParser
                else self.rulesId_ModeParser["default"]
            )

            if res:
                self.memo_lob_id[key] = res.id
            else:
                # add to db
                metadata = SastLobMetaData(
                    module=module.mode,
                    sub_module=ruleid,
                    repository_id=self.config.wasp.repository_id,
                    bugcounts=0,
                )
                self._s.add(metadata)
                self._s.commit()
                self.memo_lob_id[key] = metadata.id

    def add_sarif_result_to_db(self):
        for i, sarif_row in enumerate(self.sarifjson["runs"][0]["results"]):
            full_path = sarif_row["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            subpath_without_base = full_path[len(str(self.config.base_code_directory)) :]
            fingerprint = utils.fingerprint_semgrep_single_result_sarif(
                sarif_row, subpath_without_base
            )

            record = self._s.query(SastResult).filter_by(id=fingerprint).first()

            prioriy = PriorityEnum.MEDIUM  # default Priority
            public_initial_point = ""
            ruleid = sarif_row["ruleId"]
            extras = {}
            extras["message"] = sarif_row["message"]
            extras["properties"] = self.rulemetadata[ruleid]
            extras["region"] = sarif_row["locations"][0]["physicalLocation"]["region"]

            module = (
                self.rulesId_ModeParser[ruleid]
                if ruleid in self.rulesId_ModeParser
                else self.rulesId_ModeParser["default"]
            )

            if record and record.validated != ValidEnum.NOTVALIDATED.value:
                continue  # record already exist and validated by SPOC: just move to next

            extras["vulnpaths"] = module.get_vuln_paths(sarif_row)

            prioriy, public_paths = module.get_publicpaths_priority(sarif_row, extras)
            extras["public_endpoints"] = public_paths
            extras["vulnpaths"] = [
                [str(method), path] for method, path in extras["vulnpaths"]
            ]  # json serialization was givin problem, had to convert method:enum to string

            if public_paths:
                public_initial_point = "\n".join(
                    f"{key}  {value}" for key, value in public_paths.items()
                )

            exact_github_url = self.get_exact_line_github_url(
                full_path, extras["region"]["startLine"]
            ).replace(
                "git@github.com:", "https://github.com/"
            )  # TEMPFIX

            pod = self.config.wasp.repository.pod
            subpod = self.config.wasp.repository.subpod
            submodule = sarif_row["ruleId"]

            key = self.make_memo_key(pod, subpod, submodule)

            if record:
                if isinstance(record.extras, str):
                    record.extras = json.load(record.extras)

                if extras["public_endpoints"] == record.extras["public_endpoints"]:
                    continue
                else:
                    # db entry not yet validated manually by SPOC have changed
                    record.extras["public_endpoints"] = extras["public_endpoints"]
                    record.public_initial_point = public_initial_point
                    record.priority = prioriy.value
                    self._s.commit()
                    continue

            record = SastResult(
                id=fingerprint,
                extras=extras,
                lob_id=str(self.memo_lob_id[key]),
                vulnsnippet=str(
                    sarif_row["locations"][0]["physicalLocation"]["region"]["snippet"]["text"]
                ),
                githubpath=str(exact_github_url),
                public_initial_point=str(public_initial_point),
                priority=str(prioriy.value),
                isactive=True,
                fixed_date=None,
                validated=str(ValidEnum.NOTVALIDATED.value),
                validate_date=None,
                confidence=str(ConfidenceEnum.HIGH.value),
                source=str(self.source.value),
                secbugurl=None,
                secbug_created_date=None,
                mean_solve_time=None,
                wasp_id=str(self.config.wasp.id),
                file_path=str(subpath_without_base),
            )
            self._s.add(record)
            self._s.commit()

        return

    def make_memo_key(self, pod, subpod, module):
        return f"{pod}::{subpod}::{module}"

    def get_exact_line_github_url(self, full_path, line_number):
        relative_path = full_path[len(str(self.config.base_code_directory)) :]
        branch = self.config.wasp.commit
        repo_url = self.config.wasp.repository.url
        if repo_url.endswith(".git"):
            repo_url = repo_url[:-4]
        giturl = f"{repo_url}/blob/{branch}/{relative_path}#L{line_number}"
        return giturl

    def parsesarifmetadata(self):
        metadata = {}

        for i, semgrep in enumerate(self.sarifjson["runs"][0]["tool"]["driver"]["rules"]):
            metadata[semgrep["id"]] = {
                "description": semgrep["fullDescription"]["text"],
                "properties": semgrep["properties"],
            }

        return metadata
