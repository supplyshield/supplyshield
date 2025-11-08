from libinv.project_language_detector import Project_language_detector
from libinv.scanners.repository_scanner.sast.enums.CodeTech import CodeTech
from libinv.scanners.repository_scanner.sast.enums.SastSourceEnum import SastSourceEnum
from libinv.scanners.repository_scanner.sast.SarifResult import SarifResult
from libinv.scanners.repository_scanner.sast.semgrep import Config
from libinv.scanners.repository_scanner.sast.semgrep import utils
from libinv.scanners.repository_scanner.sast.semgrep.SemgrepRunner import SemgrepRunner


def main(args):
    config = Config.Config(args)

    semgrepRunner = SemgrepRunner(config)

    semgrepRunner.run()  # gives SarifResult Object
    result = SarifResult(config, semgrepRunner.output_file, SastSourceEnum.SEMGREP)

    result.add_lob_module()  # add all modules ran to db
    result.add_sarif_result_to_db()  # add sarif result to db


def run_cicd(wasp, code_directory):
    """
    only runs 1 repository at a time
    wasp :  wasp Object with context of current scan run, containing pod, subpod git info etc
    code_directory : directory where repo code is downlaoded
    """
    # create required folders
    if not utils.check_folder_exist(f"{wasp.project_dir}/output"):
        utils.create_folder(f"{wasp.project_dir}/output")
    if not utils.check_folder_exist(f"{wasp.project_dir}/output/semgrep_result"):
        utils.create_folder(f"{wasp.project_dir}/output/semgrep_result")
    if not utils.check_folder_exist(f"{wasp.project_dir}/output/result"):
        utils.create_folder(f"{wasp.project_dir}/output/result")

    if Project_language_detector(code_directory).most_used_language() == "Java":
        code_tech = CodeTech.JAVA
    else:
        return None  # only runs for Java project right now

    class arg:
        def __init__(self) -> None:
            self.wasp = wasp
            self.d = code_directory
            self.code_tech = code_tech

    main(arg())
