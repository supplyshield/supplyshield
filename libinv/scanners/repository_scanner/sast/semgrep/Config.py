import logging

logger = logging.getLogger("sast_configpy")


class Config:
    def __init__(self, args) -> None:
        self.base_code_directory = args.d  # relative path from run , where repo is clond
        self.code_tech = args.code_tech  # must be a enum
        self.wasp = args.wasp
