import sys
from unittest.mock import MagicMock

# Global patches for SCIO tables
fake_scio_models = type(sys)("scio_models")
sys.modules["libinv.scio_models"] = fake_scio_models

# list all classes that reflect SCIO related tables here
fake_scio_models.VulnerablePath = MagicMock()
fake_scio_models.ScanpipeProject = MagicMock()
