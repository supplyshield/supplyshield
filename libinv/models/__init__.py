"""Sprint 39.1: libinv.models package re-export shim.

Historical layout was a single ~1800-LOC ``libinv/models.py`` module.
Sprint 39 converts it to a package so each ORM domain (image, package,
vulnerability, …) can live in its own file. Every name that was
previously importable as ``from libinv.models import X`` must still be
importable from this package — that contract is enforced by tests and
dozens of call sites under ``libinv/api``, ``libinv/cli``,
``libinv/scanners``, and ``tests/``.

For now, the bulk of the ORM still lives in :mod:`libinv.models._legacy`
and is wildcard-re-exported here. Subsequent sprints (39.2 → 41.5) peel
classes off ``_legacy`` into per-domain files, updating these
re-exports as they go.
"""

from __future__ import annotations

# Re-export ``Base`` from the canonical module so callers keep working
# with ``from libinv.models import Base``. ``Base`` itself remains
# defined in :mod:`libinv.base` (see ``alembic/env.py:16``).
from libinv.base import Base  # noqa: F401

from libinv.models._base import TimestampMixin  # noqa: F401

# Star-import the legacy module so every ORM class + helper function +
# constant declared there shows up on this package's namespace. Adding
# explicit re-exports for the most-imported names below to make the
# contract visible to readers, mypy, and IDEs.
from libinv.models._legacy import *  # noqa: F401,F403

# Explicit re-exports for symbols that test code patches via
# ``patch("libinv.models.X", ...)``. These must live at the package's
# top-level namespace, not just be reachable via star-import (which
# matters for ``unittest.mock.patch``'s attribute lookup).
from libinv.models._legacy import DiscoveredPackage  # noqa: F401
# Sprint 41.3: Repository lives in libinv/models/repository.py.
from libinv.models.repository import Repository  # noqa: F401
from libinv.models._legacy import is_blacklist  # noqa: F401
# Sprint 41.1: is_excluded_repo now lives in libinv/models/wasp.py.
from libinv.models.wasp import is_excluded_repo  # noqa: F401
from libinv.models._legacy import requests  # noqa: F401  re-exported for test mocks
from libinv.models._legacy import session_scope  # noqa: F401

# Explicit re-exports of the model classes + constants + helpers callers
# rely on. Mirrors the historical ``libinv/models.py`` public surface.
from libinv.models._legacy import MAX_LENGTH_LICENSE  # noqa: F401
from libinv.models._legacy import MAX_LENGTH_VULNERABILITY_DESCRIPTION  # noqa: F401
from libinv.models._legacy import ORGSRE_ACCOUNT_ID  # noqa: F401
# Sprint 41.3: Account / DeploymentCheckpoint live in libinv/models/repository.py.
from libinv.models.repository import Account  # noqa: F401
# Sprint 41.2: Actionable-domain classes live in libinv/models/actionable.py.
from libinv.models.actionable import Actionable  # noqa: F401
from libinv.models.actionable import ActionablePackageAvailableVersion  # noqa: F401
from libinv.models._legacy import ConflictingInfoError  # noqa: F401
from libinv.models.repository import DeploymentCheckpoint  # noqa: F401
# Sprint 40.3: EPSS-domain class lives in libinv/models/epss.py.
from libinv.models.epss import EPSS  # noqa: F401
# Sprint 39.2: Image-domain classes live in libinv/models/image.py.
from libinv.models.image import Image  # noqa: F401
from libinv.models.image import ImagePackageAssociation  # noqa: F401
from libinv.models.image import LatestImage  # noqa: F401
from libinv.models.image import Layer  # noqa: F401
# Sprint 40.1: Package-domain classes live in libinv/models/package.py.
from libinv.models.package import License  # noqa: F401
# Sprint 41.1: MalformedCaterpillarMessage canonical home is
# ``libinv.exceptions``; was previously re-exported via ``_legacy``.
from libinv.exceptions import MalformedCaterpillarMessage  # noqa: F401
from libinv.models.package import Package  # noqa: F401
from libinv.models.package import PackageLicenseAssociation  # noqa: F401
from libinv.models.actionable import RepositoryActionablePackageAvailableVersion  # noqa: F401
# Deprecated alias — remove in a future cleanup once all internal callers migrate.
Repository_ActionablePackageAvailableVersion = RepositoryActionablePackageAvailableVersion  # noqa: N816
# Sprint 41.4: Secbug + SAST classes live in libinv/models/secbug.py + sast.py.
from libinv.models.sast import SastLobMetaData  # noqa: F401
from libinv.models.sast import SastResult  # noqa: F401
from libinv.models.secbug import Secbug  # noqa: F401
# Sprint 40.2: Vulnerability-domain classes live in libinv/models/vulnerability.py.
from libinv.models.vulnerability import Vulnerability  # noqa: F401
from libinv.models.vulnerability import VulnerabilityPackageAssociation  # noqa: F401
# Sprint 46.1 / 46.2: relational replacements for the legacy
# ``VulnerabilityPackageAssociation.fix`` and ``Vulnerability.related``
# comma-separated columns.
from libinv.models.vulnerability import VulnerabilityFixVersion  # noqa: F401
from libinv.models.vulnerability import VulnerabilityRelatedCve  # noqa: F401
# Sprint 41.1: Wasp lives in libinv/models/wasp.py.
from libinv.models.wasp import Wasp  # noqa: F401
from libinv.models._legacy import filter_model_collection  # noqa: F401
from libinv.models._legacy import get_base_image_of  # noqa: F401
from libinv.models._legacy import get_or_create  # noqa: F401
from libinv.models._legacy import get_or_update_entry  # noqa: F401
# Sprint 41.1: is_valid_raw_message now lives in libinv/models/wasp.py.
from libinv.models.wasp import is_valid_raw_message  # noqa: F401
from libinv.models._legacy import sort_versions  # noqa: F401
from libinv.models._legacy import update_safely  # noqa: F401
