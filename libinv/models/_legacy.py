"""Sprint 41.5: ``_legacy.py`` is now a thin module-level constants +
shared-helpers shim. All ORM classes have been peeled off into per-domain
files under ``libinv.models.<domain>`` (sprints 39.2 – 41.4). Only
package-wide constants, generic helper functions, and back-imports to
keep ``from libinv.models._legacy import X`` callers working remain
here.
"""

from __future__ import annotations

import logging

import requests  # noqa: F401  re-exported for test mocks (libinv.models.requests)
import semver
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.sql.expression import ClauseElement

from libinv.base import session_scope  # noqa: F401  re-exported via __init__.py
from libinv.exceptions import ConflictingInfoError
from libinv.helpers import case_insensitive_dict

try:
    from libinv.scio_models import DiscoveredPackage
except SQLAlchemyError:  # pragma: no cover - fallback for bootstrap when scanpipe tables missing
    # Sprint 47.2: narrowed from `except Exception`. The only failure
    # mode for ``libinv.scio_models`` import is the SQLAlchemy reflection
    # call (``inspect(engine).has_table``) when scanpipe tables are
    # missing or the SCIO DB is unreachable.
    DiscoveredPackage = None

MAX_LENGTH_LICENSE = 150
MAX_LENGTH_VULNERABILITY_DESCRIPTION = 500
ORGSRE_ACCOUNT_ID = "orgsre"

logger = logging.getLogger(__name__)
logger.level = logging.DEBUG



# https://stackoverflow.com/a/2587041/2251364
def get_or_create(session, model, defaults=None, **kwargs):
    instance = session.query(model).filter_by(**kwargs).one_or_none()
    if instance:
        return instance, False
    else:
        params = {k: v for k, v in kwargs.items() if not isinstance(v, ClauseElement)}
        params.update(defaults or {})
        instance = model(**params)
        session.add(instance)
        session.commit()
        return instance, True



def get_or_update_entry(session, model, query_filter, **kwargs):
    """
    Query the database for an entry and update it with the provided kwargs.

    :param session: session object.
    :param model: model class to query.
    :param query_filter: A dictionary of filters for the query.
    :param kwargs: The fields and values to update.
    :return: The updated object or a message if not found.
    """
    try:
        # Query the database for the entry
        obj = session.query(model).filter_by(**query_filter).first()
        if obj:
            # Update the object with provided kwargs
            for key, value in kwargs.items():
                setattr(obj, key, value)
            session.commit()
            return obj
        else:
            return f"No entry found with filter: {query_filter}"
    except SQLAlchemyError as e:
        # Sprint 47.2: narrowed from `except Exception`. The protected
        # block is purely ORM I/O — ``session.query``,
        # ``session.commit`` — which raises ``SQLAlchemyError``
        # subclasses on failure (StaleData, IntegrityError, etc.).
        session.rollback()
        return f"Error: {str(e)}"


def filter_model_collection(model_collection, filter_map: dict):
    """
    Return filtered models from a model collection (say, relationship) according to given filter map
    filter_map must not have any other field than that in model
    """
    filtered = []

    # Because mysql >:()
    filter_map = case_insensitive_dict(filter_map)

    for model in model_collection:
        # Because mysql >:()
        model_dict = case_insensitive_dict(model.__dict__)
        if filter_map.items() <= model_dict.items():
            filtered.append(model)
    return filtered


def get_base_image_of(image: Image) -> "Image":
    """
    Return base image nor None
    Base image is defined as top node of parent image hirarchy.
    """
    base = image.parent_image
    while base.parent_image:
        base = base.parent_image
    return base


def update_safely(session, model, attr: str, value):
    existing_value = getattr(model, attr)
    if existing_value and existing_value != value:
        raise ConflictingInfoError(
            f"{model} already has {attr}: {existing_value}"
            f" and it doesn't match given {attr}: {value}"
        )
    setattr(model, attr, value)
    session.add(model)
    session.commit()


def is_blacklist(package_name):
    blacklisted_substrings = []
    for substring in blacklisted_substrings:
        if substring in package_name:
            return True
    return False


def sort_versions(version_list):
    """
    Sorts a list of semantic version strings.

    :param version_list: List of version strings to sort (e.g., ["1.0.0", "2.1.0", "1.10.0"]).
    :return: A sorted list of version strings.
    """
    try:
        return sorted(version_list, key=semver.Version.parse)
    except ValueError as e:
        logger.error(f"Error sorting versions: {e}")
        return [None]


# Sprint 39.2: re-import the extracted Image-domain ORM classes at the
# bottom of the file so they remain accessible as module globals from
# inside ``DeploymentCheckpoint.set`` (which calls
# ``LatestImage.calibrate(...)`` at runtime) and from any legacy callers
# that still do ``from libinv.models._legacy import Image`` etc.
#
# Placement at the bottom is intentional: ``libinv.models.image``
# imports ``ORGSRE_ACCOUNT_ID`` from this module (``_legacy``), so the
# only safe time to back-import its symbols is *after* ``_legacy.py`` is
# fully evaluated. By the time the runtime ever calls
# ``LatestImage.calibrate``, both modules have finished loading.
from libinv.models.image import Image  # noqa: E402,F401
from libinv.models.image import ImagePackageAssociation  # noqa: E402,F401
from libinv.models.image import Layer  # noqa: E402,F401
from libinv.models.image import LatestImage  # noqa: E402,F401

# Sprint 40.1: Package-domain classes live in libinv/models/package.py.
# Back-import so historical ``from libinv.models._legacy import Package``
# callers (and any internal helpers) continue to find these names.
from libinv.models.package import License  # noqa: E402,F401
from libinv.models.package import Package  # noqa: E402,F401
from libinv.models.package import PackageLicenseAssociation  # noqa: E402,F401

# Sprint 40.2: Vulnerability-domain classes live in libinv/models/vulnerability.py.
from libinv.models.vulnerability import Vulnerability  # noqa: E402,F401
from libinv.models.vulnerability import VulnerabilityPackageAssociation  # noqa: E402,F401

# Sprint 40.3: EPSS-domain class lives in libinv/models/epss.py.
from libinv.models.epss import EPSS  # noqa: E402,F401

# Sprint 41.1: Wasp + Wasp-only helpers (is_excluded_repo,
# is_valid_raw_message) live in libinv/models/wasp.py. Back-imported so
# historical ``from libinv.models._legacy import Wasp`` / patches on
# ``libinv.models._legacy.is_excluded_repo`` keep resolving.
from libinv.models.wasp import Wasp  # noqa: E402,F401
from libinv.models.wasp import is_excluded_repo  # noqa: E402,F401
from libinv.models.wasp import is_valid_raw_message  # noqa: E402,F401

# Sprint 41.2: Actionable family (Actionable,
# ActionablePackageAvailableVersion,
# RepositoryActionablePackageAvailableVersion) lives in
# libinv/models/actionable.py. Back-imported so historical
# ``from libinv.models._legacy import Actionable`` and test patches on
# ``libinv.models._legacy.Actionable`` keep resolving.
from libinv.models.actionable import Actionable  # noqa: E402,F401
from libinv.models.actionable import ActionablePackageAvailableVersion  # noqa: E402,F401
from libinv.models.actionable import RepositoryActionablePackageAvailableVersion  # noqa: E402,F401
# Deprecated alias — preserved so historical
# ``from libinv.models._legacy import Repository_ActionablePackageAvailableVersion``
# keeps working until callers migrate.
Repository_ActionablePackageAvailableVersion = RepositoryActionablePackageAvailableVersion  # noqa: N816,E402

# Sprint 41.3: Repository / Account / DeploymentCheckpoint live in
# libinv/models/repository.py. Back-imported so historical
# ``from libinv.models._legacy import Repository`` and any test patches
# on ``libinv.models._legacy.Repository`` keep resolving.
from libinv.models.repository import Account  # noqa: E402,F401
from libinv.models.repository import DeploymentCheckpoint  # noqa: E402,F401
from libinv.models.repository import Repository  # noqa: E402,F401

# Sprint 41.4: Secbug + SAST classes live in their own domain files.
# Back-imported so historical ``from libinv.models._legacy import Secbug``
# / ``SastLobMetaData`` / ``SastResult`` callers keep resolving.
from libinv.models.secbug import Secbug  # noqa: E402,F401
from libinv.models.sast import SastLobMetaData  # noqa: E402,F401
from libinv.models.sast import SastResult  # noqa: E402,F401

