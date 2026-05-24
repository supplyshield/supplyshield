from __future__ import annotations

import json
import logging
import time
from datetime import datetime
from datetime import timezone
from io import BytesIO
from typing import TYPE_CHECKING
from uuid import uuid4

import requests  # noqa: F401  re-exported for test mocks (libinv.models.requests)
import semver
from packageurl import PackageURL
from sqlalchemy import JSON
from sqlalchemy import Boolean
from sqlalchemy import Column
from sqlalchemy import DateTime
from sqlalchemy import Float
from sqlalchemy import ForeignKey
from sqlalchemy import Index
from sqlalchemy import Integer
from sqlalchemy import String
from sqlalchemy import Text
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.mutable import MutableDict
from sqlalchemy.orm import Session as OrmSession
from sqlalchemy.orm import relationship
from sqlalchemy.orm import synonym
from sqlalchemy.sql.expression import ClauseElement

if TYPE_CHECKING:
    from typing import Any

from libinv.base import Base
from libinv.base import conn
from libinv.base import session_scope
from libinv.models._base import TimestampMixin
from libinv.env import PURLDB_API_URL
from libinv.env import SCANCODEIO_API_KEY
from libinv.env import SCANCODEIO_URL
from libinv.exceptions import ConflictingInfoError
from libinv.helpers import case_insensitive_dict
from libinv.helpers import explode_git_url
from libinv.services import issue_reporter
try:
    from libinv.scio_models import DiscoveredPackage
except Exception:  # pragma: no cover - fallback for bootstrap when scanpipe tables missing
    DiscoveredPackage = None
from libinv.vcs import BitBucketApp
from libinv.vcs import GitHubApp

MAX_LENGTH_LICENSE = 150
MAX_LENGTH_VULNERABILITY_DESCRIPTION = 500
ORGSRE_ACCOUNT_ID = "orgsre"

logger = logging.getLogger(__name__)
logger.level = logging.DEBUG



class Secbug(Base, TimestampMixin):
    __tablename__ = "secbugs"

    id = Column(String(50), primary_key=True)
    # Sprint 34.1: secbug fields are pulled from an external system that may
    # omit any of them — explicit nullable=True marks intent.
    environment = Column(String(20), nullable=True)
    severity = Column(String(10), nullable=True)
    summary = Column(String(200), nullable=True)
    description = Column(String(MAX_LENGTH_VULNERABILITY_DESCRIPTION), nullable=True)
    vulnerability_category = Column(String(120), nullable=True)
    identified_by = Column(String(40), nullable=True)
    company = Column(String(20), nullable=True)
    is_risk = Column(Boolean(), nullable=True)
    pulled_at = Column(DateTime(timezone=True), nullable=False)
    deleted_at = Column(DateTime(timezone=True), nullable=True)
    # Sprint 34.1: repository_id nullable=True — secbugs may exist before
    # a repository is associated (e.g. cross-cutting org-level bugs).
    repository_id = Column(
        ForeignKey("libinv.repositories.id", onupdate="CASCADE", ondelete="CASCADE"),
        nullable=True,
    )

    # Sprint 37.2: never traversed via secbug.repository in api/cli/scanners.
    repository = relationship("Repository", back_populates="secbugs", lazy="raise_on_sql")
    key = synonym("id")

    # Sprint 33.1/33.2: declare indexes already created by alembic 0002_fk_indexes
    __table_args__ = (
        Index("ix_secbugs_repository_id", "repository_id"),
        {"schema": "libinv"},
    )

    def __str__(self):
        return self.id

    def delete(self):
        """
        perform soft delete
        """
        self.deleted_at = datetime.now(tz=timezone.utc)

    def is_active(self):
        """Return True if the secbug is not soft-deleted."""
        return self.deleted_at is None

    @classmethod
    def get(cls, id: str, session: OrmSession | None = None) -> "Secbug | None":
        return cls.all_active(session=session).filter(cls.id == id).first()

    @classmethod
    def get_any(cls, id: str, session: OrmSession | None = None) -> "Secbug | None":
        """Return secbug with given id, even if deleted"""
        s = session or conn
        return s.query(cls).filter(cls.id == id).first()

    @classmethod
    def all_active(cls, session: OrmSession | None = None):
        s = session or conn
        return s.query(cls).filter(cls.deleted_at == None)  # noqa: E711


class SastLobMetaData(Base, TimestampMixin):
    """
    stores metadata related to each LOB
    """

    __tablename__ = "sast_lob_metadata"

    id = Column(Integer, primary_key=True, autoincrement=True)
    # Sprint 37.2: never traversed via lob_meta.repository in api/cli/scanners.
    repository = relationship("Repository", lazy="raise_on_sql")
    module = Column(String(1024), nullable=False)
    sub_module = Column(String(1024), nullable=False)
    # Sprint 34.1: repository_id nullable=True — LOB metadata may be created
    # before the repo row is bridged.
    repository_id = Column(
        ForeignKey("libinv.repositories.id", onupdate="CASCADE"), nullable=True
    )

    # Sprint 34.1: bugcounts has Python default=0; pair with server_default
    # so DB-level INSERTs without the column also get 0, and mark NOT NULL.
    bugcounts = Column(Integer, default=0, server_default="0", nullable=False)

    Index("idx_repository", repository_id)


class SastResult(Base, TimestampMixin):
    """
    stores result from semgrep of the rules
    """

    __tablename__ = "sast_result"

    id = Column(String(150), primary_key=True)
    # Sprint 34.1: all FK + free-form text fields below are nullable=True
    # (sast result rows can be partial — many fields populated only after
    # validation / triage).
    lob_id = Column(
        ForeignKey("libinv.sast_lob_metadata.id", onupdate="CASCADE"), nullable=True
    )
    # Sprint 37.2: never traversed via result.lob_metadata in api/cli/scanners.
    lob_metadata = relationship("SastLobMetaData", lazy="raise_on_sql")
    extras = Column(MutableDict.as_mutable(JSON), nullable=True)
    vulnsnippet = Column(Text, nullable=True)
    githubpath = Column(String(1024), nullable=True)
    secbugurl = Column(String(1024), nullable=True)
    file_path = Column(String(1024), nullable=True)
    priority = Column(String(20), nullable=True)
    confidence = Column(String(20), nullable=True)
    description = Column(Text, nullable=True)
    public_initial_point = Column(Text, nullable=True)
    source = Column(String(200), nullable=True)
    isactive = Column(Boolean, nullable=True)
    wasp_id = Column(
        ForeignKey("libinv.wasps.id", onupdate="CASCADE", ondelete="CASCADE"),
        nullable=True,
    )
    fixed_date = Column(DateTime, nullable=True)
    validated = Column(
        Integer, nullable=True
    )  # 0=not validted yet, 1=valid bug, 2=false positive/intended
    validate_date = Column(DateTime, nullable=True)
    secbug_created_date = Column(DateTime, nullable=True)
    mean_solve_time = Column(Integer, nullable=True)

    # Sprint 33.1/33.2: declare indexes already created by alembic 0002_fk_indexes
    __table_args__ = (
        Index("ix_sast_result_lob_id", "lob_id"),
        Index("ix_sast_result_wasp_id", "wasp_id"),
        {"schema": "libinv"},
    )


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
    except Exception as e:
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
# Repository_ActionablePackageAvailableVersion) lives in
# libinv/models/actionable.py. Back-imported so historical
# ``from libinv.models._legacy import Actionable`` and test patches on
# ``libinv.models._legacy.Actionable`` keep resolving.
from libinv.models.actionable import Actionable  # noqa: E402,F401
from libinv.models.actionable import ActionablePackageAvailableVersion  # noqa: E402,F401
from libinv.models.actionable import Repository_ActionablePackageAvailableVersion  # noqa: E402,F401

# Sprint 41.3: Repository / Account / DeploymentCheckpoint live in
# libinv/models/repository.py. Back-imported so historical
# ``from libinv.models._legacy import Repository`` and any test patches
# on ``libinv.models._legacy.Repository`` keep resolving.
from libinv.models.repository import Account  # noqa: E402,F401
from libinv.models.repository import DeploymentCheckpoint  # noqa: E402,F401
from libinv.models.repository import Repository  # noqa: E402,F401

