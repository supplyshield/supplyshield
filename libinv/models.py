from __future__ import annotations

import json
import logging
import shutil
import time
import traceback
from datetime import datetime
from datetime import timedelta
from datetime import timezone
from io import BytesIO
from pathlib import Path
from typing import TYPE_CHECKING
from uuid import uuid4

import requests
import semver
from git.exc import GitCommandError
from jsonschema import validate
from packageurl import PackageURL
from sqlalchemy import CHAR
from sqlalchemy import JSON
from sqlalchemy import Boolean
from sqlalchemy import Column
from sqlalchemy import Date
from sqlalchemy import DateTime
from sqlalchemy import Float
from sqlalchemy import ForeignKey
from sqlalchemy import Index
from sqlalchemy import Integer
from sqlalchemy import String
from sqlalchemy import Text
from sqlalchemy import and_
from sqlalchemy import cast
from sqlalchemy import delete
from sqlalchemy import exists
from sqlalchemy import func
from sqlalchemy import select
from sqlalchemy import text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.exc import PendingRollbackError
from sqlalchemy.ext.mutable import MutableDict
from sqlalchemy.orm import Mapped
from sqlalchemy.orm import Session as OrmSession
from sqlalchemy.orm import declarative_mixin
from sqlalchemy.orm import mapped_column
from sqlalchemy.orm import relationship
from sqlalchemy.orm import selectinload
from sqlalchemy.orm import synonym
from sqlalchemy.schema import UniqueConstraint
from sqlalchemy.sql.expression import ClauseElement
from univers.versions import MavenVersion

if TYPE_CHECKING:
    from typing import Any

from libinv.base import Base
from libinv.base import conn
from libinv.base import session_scope
from libinv.env import EXCLUDED_REPOS
from libinv.env import LIBINV_TEMP_DIR
from libinv.env import PURLDB_API_URL
from libinv.env import SCANCODEIO_API_KEY
from libinv.env import SCANCODEIO_URL
from libinv.exceptions import ConflictingInfoError
from libinv.exceptions import MalformedCaterpillarMessage
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


class PackageLicenseAssociation(Base):
    __tablename__ = "package_license_association"

    package_id = Column(
        ForeignKey("libinv.packages.id", onupdate="CASCADE", ondelete="CASCADE"), primary_key=True
    )
    license_id = Column(
        ForeignKey("libinv.license_family.id", onupdate="CASCADE", ondelete="CASCADE"),
        primary_key=True,
    )

    # Sprint 37.2: lazy= audit.
    # - package: never traversed via association.package in api/cli/scanners.
    # - license: never traversed via association.license in api/cli/scanners (the
    #   sbom.py selectinload chain stops at Package.licenses; License rows are
    #   created/queried directly without back-traversal).
    package = relationship("Package", back_populates="licenses", lazy="raise_on_sql")
    license = relationship("License", back_populates="packages", lazy="raise_on_sql")

    # Sprint 33.1/33.2: declare indexes already created by alembic 0002_fk_indexes
    # so `alembic check` / autogenerate treats them as in-sync with the schema.
    __table_args__ = (
        Index("ix_package_license_association_license_id", "license_id"),
        {"schema": "libinv"},
    )


@declarative_mixin
class TimestampMixin:
    # Sprint 34.1: server_default=func.now() means Postgres always populates
    # these on INSERT, so they are NOT NULL by construction. Marking explicit.
    created_at = Column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )


class Image(Base, TimestampMixin):
    __tablename__ = "images"

    id = Column(Integer, primary_key=True)
    name = Column(String(100), nullable=False)
    # Sprint 34.1: explicit nullable=True for optional build/CI metadata.
    backend_tech = Column(String(24), nullable=True)
    account_id = Column(
        ForeignKey("libinv.accounts.id", onupdate="CASCADE", ondelete="CASCADE"), nullable=False
    )
    digest = Column(String(72), nullable=False)
    tag = Column(String(128), nullable=True)
    # Sprint 34.3: git SHA-1 is 40 hex chars (SHA-256 is 64). String(128) was
    # ~3x oversized; tightened to 40 to match git's canonical commit-hash length.
    # Sprint 34.1: nullable=True — legacy images may predate commit linkage.
    commit = Column(String(40), nullable=True)
    platform = Column(String(24), nullable=False)
    # Sprint 34.1: parent/base/repo/wasp FKs are nullable=True — root images
    # have no parent, and images may exist before being bridged to a repo/wasp.
    parent_image_id = Column(
        ForeignKey("libinv.images.id", onupdate="CASCADE", ondelete="CASCADE"), nullable=True
    )
    base_image_id = Column(
        ForeignKey("libinv.images.id", onupdate="CASCADE", ondelete="CASCADE"), nullable=True
    )
    repository_id = Column(
        ForeignKey("libinv.repositories.id", onupdate="CASCADE", ondelete="CASCADE"),
        nullable=True,
    )
    wasp_id = Column(
        ForeignKey("libinv.wasps.id", onupdate="CASCADE", ondelete="CASCADE"), nullable=True
    )

    # Sprint 37.2: lazy= audit (paired with LIBINV_STRICT_LAZY flag in Sprint 37.1).
    # - parent_image: traversed by get_base_image_of() walking up chain. lazy="select" required.
    # - base_image: only the FK is read directly (image.base_image_id); the relationship
    #   itself is never traversed in api/cli/scanners. Safe for raise_on_sql.
    # - packages: traversed in image_scanner/sca.py (with selectinload), image_scanner/sbom.py
    #   (with selectinload), and cli/query.py. Keep default select.
    # - layers: traversed by sorted_layers (called from base_image.py) and join in
    #   detect_and_update_base_image. Keep default select.
    # - repository: never traversed via image.repository in api/cli/scanners. Safe for raise.
    # - wasp: only assigned (image.wasp = wasp in bridge.py); never traversed for reads.
    #   Safe for raise_on_sql.
    parent_image = relationship(
        "Image", remote_side=[id], foreign_keys=[parent_image_id], lazy="select"
    )
    base_image = relationship(
        "Image", remote_side=[id], foreign_keys=[base_image_id], lazy="raise_on_sql"
    )
    packages = relationship("ImagePackageAssociation", back_populates="image", lazy="select")
    layers = relationship("Layer", back_populates="image", lazy="select")
    repository = relationship("Repository", back_populates="images", lazy="raise_on_sql")
    wasp = relationship("Wasp", back_populates="images", lazy="raise_on_sql")

    # Sprint 33.1/33.2: declare indexes already created by alembic 0002_fk_indexes
    __table_args__ = (
        Index("ix_images_account_id", "account_id"),
        Index("ix_images_base_image_id", "base_image_id"),
        Index("ix_images_parent_image_id", "parent_image_id"),
        Index("ix_images_repository_id", "repository_id"),
        Index("ix_images_wasp_id", "wasp_id"),
        {"schema": "libinv"},
    )

    def __str__(self):
        return f"{self.name}-{self.id}"

    @property
    def sorted_layers(self) -> str:
        return sorted(self.layers, key=lambda x: x.seq)

    def is_parent_image_of(self, other: "Image"):
        """
        Return True if self is a parent image of other.
        Parent image is a different image that contains all the layers of child and no more.
        """
        other_layers = other.sorted_layers
        self_layers = self.sorted_layers

        if len(self_layers) >= len(other_layers):
            return False

        for seq, layer in enumerate(self.sorted_layers):
            if layer != other_layers[seq]:
                return False
        return True

    @classmethod
    def get_by_id(cls, session, image_id):
        return session.get(Image, {"id": image_id})

    @classmethod
    def get_all_dev_image_ids(cls, session):
        ids = session.query(Image.id).filter(Image.account_id != ORGSRE_ACCOUNT_ID)
        return list(map(lambda x: x[0], ids))  # because sqlachemy returns tuples in ids


class Package(Base):
    __tablename__ = "packages"

    id = Column(Integer, primary_key=True)
    name = Column(String(100), nullable=False)
    # Sprint 34.1: version/language are nullable=True (legacy packages
    # may lack metadata); purl is the semantic identifier — required.
    version = Column(String(150), nullable=True)
    language = Column(String(20), nullable=True)
    purl = Column(String(300), unique=True, nullable=False)
    # Sprint 34.1: server_default guarantees population; mark NOT NULL.
    created_at = Column(DateTime, server_default=func.now(), nullable=False)
    updated_at = Column(
        DateTime,
        server_default=func.now(),
        onupdate=func.current_timestamp(),
        nullable=False,
    )
    # Sprint 37.2: lazy= audit.
    # - images: never traversed in api/cli/scanners (back-ref from Package side).
    # - licenses: traversed in image_scanner/sbom.py (with selectinload Image.packages
    #   ... Package.licenses cascade) and sbom.py:138 (package.licenses.append). Keep select.
    # - vulnerabilities: traversed in image_scanner/sca.py via
    #   selectinload(Package.vulnerabilities). Keep select.
    images = relationship(
        "ImagePackageAssociation", back_populates="package", lazy="raise_on_sql"
    )
    licenses = relationship("PackageLicenseAssociation", back_populates="package", lazy="select")
    vulnerabilities = relationship(
        "VulnerabilityPackageAssociation", back_populates="package", lazy="select"
    )

    def __str__(self):
        return self.purl


class ImagePackageAssociation(Base):
    __tablename__ = "image_package_association"

    image_id = Column(
        ForeignKey("libinv.images.id", onupdate="CASCADE", ondelete="CASCADE"), primary_key=True
    )
    package_id = Column(
        ForeignKey("libinv.packages.id", onupdate="CASCADE", ondelete="CASCADE"), primary_key=True
    )
    # Sprint 34.1: optional free-form metadata blob.
    pkg_metadata = Column("metadata", Text, nullable=True)

    # Sprint 37.2: lazy= audit.
    # - image: never traversed via association.image in api/cli/scanners.
    # - package: traversed in image_scanner/sca.py + sbom.py via
    #   selectinload(...ImagePackageAssociation.package). Keep select.
    image = relationship("Image", back_populates="packages", lazy="raise_on_sql")
    package = relationship("Package", back_populates="images", lazy="select")

    Index("not-null-metadata", pkg_metadata, mysql_length=1)

    # Sprint 33.1/33.2: declare indexes already created by alembic 0002_fk_indexes
    __table_args__ = (
        Index("ix_image_package_association_package_id", "package_id"),
        {"schema": "libinv"},
    )


class VulnerabilityPackageAssociation(Base):
    __tablename__ = "vulnerability_package_association"
    vulnerability_id = Column(
        String(50),
        ForeignKey("libinv.vulnerabilities.id", ondelete="CASCADE", onupdate="CASCADE"),
        primary_key=True,
    )
    package_id = Column(
        Integer,
        ForeignKey("libinv.packages.id", ondelete="CASCADE", onupdate="CASCADE"),
        primary_key=True,
    )
    fix = Column(String(100), doc="comma seperated list of fix versions", nullable=True)

    # Sprint 37.2: lazy= audit.
    # - vulnerability: traversed in image_scanner/sca.py via
    #   selectinload(...VulnerabilityPackageAssociation.vulnerability). Keep select.
    # - package: back-ref never traversed in api/cli/scanners.
    vulnerability = relationship("Vulnerability", back_populates="packages", lazy="select")
    package = relationship("Package", back_populates="vulnerabilities", lazy="raise_on_sql")

    # Sprint 33.1/33.2: declare indexes already created by alembic 0002_fk_indexes
    __table_args__ = (
        Index("ix_vulnerability_package_association_package_id", "package_id"),
        {"schema": "libinv"},
    )


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id = Column(String(50), primary_key=True)
    # Sprint 34.1: upstream-feed-derived fields — feeds may omit any of them.
    description = Column(String(MAX_LENGTH_VULNERABILITY_DESCRIPTION), nullable=True)
    severity = Column(String(10), nullable=True)
    related = Column(
        String(200), doc="comma seperated list of related cve ids", nullable=True
    )
    nvd_cvss_base_score = Column(
        "nvd-cvss.base_score", Float(precision=3), nullable=True
    )
    nvd_cvss_exploitability_score = Column(
        "nvd-cvss.exploitability_score", Float(precision=3), nullable=True
    )
    nvd_cvss_impact_score = Column(
        "nvd-cvss.impact_score", Float(precision=3), nullable=True
    )
    # Sprint 37.2: back-ref never traversed in api/cli/scanners (only the forward
    # VulnerabilityPackageAssociation.vulnerability direction is read).
    packages = relationship(
        "VulnerabilityPackageAssociation", back_populates="vulnerability", lazy="raise_on_sql"
    )

    def set_description(self, desc: str):
        if desc:
            self.description = desc[:MAX_LENGTH_VULNERABILITY_DESCRIPTION]

    def __str__(self):
        return self.id


class License(Base):
    __tablename__ = "license_family"

    id = Column(Integer, primary_key=True)
    # Sprint 34.1: license name is the semantic key (unique) — required.
    name = Column(String(MAX_LENGTH_LICENSE), unique=True, nullable=False)
    # Sprint 37.2: back-ref never traversed in api/cli/scanners (only the forward
    # Package.licenses direction is read in sbom.py).
    packages = relationship(
        "PackageLicenseAssociation", back_populates="license", lazy="raise_on_sql"
    )

    def set_license_name(self, name):
        if name:
            self.name = name[:MAX_LENGTH_LICENSE]


class Layer(Base, TimestampMixin):
    __tablename__ = "layers"
    id = Column(CHAR(length=64), primary_key=True)
    image_id = Column(
        ForeignKey("libinv.images.id", onupdate="CASCADE", ondelete="CASCADE"), primary_key=True
    )
    seq = Column(Integer, primary_key=True, nullable=False)
    # Sprint 37.2: back-ref never traversed via layer.image; only Image.layers is read.
    image = relationship("Image", back_populates="layers", lazy="raise_on_sql")

    def __eq__(self, other):
        return self.id == other.id and self.seq == other.seq

    def __str__(self):
        return self.id


class Repository(Base):
    __tablename__ = "repositories"
    id = Column(Integer, primary_key=True)
    provider = Column(String(200), nullable=False)
    org = Column(String(200), nullable=False)
    name = Column(String(200), nullable=False)
    is_public = Column(Boolean, default=False, nullable=False)
    # Sprint 37.2: lazy= audit. All three back-refs from Repository are never
    # traversed in api/cli/scanners — routes query the child tables directly
    # filtered by repository_id. Safe for raise_on_sql.
    images = relationship("Image", back_populates="repository", lazy="raise_on_sql")
    secbugs = relationship("Secbug", back_populates="repository", lazy="raise_on_sql")
    # Sprint 34.1: optional org metadata.
    pod = Column(String(200), nullable=True)
    subpod = Column(String(200), nullable=True)

    actionable_versions = relationship(
        "Repository_ActionablePackageAvailableVersion",
        back_populates="repository",
        lazy="raise_on_sql",
    )

    UniqueConstraint("org", "name", name="org_repo")

    # Note: pod/subpod left nullable=True (declared above) — these are optional
    # organizational metadata that may not be set for every repository.

    def __str__(self):
        return self.url

    @property
    def url(self):
        return f"https://{self.provider}/{self.org}/{self.name}"

    @classmethod
    def from_url(cls, url):
        return Repository(**explode_git_url(url))

    @property
    def vcs(self):
        if self.provider == "github.com":
            github = GitHubApp()
            github.authenticate()
            return github
        elif self.provider == "bitbucket.org":
            return BitBucketApp()
        else:
            raise NotImplementedError(f"Repository provider: {self.provider} not implemented")

    def clone(self, target_dir):
        self.vcs.authenticate()
        return self.vcs.clone(self.url, target_dir)

    @classmethod
    def get_by_git_url(
        cls, git_url: str, session: OrmSession | None = None
    ) -> "Repository | None":
        s = session or conn
        try:
            repo_url = Repository.from_url(git_url)
            repo = (
                s.query(Repository)
                .filter(
                    and_(
                        Repository.name == repo_url.name,
                        Repository.provider == repo_url.provider,
                        Repository.org == repo_url.org,
                    )
                )
                .first()
            )
            return repo
        except ModuleNotFoundError:
            return None

    def raise_or_update_sca_issues(
        self, environment: str = "stage", session: OrmSession | None = None
    ) -> None:
        s = session or conn
        actionables = Actionable.get_actionable_and_secure_versions(s, self.id, environment)
        if not actionables["results"]:
            Actionable.close_sca_issue(self)
        else:
            Actionable.raise_sca_as_issue(self, actionables)


class Account(Base):
    __tablename__ = "accounts"
    id = Column(String(12), primary_key=True)
    # Sprint 34.1: account name is the human-readable identifier — required
    # (Account.ensure_exists() raises ValueError if a creating call omits it).
    name = Column(String(50), nullable=False)
    type = Column(String(10), server_default="stage", nullable=False)

    def is_prod(self):
        return self.type == "prod"

    @classmethod
    def ensure_exists(
        cls,
        account_id: str,
        name: str | None = None,
        account_type: str = "stage",
        session: OrmSession | None = None,
    ) -> None:
        """
        Create Account if it does not exist, nop otherwise
        """
        s = session or conn
        if not s.query(cls).filter(cls.id == account_id).one_or_none():
            if not name:
                raise ValueError(
                    f"Account id: {account_id} does not exist. Cannot create new account without a name"
                )
            new_account = cls(id=account_id, name=name, type=account_type)
            s.add(new_account)
            logger.info(f"Created new account id: {account_id} name: {name} type: {account_type}")


class DeploymentCheckpoint(Base, TimestampMixin):
    __tablename__ = "deployment_checkpoints"

    id: Mapped[int] = mapped_column(primary_key=True)
    active: Mapped[int] = mapped_column(default=False, nullable=False)
    checkpoint: Mapped[datetime] = mapped_column(nullable=False)

    def __str__(self):
        return f"{self.checkpoint}"

    @classmethod
    def get(cls, session):
        return session.query(DeploymentCheckpoint).filter_by(active=True).one_or_none()

    @classmethod
    def set(cls, session, checkpoint):
        old_checkpoint = cls.get(session)
        if old_checkpoint:
            old_checkpoint.active = False
            session.add(old_checkpoint)
        checkpoint, _ = get_or_create(session, DeploymentCheckpoint, checkpoint=checkpoint)
        checkpoint.active = True
        LatestImage.calibrate(session, checkpoint)
        session.add(checkpoint)
        session.commit()
        return checkpoint

    @classmethod
    def list(cls, session):
        checkpoints = session.query(DeploymentCheckpoint).all()
        return checkpoints


class LatestImage(Base):
    """
    Latest images as per DeploymentCheckpoint
    """

    __tablename__ = "latest_images"
    image_id = Column(
        ForeignKey("libinv.images.id", onupdate="CASCADE", ondelete="CASCADE"), primary_key=True
    )
    account_id = Column(
        ForeignKey("libinv.accounts.id", onupdate="CASCADE", ondelete="CASCADE"), primary_key=True
    )  # This helps to speed up joins with account table

    # Sprint 33.1/33.2: declare indexes already created by alembic 0002_fk_indexes
    __table_args__ = (
        Index("ix_latest_images_account_id", "account_id"),
        {"schema": "libinv"},
    )

    @classmethod
    def calibrate(cls, session, checkpoint):
        """
        Calibrate latest images as per given checkpoint. Images after the checkpoints are not
        considered
        """
        session.execute(delete(LatestImage))
        stmt = text(
            """
        INSERT INTO latest_images
        SELECT
              images.id, images.account_id
          FROM
              images
              INNER JOIN (
                      SELECT
                          name,
                          account_id,
                          platform,
                          max(created_at) AS created_at
                      FROM
                          images
                      WHERE created_at <= :checkpoint
                      GROUP BY
                          name, account_id, platform
                  )
                      AS finder -- finder has latest image data
                      ON
                      images.name = finder.name
                      AND images.account_id
                          = finder.account_id
                      AND images.platform = finder.platform
                      AND images.created_at
                          = finder.created_at;
           """
        )
        session.execute(stmt, {"checkpoint": checkpoint})


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


class Wasp(Base, TimestampMixin):  # Wasp eats caterpillars
    """
    A wasp eats catterpillar messages using ``eat_caterpillar_message`` function.
    """

    __tablename__ = "wasps"

    id = Column(Integer, primary_key=True, autoincrement=True)
    uuid = Column(String(36), nullable=False, unique=True, default=uuid4)
    # Sprint 34.1: repository_id nullable=True for the (rare) excluded-repo
    # path that returns before linking; Wasp's domain invariants come from
    # is_valid_raw_message at the caterpillar-message layer.
    repository_id = Column(
        ForeignKey("libinv.repositories.id", onupdate="CASCADE"), nullable=True
    )
    # Sprint 34.1: tag is not in the message schema's required[] — keep optional.
    tag = Column(String(128), nullable=True)
    # Sprint 34.3: git SHA-1 is 40 hex chars; tightened from String(128).
    # Sprint 34.1: commit/environment/jenkins_url are required by the
    # caterpillar message schema (commit + aws_environment + job_url) and
    # eat_caterpillar_message always populates them — mark NOT NULL.
    commit = Column(String(40), nullable=False)
    environment = Column(String(128), nullable=False)
    jenkins_url = Column(String(256), nullable=False)
    raw_message = Column(String(2048), nullable=False)
    ate_successfully = Column(Boolean(), nullable=False, default=True, server_default="1")
    # Sprint 34.1: server-default + Python-default of "" — never NULL.
    complaints = Column(Text, default="", server_default="", nullable=False)

    # Sprint 37.2: lazy= audit.
    # - images: never traversed via wasp.images in api/cli/scanners.
    # - repository: traversed in repository_scanner/bridge.py:69 and
    #   repository_scanner/sast/SarifResult.py:69,70,170,171,233 and
    #   sast/semgrep/SemgrepRunner.py:16. Keep default select. Callers that
    #   process many Wasp rows in a loop should add selectinload(Wasp.repository).
    # - actionable / actionable_versions: never traversed via wasp.actionable*
    #   in api/cli/scanners (the forward direction
    #   Repository_ActionablePackageAvailableVersion.wasp is used instead).
    images = relationship("Image", back_populates="wasp", lazy="raise_on_sql")
    repository = relationship("Repository", lazy="select")
    actionable = relationship(
        "Repository_ActionablePackageAvailableVersion",
        back_populates="wasp",
        overlaps="actionable_versions",
        lazy="raise_on_sql",
    )
    actionable_versions = relationship(
        "Repository_ActionablePackageAvailableVersion",
        back_populates="wasp",
        overlaps="actionable",
        lazy="raise_on_sql",
    )

    # Sprint 33.1/33.2: declare indexes already created by alembic 0002_fk_indexes
    __table_args__ = (
        Index("ix_wasps_repository_id", "repository_id"),
        {"schema": "libinv"},
    )

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, exc_traceback):
        if exc_type == MalformedCaterpillarMessage:
            logger.error(exc_value)
            return True

        if exc_type:
            trace = "".join(traceback.format_exception(exc_type, exc_value, exc_traceback))
            self.throw(f"{exc_type} : {exc_value} : {trace}")

        s = getattr(self, "_session", None) or conn
        s.add(self)
        s.commit()
        logger.debug(f"Cleaning up wasp {self}")
        if hasattr(self, "_project_dir"):
            shutil.rmtree(self._project_dir)
            logger.debug(f"Delete {self._project_dir}")

        return False

    def __str__(self):
        return f"{self.uuid}"

    @classmethod
    def eat_caterpillar_message(
        cls, message: dict, session: OrmSession | None = None
    ) -> "Wasp | None":
        """
        Messages must be sent in the following format:

            {
                "repository": {
                    "url": "git@github.com:org-name/repository.git",
                    "commit": "commit_hash",
                    "tag": "tag"
                },
                "job_url": "https://jenkins/job/project/",
                "aws_environment": "stage/prod",
                "buildx_enabled": "1/0",
                "ecr_image": [
                    {
                        "name": "account-id.dkr.ecr.ap-south-1.amazonaws.com/name",
                        "digest": "sha256:digest",
                        "type": "Image",
                        "platform": {
                            "architecture": "amd64",
                            "os": "linux"
                        }
                    }
                ],
                "type": "Bridge",
                "timestamp": "2024-09-20-03:45:42"
            }
        """
        s = session or conn

        if not is_valid_raw_message(message):
            raise MalformedCaterpillarMessage("Invalid wasp received")

        raw_message = json.dumps(message)
        repository_url = message["repository"]["url"]
        commit = message["repository"]["commit"]
        tag = message["repository"]["tag"]
        environment = message["aws_environment"]
        jenkins_url = message["job_url"]

        if is_excluded_repo(repository_url):
            logger.error(f"[!] Excluded repository: {repository_url}")
            return

        repository, created = get_or_create(s, Repository, **explode_git_url(repository_url))
        if created:
            logger.debug(f"[*] Created repository: {repository}")

        # sql constraint might take care of null/None value, ensure it's not empty ("")
        if not repository.name or not repository.url or not repository.provider:
            raise MalformedCaterpillarMessage(
                f"Repository details cannot be empty, repository: {repository}"
                f" given url: {repository_url}"
            )

        wasp = cls(
            repository=repository,
            tag=tag,
            commit=commit,
            raw_message=raw_message,
            environment=environment,
            jenkins_url=jenkins_url,
        )
        wasp._session = s

        s.add(wasp)
        s.commit()
        logger.info(f"Wasp ate caterpillar: {wasp}")
        return wasp

    @property
    def cwd(self) -> Path:
        return Path(LIBINV_TEMP_DIR)

    def throw(self, why: str):
        """
        Throw some food out. Specify why any actions on wasp failed without failing entire libinv
        """
        s = getattr(self, "_session", None) or conn
        try:
            s.connection()
        except PendingRollbackError:
            s.rollback()

        self.complaints += why
        self.ate_successfully = False
        logger.error(f"{self} raised: {why}")

    @property
    def project_dir(self) -> Path:
        """
        Return a dir for this wasp to keep all its files.
        Treat this as a temp dir that will be emptied when the wasp dies
        """
        if not hasattr(self, "_project_dir"):
            self._project_dir = Path(self.cwd, self.uuid)
            logger.debug("project_dir: %s", self._project_dir)
            self._project_dir.mkdir(exist_ok=True, parents=True)

        return self._project_dir

    @property
    def repo_dir(self):
        if not hasattr(self, "_repo_dir"):
            self._repo_dir = self.clone()

        return self._repo_dir

    def clone(self):
        """
        Return dir after cloning repository given to to wasp
        """
        repository = self.repository
        commit = self.commit
        logger.debug(f"[*] Cloning {self.repository.url}")
        target_dir = Path(self.project_dir, f"{repository.name}-{commit[:10]}")
        Path(target_dir).mkdir(exist_ok=True)
        repo = None
        try:
            logger.info("Trying to clone now..")
            repo = repository.clone(target_dir)
            if repo is None:
                raise ValueError(f"repository.clone() returned None for {repository.url}")
        except GitCommandError as e:
            logger.error(e)
            self.throw(f"failed to clone repository: {repository.url}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error during clone: {e}")
            self.throw(f"failed to clone repository: {repository.url} - {str(e)}")
            raise
        try:
            repo.git.checkout(commit)
        except GitCommandError:
            self.throw(f"commit does not exist: {commit}")
            raise

        if not repo.head.is_detached:
            raise RuntimeError(
                f"Expected detached HEAD after checkout, got branch {repo.head.ref}"
            )
        logger.info(f"[+] Cloned {repository}")
        return target_dir


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


class Actionable(Base):
    """
    Stores next safe version of an actionable package
    """

    __tablename__ = "safe_actionable"

    uuid = Column(String(36), nullable=False, unique=True, default=uuid4, primary_key=True)
    package_url = Column(String(300), nullable=False, unique=True)
    # Sprint 34.1: server_default guarantees population — NOT NULL.
    updated_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    # Sprint 37.2: traversed in api/onboard_package.py:45,64 (actionable.available_versions)
    # and via the selectinload chain in get_actionable (Actionable.get_safe_versions /
    # get_latest use the __dict__ sentinel to detect pre-loaded state). Keep select.
    available_versions = relationship(
        "ActionablePackageAvailableVersion",
        back_populates="actionable",
        cascade="all, delete-orphan",
        lazy="select",
    )

    @classmethod
    def populate(
        cls,
        repository_id: int | None = None,
        environment: str | None = None,
        session: OrmSession | None = None,
    ) -> None:
        actionable_purls = cls.get_actionable_for(repository_id, environment)
        for purl in actionable_purls:
            purl_name = f"pkg:{purl.type}/{purl.namespace}/{purl.name}"
            if is_blacklist(purl_name):
                logger.debug(f"Blacklisted package: {purl_name}")
                continue

            with session_scope() as session:
                available_versions = (
                    session.query(ActionablePackageAvailableVersion.version)
                    .filter(ActionablePackageAvailableVersion.package_url == purl_name)
                    .all()
                )
                available_versions = [v[0] for v in available_versions]

                actionable, _ = get_or_create(session, Actionable, package_url=purl_name)
                if purl.version not in available_versions:
                    get_or_create(
                        session,
                        ActionablePackageAvailableVersion,
                        package_url=purl_name,
                        version=purl.version,
                        is_version_in_use=True,
                        actionable_id=actionable.uuid,
                        scan_status="ADDED",
                        is_latest=False,
                    )
                session.add(actionable)
                session.commit()

    def fetch_and_store_versions(self, session: OrmSession | None = None) -> None:
        s = session or conn
        logger.info(f"Processing: {self.package_url}")
        try:
            query = {"packages": [{"purl": self.package_url}]}
            try:
                response = requests.post(
                    f"{PURLDB_API_URL}/collect/index_packages/",
                    json=query,
                    timeout=30,
                )
                response.raise_for_status()
            except requests.RequestException as exc:
                logger.error("PURLDB index_packages request failed: %s", exc)
                raise

            if response.status_code == 200:
                response_json = response.json()
                new_versions = set(
                    PackageURL.from_string(purl).version
                    for purl in response_json.get("unqueued_packages", [])
                    + response_json.get("queued_packages", [])
                )

                if new_versions == ():
                    logger.error(f"No available versions found for package: {self.package_url}")
                    return

                results = []
                for version in new_versions:
                    results.append(
                        {
                            "package_url": self.package_url,
                            "scan_status": "ADDED",
                            "is_latest": False,
                            "vulns_count": None,
                            "scan_output": None,
                            "actionable_id": self.uuid,
                            "version": version,
                        }
                    )

                with session_scope() as session:
                    for result in results:
                        get_or_create(session, ActionablePackageAvailableVersion, **result)
                        session.commit()
            else:
                logger.error(f"Error fetching package: {self.package_url} - Error: {response.text}")
                return
            s.commit()
        except Exception as e:
            logger.error(f"Error processing package: {self.package_url} - {e}")
            s.rollback()

    def get_available_versions(self):
        available_versions = list()
        with session_scope() as session:
            available_versions = (
                session.query(ActionablePackageAvailableVersion)
                .filter(ActionablePackageAvailableVersion.actionable_id == self.uuid)
                .all()
            )
        sorted_versions = sorted(available_versions, key=lambda v: MavenVersion(v.version))
        return sorted_versions

    @classmethod
    def get_packages_without_versions(cls, session: OrmSession | None = None):
        s = session or conn
        subquery = select(1).where(
            ActionablePackageAvailableVersion.actionable_id == Actionable.uuid
        )
        query = select(Actionable).where(~exists(subquery))
        return s.execute(query).scalars().all()

    def get_versions_in_use(self, session):
        return list(
            session.query(ActionablePackageAvailableVersion)
            .filter(ActionablePackageAvailableVersion.actionable_id == self.uuid)
            .filter(ActionablePackageAvailableVersion.is_version_in_use == True)
            .all()
        )

    def get_safe_versions(self, session: OrmSession | None = None):
        # Prefer eagerly-loaded relationship to avoid N+1 round trips when
        # the caller pre-loaded `available_versions` (e.g. via selectinload
        # in `get_actionable_and_secure_versions`). `"available_versions" in
        # self.__dict__` is the canonical sentinel for "this collection has
        # already been populated on the instance" — it does NOT trigger a
        # lazy load (which `getattr(self, "available_versions")` would).
        if "available_versions" in self.__dict__:
            result = [
                v
                for v in self.available_versions
                if v.vulns_count == 0 and v.scan_status == "SUCCESS"
            ]
            return sorted(result, key=lambda v: MavenVersion(v.version))
        s = session or conn
        result = list(
            s.query(ActionablePackageAvailableVersion)
            .filter(ActionablePackageAvailableVersion.actionable_id == self.uuid)
            .filter(ActionablePackageAvailableVersion.vulns_count == 0)
            .filter(ActionablePackageAvailableVersion.scan_status == "SUCCESS")
            .all()
        )
        return sorted(result, key=lambda v: MavenVersion(v.version))

    def get_versions_between(self, start_version, end_version):
        versions = self.get_available_versions()
        start_index = None
        end_index = None
        for i in range(0, len(versions)):
            if not start_index and versions[i].version == start_version.version:
                start_index = i
            if not end_index and versions[i].version == end_version:
                end_index = i

        return versions[start_index : end_index + 1]

    def find_safe_version_in(
        self, list_of_versions, session: OrmSession | None = None
    ) -> None:
        s = session or conn
        logger.info(f"Finding closest safe version for : {self.package_url}")

        if len(list_of_versions) == 0:
            logger.error(f"No available versions found for package: {self.package_url}")
            return

        left, right = 0, len(list_of_versions) - 1
        safe_version_obj = None

        while left <= right:
            mid = (left + right) // 2
            mid_version = list_of_versions[mid]
            logger.info(f"Checking version: {mid_version}")

            mid_version.scan_and_update_results()

            if mid_version._get_vulnerabilities_count() == 0:
                safe_version_obj = mid_version
                right = mid - 1
            else:
                left = mid + 1

        if safe_version_obj:
            logger.warning(
                f"Closest safe version for {self.package_url}: {safe_version_obj.version}"
            )
            self.scan_complete = True
        else:
            logger.warning(f"No safe version found for {self.package_url}")
            self.scan_complete = True

        s.commit()

    def get_latest(
        self, session: OrmSession | None = None
    ) -> "ActionablePackageAvailableVersion | None":
        # Prefer eagerly-loaded relationship to avoid N+1 round trips.
        # See `get_safe_versions` for the `__dict__` sentinel rationale.
        if "available_versions" in self.__dict__:
            latest = [v for v in self.available_versions if v.is_latest]
            return latest[0] if latest else None
        s = session or conn
        return (
            s.query(ActionablePackageAvailableVersion)
            .filter(ActionablePackageAvailableVersion.actionable_id == self.uuid)
            .filter(ActionablePackageAvailableVersion.is_latest == True)
            .one_or_none()
        )

    @classmethod
    def get_safe_version_for(cls, session, package_url):
        package_url = PackageURL.from_string(package_url)
        current_version = (
            session.query(ActionablePackageAvailableVersion)
            .filter(
                ActionablePackageAvailableVersion.package_url
                == f"pkg:{package_url.type}/{package_url.namespace}/{package_url.name}",
                ActionablePackageAvailableVersion.version == package_url.version,
            )
            .one_or_none()
        )
        if current_version:
            return current_version.get_safe_upgrade()
        else:
            return "NO_SAFE_VERSION"

    def mark_latest_version(self):
        """
        Mark the maximum version as latest for each actionable package.
        """
        with session_scope() as session:
            versions = (
                session.query(ActionablePackageAvailableVersion)
                .filter(ActionablePackageAvailableVersion.actionable_id == self.uuid)
                .all()
            )
            for version in versions:
                version.is_latest = False

            latest_version = max(versions, key=lambda v: MavenVersion(v.version))
            latest_version.is_latest = True
            session.commit()

    @classmethod
    def get_actionable(cls, session, repository_id, environment):
        # Eagerly load the per-row chain that `get_actionable_and_secure_versions`
        # walks for every row:
        #   row.available_version            -> ActionablePackageAvailableVersion
        #   row.available_version.actionable -> Actionable
        #   row.available_version.actionable.available_versions
        #                                    -> all sibling versions (used by
        #                                       Actionable.get_latest /
        #                                       get_safe_versions)
        #   row.wasp                         -> commit + jenkins_url metadata
        # Without selectinload this is the classic N+1 cascade: per outer row
        # SQLAlchemy issues 3+ lazy-load queries. With selectinload each level
        # is a single IN(...) query, collapsing O(P) -> O(1).
        return (
            session.query(Repository_ActionablePackageAvailableVersion)
            .options(
                selectinload(
                    Repository_ActionablePackageAvailableVersion.available_version
                )
                .selectinload(ActionablePackageAvailableVersion.actionable)
                .selectinload(Actionable.available_versions),
                selectinload(Repository_ActionablePackageAvailableVersion.wasp),
            )
            .join(ActionablePackageAvailableVersion)
            .filter(Repository_ActionablePackageAvailableVersion.repository_id == repository_id)
            .filter(Repository_ActionablePackageAvailableVersion.environment == environment)
            .all()
        )

    @classmethod
    def get_actionable_and_secure_versions(
        cls, session, repository_id, environment, with_metadata=True
    ):
        actionable_packages = Actionable.get_actionable(session, repository_id, environment)
        results = []

        for package in actionable_packages:
            current_version = package.available_version.version

            if (
                not package.available_version.vulns_count
                or package.available_version.vulns_count == 0
            ):
                continue

            latest_version = package.available_version.actionable.get_latest()

            secure_versions = None
            secure_versions = [
                package.version
                for package in package.available_version.actionable.get_safe_versions()
            ]

            results.append(
                {
                    "secure_version_available": len(secure_versions) > 0,
                    "full_package_url": package.available_version.package_url,
                    "current_version": current_version,
                    "current_version_score": package.available_version.epss_score,
                    "latest_version_score": latest_version.score,
                    "suggested_versions": secure_versions,
                    "versionless_id": package.available_version.actionable.uuid,
                }
            )

        commit_id = ""
        jenkins_url = ""

        if with_metadata and len(actionable_packages) > 0:
            commit_id = actionable_packages[0].wasp.commit
            jenkins_url = actionable_packages[0].wasp.jenkins_url

        results = sorted(results, key=lambda x: x["secure_version_available"], reverse=True)

        if with_metadata:
            return {"commit_id": commit_id, "jenkins_url": jenkins_url, "results": results}
        return results

    @staticmethod
    def get_actionables_issue(repo):
        """
        Checks if an issue already exists in the GitHub repository.
        """
        issues = repo.vcs.get_issues(repo)
        for issue in issues:
            for label in issue["labels"]:
                if label["name"] == f"sca-actionable-{repo.name}":
                    return issue["url"], True
        return None, False

    @classmethod
    def raise_sca_as_issue(cls, repo, actionables):
        """
        Creates an issue in the GitHub repository or updates if the issue already exists.
        """
        issue_url, existing_issue = cls.get_actionables_issue(repo)
        title, message = issue_reporter.prepare_git_issue_content(actionables)

        if existing_issue:
            repo.vcs.update_issue(
                issue_url, title, message, [f"sca-actionable-{repo.name}"], "Task"
            )
        else:
            repo.vcs.create_issue(repo, title, message, [f"sca-actionable-{repo.name}"], "Task")
            repo.vcs.update_label(repo, f"sca-actionable-{repo.name}", {"color": "b62c41"})

    @classmethod
    def close_sca_issue(cls, repo):
        """
        Closes an issue in the GitHub repository.
        """
        issue_url, existing_issue = cls.get_actionables_issue(repo)
        if existing_issue:
            repo.vcs.close_issue(issue_url)
        else:
            logger.error("No Issues were created for this repo")


class ActionablePackageAvailableVersion(Base):
    """
    Stores all available versions of an actionable package
    """

    __tablename__ = "actionable_package_available_versions"

    uuid = Column(String(36), nullable=False, unique=True, default=uuid4, primary_key=True)
    scan_status = Column(String(20), nullable=False)
    package_url = Column(String(300), nullable=False)
    version = Column(String(100), nullable=False)
    is_latest = Column(Boolean, nullable=False)
    vulns_count = Column(Integer, nullable=True)
    epss_score = Column(Float(precision=6), nullable=True)
    scan_output = Column(Text, nullable=True)
    # Sprint 34.1: server_default guarantees population — NOT NULL.
    updated_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )
    # Sprint 34.1: Python default=False; pair with server_default + NOT NULL.
    is_version_in_use = Column(
        Boolean, default=False, server_default="false", nullable=False
    )
    # Sprint 34.1: actionable_id FK left nullable=True — an APAV row may
    # transiently exist without an Actionable parent during ingestion.
    actionable_id = Column(
        ForeignKey("libinv.safe_actionable.uuid", onupdate="CASCADE", ondelete="CASCADE"),
        nullable=True,
    )
    scancode_project_uuid = Column(String(36), nullable=True)
    # Sprint 37.2: lazy= audit.
    # - actionable: traversed in api/actionable/package_scan.py:45 and
    #   api/actionable/dashboards.py via the get_actionable selectinload chain
    #   (Repository_APAV.available_version -> APAV.actionable -> Actionable.available_versions).
    #   cli/actionable.py:221 also walks package.available_version.actionable. Keep select.
    # - associated_repositories: never traversed in api/cli/scanners (queries go
    #   through Repository_APAV directly).
    actionable = relationship("Actionable", back_populates="available_versions", lazy="select")
    associated_repositories = relationship(
        "Repository_ActionablePackageAvailableVersion",
        back_populates="available_version",
        primaryjoin="ActionablePackageAvailableVersion.uuid == Repository_ActionablePackageAvailableVersion.actionable_package_version_id",
        lazy="raise_on_sql",
    )

    __table_args__ = (
        UniqueConstraint("package_url", "version", name="uq_package_version"),
        # Sprint 33.1/33.2: declare indexes already created by alembic 0002_fk_indexes
        Index("ix_actionable_pkg_available_versions_actionable_id", "actionable_id"),
        {"schema": "libinv"},
    )

    def __str__(self):
        return str(self.uuid)

    @property
    def purl(self):
        return PackageURL.from_string(self.package_url + "@" + self.version)

    @property
    def parsed_purl(self):
        """Return the parsed PackageURL without version for easy access to type, namespace, name"""
        return PackageURL.from_string(self.package_url)

    def _set_vulns_count(self, vulns_count):
        self.vulns_count = vulns_count

    def _get_vulnerabilities_count(self):
        if not self.scancode_project_uuid:
            return 0

        from libinv.services.scancodeio_client import get_default_client

        http_client = get_default_client()
        if http_client is not None:
            try:
                return http_client.get_vulnerability_count(self.scancode_project_uuid)
            except Exception as exc:
                logger.warning(
                    "SCIO HTTP get_vulnerability_count failed for %s: %s; "
                    "falling back to SQL",
                    self.scancode_project_uuid,
                    exc,
                )

        if DiscoveredPackage is None:
            return 0

        with session_scope() as session:
            result = (
                session.query(
                    func.sum(
                        func.jsonb_array_length(
                            cast(DiscoveredPackage.affected_by_vulnerabilities, JSONB)
                        )
                    ).label("total_vulnerabilities")
                )
                .filter(DiscoveredPackage.project_id == self.scancode_project_uuid)
                .filter(DiscoveredPackage.affected_by_vulnerabilities != "[]")
                .one()
            )
            total_vulnerabilities = result.total_vulnerabilities
            if total_vulnerabilities is None:
                return 0
            return int(total_vulnerabilities)

    @property
    def vulnerability_severities(self):
        if self.scancode_project_uuid is None:
            return None

        from libinv.services.scancodeio_client import get_default_client

        http_client = get_default_client()
        if http_client is not None:
            try:
                return http_client.get_severity_counts(self.scancode_project_uuid)
            except Exception as exc:
                logger.warning(
                    "SCIO HTTP get_severity_counts failed for %s: %s; "
                    "falling back to SQL",
                    self.scancode_project_uuid,
                    exc,
                )

        query = text(
            """
            WITH RECURSIVE severities(level) AS (
                VALUES ('critical'), ('high'), ('medium'), ('low'), ('unknown')
            ),
            mdata AS (
                SELECT
                    CASE
                        WHEN EXISTS (SELECT 1 FROM jsonb_array_elements(sd.affected_by_vulnerabilities) AS elem WHERE elem::varchar LIKE '%CRITICAL%') THEN 'critical'
                        WHEN EXISTS (SELECT 1 FROM jsonb_array_elements(sd.affected_by_vulnerabilities) AS elem WHERE elem::varchar LIKE '%HIGH%') THEN 'high'
                        WHEN EXISTS (SELECT 1 FROM jsonb_array_elements(sd.affected_by_vulnerabilities) AS elem WHERE elem::varchar LIKE '%MEDIUM%' OR elem::varchar LIKE '%MODERATE%') THEN 'medium'
                        WHEN EXISTS (SELECT 1 FROM jsonb_array_elements(sd.affected_by_vulnerabilities) AS elem WHERE elem::varchar LIKE '%LOW%') THEN 'low'
                        ELSE 'unknown'
                    END AS severity_level
                FROM public.scanpipe_discoveredpackage sd
                WHERE
                    jsonb_array_length(sd.affected_by_vulnerabilities) > 0
                    AND sd.project_id = :project_id
            )
            SELECT
                s.level AS severity_level,
                COALESCE(COUNT(m.severity_level), 0) as count
            FROM severities s
            LEFT JOIN mdata m ON m.severity_level = s.level
            GROUP BY s.level
            ORDER BY
                CASE s.level
                    WHEN 'critical' THEN 1
                    WHEN 'high' THEN 2
                    WHEN 'medium' THEN 3
                    WHEN 'low' THEN 4
                    ELSE 5
                END;
            """
        )

        with session_scope() as session:
            result = session.execute(query, {"project_id": self.scancode_project_uuid})
            data = [{"severity_level": row.severity_level, "count": row.count} for row in result]
            return data

    @property
    def score(self):
        severities = self.vulnerability_severities
        if not severities:
            return None
        score = 0
        for severity in severities:
            if severity["severity_level"] == "critical":
                score += severity["count"] * 20
            elif severity["severity_level"] == "high":
                score += severity["count"] * 10
            elif severity["severity_level"] == "medium":
                score += severity["count"] * 5
            elif severity["severity_level"] == "low":
                score += severity["count"] * 1
        return score

    @classmethod
    def get_latest_packages(cls):
        with session_scope() as session:
            return session.query(cls).filter(cls.is_latest == True).all()

    @classmethod
    def get_scan_failed_packages(cls):
        with session_scope() as session:
            return (
                session.query(cls)
                .filter(cls.vulns_count == None)
                .filter(cls.scan_status == "FAILED")
                .all()
            )

    @classmethod
    def get_packages_in_use(cls):
        with session_scope() as session:
            return session.query(cls).filter(cls.is_version_in_use == True).all()

    def scan_and_update_results(
        self, session: OrmSession | None = None, is_rescan: bool = False
    ) -> None:
        """ "
        The function triggers a scan for the package and updates the results.
        """
        s = session or conn
        logger.info(f"Scanning: {self}")
        if self.scan_status == "SUCCESS" and not is_rescan:
            logger.info(f"Scan already completed for: {self}")
            return

        try:
            request_session = requests.Session()
            self.scan_status = "TRIGGERED"
            if SCANCODEIO_API_KEY:
                request_session.headers.update({"Authorization": f"Token {SCANCODEIO_API_KEY}"})

            projects_api_url = f"{SCANCODEIO_URL}/api/projects/"
            project_name = f"{str(self)}-{time.time_ns()}"
            project_data = {
                "name": project_name,
                "pipeline": ["load_inventory", "purl_sbom", "load_sbom", "find_vulnerabilities"],
                "execute_now": True,
            }
            scan_data = {
                "headers": [{"tool_name": "scanpipe"}],
                "packages": [
                    {
                        "type": self.purl.type,
                        "namespace": self.purl.namespace,
                        "name": self.purl.name,
                        "version": self.purl.version,
                        "qualifiers": "",
                        "subpath": "",
                    }
                ],
            }
            memory_file = BytesIO(json.dumps(scan_data).encode())
            files = {"upload_file": ("dependencies.json", memory_file)}

            response = request_session.post(
                projects_api_url, data=project_data, files=files, timeout=300
            )
            logger.debug("projects_api_url: %s", projects_api_url)
            logger.debug(f"Scancodeio response: {response.text}")

            self.scan_output = response.text
            response_json = response.json()
            self.scancode_project_uuid = response_json["uuid"]
            self.vulns_count = self._get_vulnerabilities_count()
        except Exception as e:
            self.scan_status = "FAILED"
            self.scan_output = f"Error running scancodeio - Error: {e}"
            logger.error(f"Error running scancodeio - Error: {e}")
        finally:
            if self.scan_status != "FAILED":
                self.scan_status = "SUCCESS"
            s.add(self)
            s.commit()
            memory_file.close()

    @property
    def is_safe(self):
        return self.vulns_count == 0

    @property
    def scanned(self):
        return self.scan_status == "SUCCESS"

    def get_safe_upgrade(self):
        """
        Return the upgrade version if there are any available safe versions above the current version
        """
        available_safe_versions = self.actionable.get_safe_versions()
        current_version = MavenVersion(self.version)
        for version in available_safe_versions:
            if MavenVersion(version.version) >= current_version:
                return version.version
        return None

    @classmethod
    def get_by_purl(cls, session, package_url, version):
        return (
            session.query(cls)
            .filter(cls.package_url == package_url)
            .filter(cls.version == version)
            .one_or_none()
        )

    def get_cves(self, session):
        """
        Return a set of CVE IDs affecting this package version based on
        scanpipe discovered packages linked via scancode_project_uuid.
        """
        if not self.scancode_project_uuid or DiscoveredPackage is None:
            return set()

        discovered_packages = (
            session.query(DiscoveredPackage)
            .filter(DiscoveredPackage.project_id == self.scancode_project_uuid)
            .all()
        )

        cve_set = set()
        for discovered_pkg in discovered_packages:
            vulnerabilities = getattr(discovered_pkg, "affected_by_vulnerabilities", [])
            if not vulnerabilities:
                continue
            for vulnerability in vulnerabilities:
                try:
                    aliases = vulnerability.get("aliases", [])
                    for alias in aliases:
                        if isinstance(alias, str) and alias.upper().startswith("CVE-"):
                            cve_set.add(alias.upper())
                except (AttributeError, TypeError):
                    # Ignore malformed vulnerability entries
                    continue

        return cve_set


class Repository_ActionablePackageAvailableVersion(Base):
    """
    Model representing actionable for a repository and the corresponding version in ActionablePackageAvailableVersion table
    """

    __tablename__ = "repository_actionable_package_versions_association"

    uuid = Column(String(36), nullable=False, unique=True, default=uuid4, primary_key=True)
    # Sprint 34.1: FKs left nullable=True — association rows may be created
    # by partial ingestion paths that fill in linkage incrementally.
    wasp_uuid = Column(
        ForeignKey("libinv.wasps.uuid", onupdate="CASCADE", ondelete="CASCADE"),
        nullable=True,
    )
    actionable_package_version_id = Column(
        ForeignKey(
            "libinv.actionable_package_available_versions.uuid",
            onupdate="CASCADE",
            ondelete="CASCADE",
        ),
        nullable=True,
    )
    repository_id = Column(
        ForeignKey("libinv.repositories.id", onupdate="CASCADE", ondelete="CASCADE"),
        nullable=True,
    )
    environment = Column(String(20), nullable=False)
    # Sprint 34.1: server_default guarantees population — NOT NULL.
    created_at = Column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    # Sprint 37.2: lazy= audit.
    # - wasp: traversed in api/actionable/dashboards.py:86-88 (commit_id, jenkins_url,
    #   created_at). Eagerly loaded via selectinload in Actionable.get_actionable.
    #   Keep select.
    # - available_version: traversed in api/actionable/dashboards.py (extensively) and
    #   cli/actionable.py:214-221 via package.available_version.*. Pre-loaded via the
    #   selectinload chain in get_actionable. Keep select.
    # - repository: never traversed via row.repository in api/cli/scanners (queries
    #   already filter on repository_id; the Repository row is fetched separately
    #   via _common.fetch_repository).
    wasp = relationship("Wasp", back_populates="actionable_versions", lazy="select")
    available_version = relationship(
        "ActionablePackageAvailableVersion",
        back_populates="associated_repositories",
        primaryjoin="Repository_ActionablePackageAvailableVersion.actionable_package_version_id == ActionablePackageAvailableVersion.uuid",
        lazy="select",
    )
    repository = relationship(
        "Repository", back_populates="actionable_versions", lazy="raise_on_sql"
    )

    __table_args__ = (
        # Sprint 33.1/33.2: declare indexes already created by alembic 0002_fk_indexes
        Index(
            "ix_repo_actionable_pkg_versions_assoc_pkg_version_id",
            "actionable_package_version_id",
        ),
        Index(
            "ix_repo_actionable_pkg_versions_assoc_repository_id",
            "repository_id",
        ),
        Index(
            "ix_repo_actionable_pkg_versions_assoc_wasp_uuid",
            "wasp_uuid",
        ),
        # Composite index for hot query path.
        Index(
            "ix_repo_actionable_pkg_versions_repo_env",
            "repository_id",
            "environment",
        ),
        {"schema": "libinv"},
    )


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


def is_excluded_repo(repository_url):
    git_url_components = explode_git_url(repository_url)
    return f"{git_url_components['org']}/{git_url_components['name']}" in EXCLUDED_REPOS


def is_valid_raw_message(message):
    """
    Validate the Wasp message schema
    """
    schema = {
        "type": "object",
        "properties": {
            "repository": {
                "type": "object",
                "properties": {
                    "url": {"type": "string"},
                    "commit": {"type": "string"},
                    "tag": {"type": "string"},
                    "commit_author": {"type": "string"},
                },
                "required": ["url", "commit"],
            },
            "aws_environment": {"type": "string"},
            "job_url": {"type": "string"},
            "buildx_enabled": {"type": "string"},
            "type": {"type": "string"},
            "timestamp": {"type": "string"},
            "ecr_image": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string"},
                        "digest": {"type": "string"},
                        "type": {"type": "string"},
                        "platform": {
                            "type": "object",
                            "properties": {
                                "os": {"type": "string"},
                                "architecture": {"type": "string"},
                            },
                        },
                    },
                },
            },
        },
        "required": ["repository", "aws_environment", "job_url", "timestamp"],
    }
    try:
        validate(instance=message, schema=schema)
        return True
    except Exception as e:
        logger.error(f"Invalid wasp message: {e}")
        return False


def is_blacklist(package_name):
    blacklisted_substrings = []
    for substring in blacklisted_substrings:
        if substring in package_name:
            return True
    return False


class EPSS(Base):
    """
    EPSS (Exploit Prediction Scoring System) model to store CVE EPSS scores
    """

    __tablename__ = "epss"

    cve = Column(String(50), primary_key=True, nullable=False)
    epss_score = Column(Float(precision=6), nullable=False)
    epss_percentile = Column(Float(precision=6), nullable=False)
    # Sprint 34.2: epss_date promoted from String(20) to native DATE for
    # proper ordering / range queries. Migration 0003 ALTERs the column with
    # ``USING epss_date::date`` so existing 'YYYY-MM-DD' string rows convert
    # losslessly. Callers should pass either a ``datetime.date`` or an
    # ISO-8601 'YYYY-MM-DD' string — psycopg2 parses both.
    epss_date = Column(Date, nullable=True)
    # Sprint 34.1: server_default guarantees population — NOT NULL.
    updated_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    # Sprint 33.1/33.2: declare composite index already created by alembic 0002_fk_indexes
    __table_args__ = (
        Index("ix_epss_cve_updated_at", "cve", "updated_at"),
        {"schema": "libinv"},
    )

    def __str__(self):
        return f"{self.cve} - {self.epss_score}"

    @classmethod
    def get_fresh_cves(cls, session, cve_list, days=30):

        stale_threshold = datetime.now(timezone.utc) - timedelta(days=days)

        fresh_cves = set(
            r.cve
            for r in session.query(cls.cve)
            .filter(cls.cve.in_(cve_list))
            .filter(cls.updated_at > stale_threshold)
            .all()
        )
        return fresh_cves

    @classmethod
    def get_stale_or_missing_cves(cls, session, cve_list, days=30):
        fresh_cves = cls.get_fresh_cves(session, cve_list, days)
        return [cve for cve in cve_list if cve not in fresh_cves]

    @classmethod
    def refresh_cves(cls, session, cve_list, verbose=False, logger=None):
        valid_cves_upper = [c.upper() for c in cve_list]
        # Use model methods to determine which CVEs need updates
        to_fetch = cls.get_stale_or_missing_cves(session, valid_cves_upper)
        fresh_cves = cls.get_fresh_cves(session, valid_cves_upper)

        updated, skipped, failed = 0, 0, len(fresh_cves)

        if verbose and fresh_cves and logger:
            logger.warning(f"Skipping {len(fresh_cves)} fresh CVEs (updated within 30 days)")

        # Fetch from API if needed
        if to_fetch:
            if logger:
                logger.warning(f"Fetching {len(to_fetch)} CVEs from EPSS API...")

            batch_size = 100
            for i in range(0, len(to_fetch), batch_size):
                if i > 0:
                    # Polite rate-limit between batches against the public EPSS API.
                    time.sleep(0.5)
                batch = to_fetch[i : i + batch_size]
                cve_string = ",".join(batch)
                try:
                    response = requests.get(
                        f"https://api.first.org/data/v1/epss?cve={cve_string}", timeout=30
                    )
                    if response.status_code == 200:
                        api_data = response.json()
                        new_epss_data = {}
                        found_cves = set()
                        for item in api_data.get("data", []):
                            cve_id = item.get("cve", "").upper()
                            found_cves.add(cve_id)
                            new_epss_data[cve_id] = {
                                "epss_score": float(item.get("epss", 0)),
                                "epss_percentile": float(item.get("percentile", 0)),
                                "epss_date": item.get("date", ""),
                            }

                        for cve_nf in batch:
                            if cve_nf not in found_cves:
                                if logger:
                                    logger.warning(f"CVE {cve_nf} not found in EPSS API, skipping")
                                continue

                        cls.update_epss_scores(session, new_epss_data)
                        updated += len([cve for cve in batch if cve in found_cves])
                        failed += len([cve for cve in batch if cve not in found_cves])
                    else:
                        if logger:
                            logger.error(f"API error: {response.status_code} {response.text}")
                        failed += len(batch)
                except Exception as e:
                    if logger:
                        logger.error(f"Error fetching EPSS data: {e}")
                    failed += len(batch)

        return {"updated": updated, "skipped": skipped, "failed": failed}

    @classmethod
    def update_epss_scores(cls, session, epss_data_dict):
        """Bulk-upsert EPSS scores via INSERT ... ON CONFLICT DO UPDATE.

        One round trip per batch instead of one SELECT + one INSERT/UPDATE
        per CVE.
        """
        if not epss_data_dict:
            return

        now = datetime.now(timezone.utc)
        rows = [
            {
                "cve": cve_id,
                "epss_score": data["epss_score"],
                "epss_percentile": data["epss_percentile"],
                "epss_date": data["epss_date"],
                "updated_at": now,
            }
            for cve_id, data in epss_data_dict.items()
        ]
        stmt = pg_insert(cls).values(rows)
        stmt = stmt.on_conflict_do_update(
            index_elements=[cls.cve],
            set_={
                "epss_score": stmt.excluded.epss_score,
                "epss_percentile": stmt.excluded.epss_percentile,
                "epss_date": stmt.excluded.epss_date,
                "updated_at": stmt.excluded.updated_at,
            },
        )
        session.execute(stmt)
        session.commit()


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
