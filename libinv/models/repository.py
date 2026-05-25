"""Sprint 41.3: Repository / Account / DeploymentCheckpoint extraction.

Owns three top-of-domain ORM classes that historically lived at the
top of ``libinv/models/_legacy.py``:

- ``Repository`` — the canonical (provider, org, name) git repo row,
  referenced by FK from Wasp / Image / Secbug / SAST / Actionable.
- ``Account`` — the AWS account row used by Image scanning.
- ``DeploymentCheckpoint`` — global ``checkpoint`` toggle that drives
  ``LatestImage.calibrate``.

They live in a single file rather than three (per the Sprint 41.3
task option) because Repository has comparatively few helpers and
the three classes are linked at the deployment-tracking layer:
``DeploymentCheckpoint.set`` calls ``LatestImage.calibrate`` which
walks ``Account`` + ``Image`` + ``Repository`` graphs.

Re-exports + back-imports follow the Sprint 39/40 pattern.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import Boolean
from sqlalchemy import Column
from sqlalchemy import Integer
from sqlalchemy import String
from sqlalchemy import and_
from sqlalchemy.orm import Mapped
from sqlalchemy.orm import Session as OrmSession
from sqlalchemy.orm import mapped_column
from sqlalchemy.orm import relationship
from sqlalchemy.schema import UniqueConstraint

from libinv.base import Base
from libinv.helpers import explode_git_url
from libinv.models._base import TimestampMixin
from libinv.vcs import BitBucketApp
from libinv.vcs import GitHubApp

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)


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
        "RepositoryActionablePackageAvailableVersion",
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
        cls, git_url: str, session: OrmSession
    ) -> "Repository | None":
        # Sprint 48.1: session required (no more conn fallback).
        try:
            repo_url = Repository.from_url(git_url)
            repo = (
                session.query(Repository)
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
        self, environment: str = "stage", *, session: OrmSession
    ) -> None:
        # Sprint 41.3: lazy import to avoid circular dep between
        # ``libinv.models.repository`` and ``libinv.models.actionable``.
        # Sprint 48.1: session required keyword-only (no more conn fallback).
        from libinv.models.actionable import Actionable

        actionables = Actionable.get_actionable_and_secure_versions(
            session, self.id, environment
        )
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
        *,
        session: OrmSession,
    ) -> None:
        """
        Create Account if it does not exist, nop otherwise

        Sprint 48.1: ``session`` is required keyword-only (no more conn fallback).
        """
        if not session.query(cls).filter(cls.id == account_id).one_or_none():
            if not name:
                raise ValueError(
                    f"Account id: {account_id} does not exist. Cannot create new account without a name"
                )
            new_account = cls(id=account_id, name=name, type=account_type)
            session.add(new_account)
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
        # Sprint 41.3: lazy import — ``get_or_create`` lives in ``_legacy``;
        # ``LatestImage`` lives in ``libinv.models.image``. Both are safe
        # to import inside the method since ``_legacy`` finishes loading
        # before ``DeploymentCheckpoint.set`` is ever called at runtime.
        from libinv.models._legacy import get_or_create
        from libinv.models.image import LatestImage

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
