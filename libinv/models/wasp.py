"""Sprint 41.1: Wasp-domain ORM extraction from ``libinv.models._legacy``.

This module owns the ``Wasp`` ORM class (which models a Caterpillar SQS
message that has been received + linked to a Repository) along with the
two helpers used *only* by the Wasp ingestion path:

- ``is_excluded_repo`` — short-circuit for repos in ``EXCLUDED_REPOS``.
- ``is_valid_raw_message`` — jsonschema validation of the wire format.

Shared helpers (``is_blacklist`` — used by ``Actionable.populate``;
``get_or_create`` — used by half the codebase) remain in
``libinv.models._legacy`` for now and are imported here.

Contract: every name historically importable as ``from libinv.models
import X`` continues to work via the package ``__init__`` re-exports.
``_legacy.py`` back-imports ``Wasp`` / ``is_excluded_repo`` /
``is_valid_raw_message`` at the file bottom so existing
``from libinv.models._legacy import Wasp`` callers and the test
patches that target ``libinv.models._legacy.is_excluded_repo`` keep
resolving.
"""

from __future__ import annotations

import json
import logging
import shutil
import traceback
from pathlib import Path
from uuid import uuid4

from git.exc import GitCommandError
from jsonschema import SchemaError
from jsonschema import ValidationError
from jsonschema import validate
from sqlalchemy import Boolean
from sqlalchemy import Column
from sqlalchemy import ForeignKey
from sqlalchemy import Index
from sqlalchemy import Integer
from sqlalchemy import String
from sqlalchemy import Text
from sqlalchemy.exc import PendingRollbackError
from sqlalchemy.orm import Session as OrmSession
from sqlalchemy.orm import relationship

from libinv.base import Base
from libinv.env import EXCLUDED_REPOS
from libinv.env import LIBINV_TEMP_DIR
from libinv.exceptions import MalformedCaterpillarMessage
from libinv.helpers import explode_git_url
from libinv.models._base import TimestampMixin

logger = logging.getLogger(__name__)


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
    except (ValidationError, SchemaError) as e:
        # Sprint 47.2: narrowed from `except Exception`. ``validate``
        # raises ``ValidationError`` for instance/schema mismatch and
        # ``SchemaError`` for malformed schemas — there are no other
        # documented failure paths.
        logger.error(f"Invalid wasp message: {e}")
        return False


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
    #   RepositoryActionablePackageAvailableVersion.wasp is used instead).
    images = relationship("Image", back_populates="wasp", lazy="raise_on_sql")
    repository = relationship("Repository", lazy="select")
    actionable = relationship(
        "RepositoryActionablePackageAvailableVersion",
        back_populates="wasp",
        overlaps="actionable_versions",
        lazy="raise_on_sql",
    )
    actionable_versions = relationship(
        "RepositoryActionablePackageAvailableVersion",
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

        # Sprint 48.1: ``_session`` must have been set by
        # ``eat_caterpillar_message`` (which is the only public entry that
        # builds + persists a Wasp). If it's missing the caller skipped the
        # constructor — surface that explicitly rather than silently falling
        # back to the deprecated ``conn`` global.
        s = getattr(self, "_session", None)
        if s is None:
            raise RuntimeError(
                "Wasp.__exit__ called without an attached session; "
                "use Wasp.eat_caterpillar_message() to construct Wasp instances."
            )
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
        cls, message: dict, *, session: OrmSession
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
        # Sprint 41.1: import Repository + get_or_create lazily from
        # ``_legacy`` to avoid an import-time cycle (this module is
        # imported by ``libinv.models`` which still loads ``_legacy``).
        from libinv.models._legacy import Repository
        from libinv.models._legacy import get_or_create

        # Sprint 48.1: ``session`` is required keyword-only (no more conn fallback).
        s = session

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
        # Sprint 48.1: ``_session`` must have been set by
        # ``eat_caterpillar_message``; surface a clear error rather than
        # silently falling back to the deprecated ``conn`` global.
        s = getattr(self, "_session", None)
        if s is None:
            raise RuntimeError(
                "Wasp.throw called without an attached session; "
                "use Wasp.eat_caterpillar_message() to construct Wasp instances."
            )
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
        except Exception as e:  # noqa: BLE001
            # Sprint 47.2: narrowing deferred — multi-source error path
            # (gitpython internals can surface OSError, ValueError,
            # InvalidGitRepositoryError, NoSuchPathError as well as
            # filesystem failures from ``Path.mkdir``). Kept broad as a
            # last-resort guard that still re-raises after recording the
            # failure on the wasp row; reviewer to triage if a tighter
            # union is appropriate.
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
