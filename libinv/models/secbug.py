"""Sprint 41.4: Secbug-domain ORM extraction from ``libinv.models._legacy``.

This module owns the ``Secbug`` ORM class — a security-bug row pulled
from an external tracker (Jira), optionally linked to a ``Repository``.
Soft-delete is encoded via the ``deleted_at`` timestamp; queries should
prefer ``Secbug.all_active(...)`` over ``session.query(Secbug)``.

Contract: every name historically importable as ``from libinv.models
import Secbug`` continues to work via the package ``__init__``
re-exports. ``_legacy.py`` back-imports ``Secbug`` at the file bottom so
existing ``from libinv.models._legacy import Secbug`` callers continue
to resolve.
"""

from __future__ import annotations

from datetime import datetime
from datetime import timezone

from sqlalchemy import Boolean
from sqlalchemy import Column
from sqlalchemy import DateTime
from sqlalchemy import ForeignKey
from sqlalchemy import Index
from sqlalchemy import String
from sqlalchemy.orm import Session as OrmSession
from sqlalchemy.orm import relationship
from sqlalchemy.orm import synonym

from libinv.base import Base
from libinv.models._base import TimestampMixin

# Re-use the canonical constant from ``_legacy``. The constant lives
# there pending a future ``_constants`` extraction; importing it from a
# single source avoids drift.
from libinv.models._legacy import MAX_LENGTH_VULNERABILITY_DESCRIPTION


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
    is_risk: Column = Column(Boolean(), nullable=True)
    pulled_at = Column(DateTime(timezone=True), nullable=False)
    deleted_at = Column(DateTime(timezone=True), nullable=True)
    # Sprint 34.1: repository_id nullable=True — secbugs may exist before
    # a repository is associated (e.g. cross-cutting org-level bugs).
    repository_id: Column = Column(
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
    def get(cls, id: str, session: OrmSession) -> "Secbug | None":
        # Sprint 48.1: session required (no more conn fallback).
        return cls.all_active(session=session).filter(cls.id == id).first()

    @classmethod
    def get_any(cls, id: str, session: OrmSession) -> "Secbug | None":
        """Return secbug with given id, even if deleted"""
        # Sprint 48.1: session required (no more conn fallback).
        return session.query(cls).filter(cls.id == id).first()

    @classmethod
    def all_active(cls, session: OrmSession):
        # Sprint 48.1: session required (no more conn fallback).
        return session.query(cls).filter(cls.deleted_at == None)  # noqa: E711
