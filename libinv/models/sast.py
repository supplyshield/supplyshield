"""Sprint 41.4: SAST-domain ORM extraction from ``libinv.models._legacy``.

This module owns the ``SastLobMetaData`` (per-LOB module/sub-module
metadata) and ``SastResult`` (a single Semgrep finding) ORM classes.
Together they back the SAST scanner's persistence layer
(``libinv/scanners/repository_scanner/sast/SarifResult.py``).

Contract: every name historically importable as ``from libinv.models
import SastLobMetaData`` / ``SastResult`` continues to work via the
package ``__init__`` re-exports. ``_legacy.py`` back-imports both
classes at the file bottom so existing
``from libinv.models._legacy import SastResult`` callers continue to
resolve.
"""

from __future__ import annotations

from sqlalchemy import JSON
from sqlalchemy import Boolean
from sqlalchemy import Column
from sqlalchemy import DateTime
from sqlalchemy import ForeignKey
from sqlalchemy import Index
from sqlalchemy import Integer
from sqlalchemy import String
from sqlalchemy import Text
from sqlalchemy.ext.mutable import MutableDict
from sqlalchemy.orm import relationship

from libinv.base import Base
from libinv.models._base import TimestampMixin


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
