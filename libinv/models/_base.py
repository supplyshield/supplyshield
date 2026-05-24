"""Sprint 39.1: shared declarative mixins for libinv ORM models.

``Base`` itself lives in :mod:`libinv.base` (built via
``declarative_base(cls=LibinvBase)``) and is re-exported from
:mod:`libinv.models` for backwards compatibility. This module holds only
mixin classes that the per-domain modules (image.py, package.py, …) need
to attach to their ORM classes.
"""

from __future__ import annotations

from sqlalchemy import Column
from sqlalchemy import DateTime
from sqlalchemy import func
from sqlalchemy.orm import declarative_mixin


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
