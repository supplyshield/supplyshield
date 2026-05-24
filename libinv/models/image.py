"""Sprint 39.2: Image-domain ORM classes.

Extracted from the legacy single-file ``libinv/models.py`` (now
``libinv/models/_legacy.py``). Holds the four classes that describe
container-image inventory:

  * ``Image``                    — one image build, linked to an account,
                                    optional repository, optional wasp,
                                    and parent/base image relationships
                                    used by ``get_base_image_of``.
  * ``ImagePackageAssociation``  — M:N edge between Image and Package
                                    carrying a JSON metadata blob.
  * ``Layer``                    — image filesystem layers, used by
                                    base-image detection.
  * ``LatestImage``              — materialized "latest per (name,
                                    account, platform) <= checkpoint"
                                    table, repopulated by
                                    ``LatestImage.calibrate``.

The legacy module retains the runtime *bindings* (``Image``, etc.) by
re-importing from this file via ``libinv.models.__init__``; per-domain
new code should ``from libinv.models.image import …`` directly.
"""

from __future__ import annotations

from sqlalchemy import CHAR
from sqlalchemy import Column
from sqlalchemy import ForeignKey
from sqlalchemy import Index
from sqlalchemy import Integer
from sqlalchemy import String
from sqlalchemy import Text
from sqlalchemy import delete
from sqlalchemy import text
from sqlalchemy.orm import relationship

from libinv.base import Base
from libinv.models._base import TimestampMixin

# ``ORGSRE_ACCOUNT_ID`` remains canonically defined in ``_legacy`` so
# the single-source-of-truth contract holds while the rest of the file
# is still being split. Once Sprint 41.5 retires ``_legacy``, this
# constant will move to a shared ``libinv.models._constants`` (TBD).
from libinv.models._legacy import ORGSRE_ACCOUNT_ID


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
