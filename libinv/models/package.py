"""Sprint 40.1: Package-domain ORM classes.

Extracted from ``libinv/models/_legacy.py`` following the Sprint 39.2
pattern that pulled the Image-domain classes out into
``libinv/models/image.py``. Holds three classes describing the package
inventory layer of the ORM:

  * ``Package``                      — one (name, version, language)
                                        identified by a canonical purl,
                                        linked to images, licenses and
                                        vulnerabilities via association
                                        tables.
  * ``PackageLicenseAssociation``    — M:N edge between Package and
                                        License, with no extra payload.
  * ``License``                      — license_family rows, keyed by a
                                        unique normalized name.

Per-relationship ``lazy=`` annotations were set under Sprint 37.2 and
are preserved verbatim — see the inline comments on each
``relationship(...)`` call for the audit trail.

The package's previous home (`_legacy.py`) re-imports these names at the
bottom of the file so any historical
``from libinv.models._legacy import Package`` callers (and any internal
helpers that referenced these names as module globals) keep working
while the extraction is incremental.
"""

from __future__ import annotations

from sqlalchemy import Column
from sqlalchemy import DateTime
from sqlalchemy import ForeignKey
from sqlalchemy import Index
from sqlalchemy import Integer
from sqlalchemy import String
from sqlalchemy import func
from sqlalchemy.orm import relationship

from libinv.base import Base

# ``MAX_LENGTH_LICENSE`` remains canonically defined in ``_legacy`` so
# the single-source-of-truth contract holds while the rest of the file
# is still being split. Once the final extraction sprint retires
# ``_legacy``, this constant will move to a shared
# ``libinv.models._constants`` (TBD).
from libinv.models._legacy import MAX_LENGTH_LICENSE


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
