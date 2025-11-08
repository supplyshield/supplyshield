from sqlalchemy import Table

from libinv.base import Base
from libinv.base import engine
from libinv.base import metadata


class VulnerablePath(Base):
    __table__ = Table("scanpipe_vulnerablepaths", metadata, schema="public", autoload_with=engine)


class ScanpipeProject(Base):
    __table__ = Table("scanpipe_project", metadata, schema="public", autoload_with=engine)


class DiscoveredPackage(Base):
    __table__ = Table("scanpipe_discoveredpackage", metadata, schema="public", autoload_with=engine)
