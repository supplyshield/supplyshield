from sqlalchemy import Table
from sqlalchemy import inspect
from sqlalchemy.exc import SQLAlchemyError

from libinv.base import Base
from libinv.base import engine
from libinv.base import metadata


def _load_scanpipe_table(table_name: str):
    """
    Attempt to reflect a ScanCode table. Returns a Table or None if it does not exist yet.
    """
    inspector = inspect(engine)
    try:
        if inspector.has_table(table_name, schema="public"):
            return Table(table_name, metadata, schema="public", autoload_with=engine)
    except SQLAlchemyError:
        return None
    return None


_scanpipe_project_table = _load_scanpipe_table("scanpipe_project")
if _scanpipe_project_table is not None:
    class ScanpipeProject(Base):
        __table__ = _scanpipe_project_table
else:
    ScanpipeProject = None


_discovered_package_table = _load_scanpipe_table("scanpipe_discoveredpackage")
if _discovered_package_table is not None:
    class DiscoveredPackage(Base):
        __table__ = _discovered_package_table
else:
    DiscoveredPackage = None
