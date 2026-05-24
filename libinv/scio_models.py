from sqlalchemy import Table
from sqlalchemy import inspect
from sqlalchemy.exc import SQLAlchemyError

from libinv.base import Base
from libinv.base import engine
from libinv.base import metadata
from libinv.env import LIBINV_SCIO_USE_HTTP


class _ScioModelStub:
    """Raise-on-access stub used when LIBINV_SCIO_USE_HTTP is enabled.

    The reflection path in this module touches the live SCIO Postgres at
    import time (``inspect(engine).has_table(...)``). When the HTTP client
    is the source of truth for SCIO data, that import-time round-trip is
    both unnecessary and a source of subtle drift (callers that still
    reach for ``scio_models.ScanpipeProject`` would silently bypass the
    HTTP path). The stub turns any such access into a loud
    ``RuntimeError`` so the offending caller surfaces immediately.
    """

    def __init__(self, name: str) -> None:
        self._name = name

    def _raise(self) -> "None":
        raise RuntimeError(
            f"libinv.scio_models.{self._name} is disabled when "
            "LIBINV_SCIO_USE_HTTP is true; use "
            "libinv.services.scancodeio.get_default_client() instead."
        )

    def __getattr__(self, item: str):  # type: ignore[no-untyped-def]
        self._raise()

    def __call__(self, *args, **kwargs):  # type: ignore[no-untyped-def]
        self._raise()

    def __bool__(self) -> bool:
        # ``if scio_models.ScanpipeProject is not None`` style guards in
        # the codebase predate the stub. Keep falsy so those branches
        # transparently route to the HTTP fallback path.
        return False


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


if LIBINV_SCIO_USE_HTTP:
    # HTTP mode: do NOT touch the DB at import time. Replace the model
    # symbols with raise-on-access stubs so any leftover SQL caller
    # surfaces with a clear RuntimeError instead of crashing later
    # inside SQLAlchemy.
    ScanpipeProject = _ScioModelStub("ScanpipeProject")  # type: ignore[assignment]
    DiscoveredPackage = _ScioModelStub("DiscoveredPackage")  # type: ignore[assignment]
else:
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
