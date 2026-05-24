"""Shared fixtures and import-time stubs for the SupplyShield test suite.

This file MUST run before any `libinv.*` import so that:
1. `libinv.env` parses cleanly without a real database or full env.
2. The `libinv.scio_models` external module (which lives outside the repo in
   production) is stubbed out, mirroring `libinv/conftest.py`.
3. The `flask_app_client` fixture can spin up a minimal Flask app exercising
   `libinv.api.auth.register_global_auth` in isolation. The full
   `libinv.api.app` cannot be imported in this test environment because of
   pre-existing source bugs (see the docstring on `flask_app_client`).
"""

import json
import os
import sys
import types
from unittest.mock import MagicMock


def _is_valid_json(value):
    """Return True if `value` is a non-None string that parses as JSON."""
    if value is None:
        return False
    try:
        json.loads(value)
        return True
    except (ValueError, TypeError):
        return False

# ---------------------------------------------------------------------------
# Step 1 - Set env-var defaults BEFORE any libinv.* import.
# `libinv.env` calls `json.loads(os.getenv("JAVA_HOME", "{}"))` etc. at
# import time, so missing/empty values produce a JSONDecodeError. We also
# need DB_* values so the SQLAlchemy URL parses, even though we never
# actually connect.
#
# For env vars that libinv.env parses as JSON (JAVA_HOME, JOBS,
# BASE_IMAGE_JAVA_VERSION_MAPPING), we OVERRIDE any existing system value
# because the host's value (e.g. /opt/homebrew/.../JDK) is not valid JSON
# and would break the import. For other vars we use setdefault so an
# explicit caller-supplied value wins.
# ---------------------------------------------------------------------------
for _k in ("JAVA_HOME", "BASE_IMAGE_JAVA_VERSION_MAPPING", "JOBS"):
    if not _is_valid_json(os.environ.get(_k)):
        os.environ[_k] = "{}"

os.environ.setdefault("DB_HOSTNAME", "x")
os.environ.setdefault("DB_USERNAME", "x")
os.environ.setdefault("DB_PASSWORD", "x")
os.environ.setdefault("LIBINV_API_TOKEN", "test-token-for-tests")
os.environ.setdefault("SLACK_URL", "http://localhost:0/unused")

# ---------------------------------------------------------------------------
# Step 2 - Stub libinv.scio_models (lives in an external scio repo in prod).
# Mirrors the pattern in libinv/conftest.py, but adds DiscoveredPackage which
# libinv.cli.epss expects at import time.
#
# NOTE: libinv/conftest.py ALSO installs a stub for `libinv.scio_models` but
# only with VulnerablePath / ScanpipeProject. Depending on conftest load
# order, `libinv/conftest.py` may run AFTER us and replace the module — in
# that case `DiscoveredPackage` would be missing. We patch attributes onto
# whichever module is currently registered, and lazy-add missing attrs via
# `_ensure_scio_stub()` to be re-entrant.
# ---------------------------------------------------------------------------
def _ensure_scio_stub():
    mod = sys.modules.get("libinv.scio_models")
    if mod is None:
        mod = types.ModuleType("scio_models")
        sys.modules["libinv.scio_models"] = mod
    for attr in ("VulnerablePath", "ScanpipeProject", "DiscoveredPackage"):
        if not hasattr(mod, attr):
            setattr(mod, attr, MagicMock())
    return mod


_ensure_scio_stub()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
import pytest  # noqa: E402  - intentionally late so env is set first
from flask import Flask  # noqa: E402


# ---------------------------------------------------------------------------
# pytest-postgresql factories (Sprint 30.1)
# ---------------------------------------------------------------------------
# These factories spin an ephemeral Postgres on-demand. They are wired here at
# the top-level conftest so any test (unit OR integration) can request the
# ``postgresql`` fixture and get a clean per-test DB. Integration tests still
# honor an explicit ``TEST_DATABASE_URL`` (see ``tests/integration/conftest.py``);
# when unset, they will fall back to the pytest-postgresql ephemeral DSN.
#
# ``postgresql_proc`` selects an ephemeral port (port=None) and uses /tmp as the
# unix-socket directory to avoid clashes with system services. The ``postgresql``
# factory hangs off that proc and gives each test a fresh psycopg2 connection.
#
# Import is wrapped in a try/except so the unit-test run stays green even when
# pytest-postgresql isn't installed yet (e.g. during the requirements bump
# rollout). When the import fails, the factories simply aren't registered —
# integration tests still work via the explicit TEST_DATABASE_URL path.
try:
    from pytest_postgresql import factories  # noqa: E402

    postgresql_proc = factories.postgresql_proc(port=None, unixsocketdir="/tmp")
    postgresql = factories.postgresql("postgresql_proc")
except ImportError:  # pragma: no cover - exercised when dev dep not installed
    pass


@pytest.fixture
def test_db_url(request):
    """Yield a Postgres DSN for the duration of a test.

    Resolution order:
      1. ``TEST_DATABASE_URL`` env var (explicit operator override).
      2. ``postgresql`` pytest-postgresql fixture (ephemeral DB).

    Tests / integration fixtures should depend on ``test_db_url`` when they
    need a Postgres connection string and want to work in both CI (ephemeral)
    and local-with-operator-DB modes.
    """
    explicit = os.environ.get("TEST_DATABASE_URL")
    if explicit:
        yield explicit
        return

    # Lazy-request the pytest-postgresql fixture so tests that don't need a DB
    # don't pay the spin-up cost.
    pg = request.getfixturevalue("postgresql")
    # pg is a psycopg2 connection; build a SQLAlchemy-compatible URL from it.
    info = pg.info
    user = info.user
    password = info.password or ""
    host = info.host or "localhost"
    port = info.port
    dbname = info.dbname
    auth = f"{user}:{password}@" if password else f"{user}@"
    yield f"postgresql://{auth}{host}:{port}/{dbname}"


@pytest.fixture
def flask_app_client():
    """Yield a Flask test client wired with `register_global_auth`.

    NOTE: We do NOT import `libinv.api.app` because doing so currently fails
    with two pre-existing source bugs (sprint-2 refactor leftovers):
      - `libinv/api/actionable/__init__.py` imports submodules
        (`package_details`, `repositories`, `statistics`, `package_scan`)
        that do not exist in the repo.
      - `libinv/api/compare_builds.py` imports `fetch_repository` from
        `libinv.api.actionable`, but it actually lives in
        `libinv.api.actionable._common`.

    These are flagged in the test report but NOT fixed in this task per
    instructions (no edits under libinv/). Once they are resolved, this
    fixture can be switched to `from libinv.api.app import app`.

    Until then, we register the auth hook against a minimal Flask app plus
    a stub route that mirrors the real PUT /libinv/sast/update endpoint
    just enough to verify auth allows it through.
    """
    from libinv.api.auth import register_global_auth

    app = Flask(__name__)
    register_global_auth(app)

    @app.route("/libinv/sast/update", methods=["PUT"])
    def _stub_update_sast_result():  # pragma: no cover - exercised via client
        # Mimic the real handler enough that auth-allowed calls produce a
        # deterministic 400 (because the body is missing `sec_id`) rather
        # than a 200. That lets tests assert "auth let me through" by
        # checking the status code is NOT 401/503.
        from flask import jsonify
        from flask import request

        data = request.get_json(silent=True) or {}
        if "sec_id" not in data:
            return jsonify({"error": "sec_id key missing"}), 400
        return jsonify({"error": None}), 200

    @app.route("/libinv/sast/<sid>")
    def _stub_sast_data(sid):  # pragma: no cover
        return f"ok-{sid}", 200

    @app.route("/")
    def _stub_index():  # pragma: no cover
        return "Hello, World!", 200

    with app.test_client() as client:
        yield client


@pytest.fixture
def reset_daemon_shutdown_flag():
    """Save/restore libinv.cli.daemon._shutdown_requested around a test.

    Yields the daemon MODULE (not the click Command of the same name).
    NOTE: `libinv.cli.__init__` does `from libinv.cli.daemon import daemon`,
    which shadows the submodule attribute with the click Command. We work
    around this by reading the module via sys.modules after import.
    """
    # Defensive: libinv/conftest.py may have replaced our scio_models stub
    # in between collections, losing DiscoveredPackage. Restore before the
    # daemon import chain runs.
    _ensure_scio_stub()

    import libinv.cli.daemon  # noqa: F401 - ensures module is registered

    daemon_module = sys.modules["libinv.cli.daemon"]
    original = daemon_module._shutdown_requested
    yield daemon_module
    daemon_module._shutdown_requested = original
