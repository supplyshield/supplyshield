from flask import Blueprint

# Drop `template_folder="templates"` — Flask app's global template_folder
# covers it; the relative path would otherwise resolve to a non-existent
# libinv/api/actionable/templates/ directory.
actionable = Blueprint("actionable", __name__)

# Re-export shared helpers so external callers (e.g. libinv.api.compare_builds)
# can keep importing them from `libinv.api.actionable` exactly as they did
# before the split.
from libinv.api.actionable._common import fetch_repository  # noqa: F401, E402

# Importing the view modules triggers their @actionable.route(...) decorators,
# which register the routes against the blueprint above.
from libinv.api.actionable import dashboards  # noqa: F401, E402
from libinv.api.actionable import package_details  # noqa: F401, E402
from libinv.api.actionable import repositories  # noqa: F401, E402
from libinv.api.actionable import statistics  # noqa: F401, E402
from libinv.api.actionable import package_scan  # noqa: F401, E402
