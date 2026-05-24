from flask import Flask
from flask import jsonify
from flask import redirect
from flask import render_template
from flask import request
from flask import send_from_directory
from sqlalchemy import text

from libinv.api.actionable import actionable
from libinv.api.auth import register_global_auth
from libinv.api.compare_builds import compare_builds
from libinv.api.graph import blastradius
from libinv.api.health import health
from libinv.api.metrics import register_metrics
from libinv.api.onboard_package import onboard_package
from libinv.api.request_id import register_request_id
from libinv.api.wasp import wasp
from libinv.base import ScopedSession
from libinv.env import API_DOCS_FOLDER
from libinv.logger import install_json_formatter_if_configured
from libinv.models import SastResult
from libinv.scanners.repository_scanner.sast.enums.ValidEnum import ValidEnum

app = Flask(__name__, static_folder="static", template_folder="templates")

app.register_blueprint(actionable, url_prefix="/actionable")
app.register_blueprint(blastradius, url_prefix="/blastradius")
app.register_blueprint(onboard_package, url_prefix="/onboard")
app.register_blueprint(wasp, url_prefix="/wasp")
app.register_blueprint(compare_builds, url_prefix="/compare")
app.register_blueprint(health)

register_global_auth(app)
register_metrics(app)
install_json_formatter_if_configured()
register_request_id(app)


@app.before_request
def _set_statement_timeout():
    # Sprint 35.2 — apply a 30s statement_timeout to every request's session
    # so a single slow query cannot pin a worker thread indefinitely. Using
    # SET LOCAL scopes the timeout to the current transaction; on Postgres a
    # bare query auto-opens a transaction, so this binds to the work that
    # follows in the same request. The previous per-route SET inside
    # `statistics_dashboard` is now redundant and was removed.
    try:
        ScopedSession().execute(text("SET LOCAL statement_timeout = '30s'"))
    except Exception:
        # Never let timeout setup fail a request; if the database is
        # unreachable the downstream query will surface that error.
        ScopedSession.remove()


@app.teardown_request
def _remove_thread_local_session(exc):
    # Dispose the current thread's session at end of every request so the
    # next request on the same thread starts with a fresh identity map and
    # transactional state. Without this, the long-lived module-level `conn`
    # accumulates state across requests under gunicorn threads.
    ScopedSession.remove()


@app.route("/")
def index():
    return "Hello, World!"


@app.route("/docs/")
@app.route("/docs/<path:path>")
def docs(path="index.html"):
    return send_from_directory(API_DOCS_FOLDER, path)


@app.route("/libinv/sast/<sid>")
def sast_data(sid):
    session = ScopedSession()
    result = session.query(SastResult).filter_by(id=sid).first()
    if not result:
        return "Not Found", 404

    return render_template("validate_report.html", result=result)


@app.route("/libinv/sast/update", methods=["PUT"])
def update_sast_result():
    data = request.json
    update_data = None
    sec_id = None
    status_messages = {
        "FALSEPOSITIVE": ValidEnum.FALSEPOSITIVE,
        "Duplicate": ValidEnum.DUPLICATE,
        "VALIDATED": ValidEnum.VALIDATED,
    }

    if "sec_id" in data:
        sec_id = data["sec_id"]
    else:
        return jsonify({"error": "sec_id key missing"}), 400

    session = ScopedSession()
    result = session.query(SastResult).filter_by(id=sec_id).first()
    if not result:
        return jsonify({"error": "SEC ID not found"}), 404

    if "data" in data:
        update_data = data["data"]
    else:
        return jsonify({"error": "data key missing"}), 400

    if "validated" in data:
        result.validated = status_messages[data["validated"]].value
    else:
        return jsonify({"error": "validated key missing / incorrect"}), 400

    if data["validated"] == "FALSEPOSITIVE":
        result.description = update_data
    else:
        result.secbugurl = update_data  # we will be given sec bug id

    session.commit()
    return jsonify({"error": None}), 200


@app.errorhandler(404)
def page_not_found(e):
    # Note that we set the 404 status explicitly
    return "Not Found", 404


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
