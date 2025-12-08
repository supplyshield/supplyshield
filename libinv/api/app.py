from flask import Flask
from flask import jsonify
from flask import redirect
from flask import render_template
from flask import request
from flask import send_from_directory

from libinv.api.actionable import actionable
from libinv.api.compare_builds import compare_builds
from libinv.api.graph import blastradius
from libinv.api.wasp import wasp
from libinv.base import conn
from libinv.env import API_DOCS_FOLDER
from libinv.models import SastResult
from libinv.scanners.repository_scanner.sast.enums.ValidEnum import ValidEnum

app = Flask(__name__, static_folder="static", template_folder="templates")

app.register_blueprint(actionable, url_prefix="/actionable")
app.register_blueprint(blastradius, url_prefix="/blastradius")
app.register_blueprint(wasp, url_prefix="/wasp")
app.register_blueprint(compare_builds, url_prefix="/compare")


@app.route("/")
def index():
    return "Hello, World!"


@app.route("/docs/")
@app.route("/docs/<path:path>")
def docs(path="index.html"):
    return send_from_directory(API_DOCS_FOLDER, path)


@app.route("/libinv/sast/<sid>")
def sast_data(sid):
    result = conn.query(SastResult).filter_by(id=sid).first()
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
        return jsonify({"error", "sec_id key missing"}), 200

    result = conn.query(SastResult).filter_by(id=sec_id).first()
    if not result:
        return jsonify({"error": "SEC ID not found"}), 200

    if "data" in data:
        update_data = data["data"]
    else:
        return jsonify({"error": "data key missing"}), 200

    if "validated" in data:
        result.validated = status_messages[data["validated"]].value
    else:
        return jsonify({"error": "validated key missing / incorrect"}), 200

    if data["validated"] == "FALSEPOSITIVE":
        result.description = update_data
    else:
        result.secbugurl = update_data  # we will be given sec bug id

    conn.commit()
    return jsonify({"error": None}), 200


@app.errorhandler(404)
def page_not_found(e):
    # Note that we set the 404 status explicitly
    return "Not Found", 404


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
