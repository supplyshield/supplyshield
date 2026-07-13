import json

from flask import Flask
from flask import jsonify
from flask import redirect
from flask import render_template
from flask import request
from flask import send_from_directory
from sqlalchemy import distinct

from libinv.api.actionable import actionable
from libinv.api.compare_builds import compare_builds
from libinv.api.deps import deps
from libinv.api.graph import blastradius
from libinv.api.package import package
from libinv.api.wasp import wasp
from libinv.base import conn
from libinv.env import API_DOCS_FOLDER, PRIORITY_SQS_QUEUE_NAME, PRIORITY_QUEUE_MESSAGE_TEMPLATE
from libinv.models import SastResult, Wasp
from libinv.scanners.repository_scanner.sast.enums.ValidEnum import ValidEnum
from libinv.sqs import send_message, get_queue_url

app = Flask(__name__, static_folder="static", template_folder="templates")

app.register_blueprint(actionable, url_prefix="/actionable")
app.register_blueprint(blastradius, url_prefix="/blastradius")
app.register_blueprint(package, url_prefix="/actionable")
app.register_blueprint(deps, url_prefix="/deps")
app.register_blueprint(wasp, url_prefix="/wasp")
app.register_blueprint(compare_builds, url_prefix="/compare")


@app.route("/")
def index():
    return redirect("/actionable/v3/repositories")


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


@app.route("/actionable/v3/scan", methods=["GET"])
def priority_scan_form():
    # Query all distinct environments from Wasp table
    environments_query = (
        conn.query(distinct(Wasp.environment))
        .filter(Wasp.environment.isnot(None))
        .order_by(Wasp.environment)
        .all()
    )
    # Extract strings from tuples [(env1,), (env2,)] -> [env1, env2]
    environments = [env[0] for env in environments_query if env[0]]

    # Ensure 'prod' is in the list as default
    if not environments:
        environments = ['prod']
    elif 'prod' not in environments:
        environments.insert(0, 'prod')

    return render_template("sca_scan_form.html", environments=environments)


@app.route("/actionable/v3/scan", methods=["POST"])
def priority_scan():
    repo = request.form.get("repo")
    commit = request.form.get("commit")
    environment = request.form.get("environment")

    # Query environments for validation
    environments_query = (
        conn.query(distinct(Wasp.environment))
        .filter(Wasp.environment.isnot(None))
        .order_by(Wasp.environment)
        .all()
    )
    environments = [env[0] for env in environments_query if env[0]]
    if not environments:
        environments = ['prod']

    # Validation
    if not repo or not commit or not environment:
        return jsonify({"error": "repo, commit, and environment parameters are required"}), 400

    # Validate environment exists in database
    if environment not in environments:
        return jsonify({"error": f"Invalid environment: {environment}"}), 400

    if not PRIORITY_QUEUE_MESSAGE_TEMPLATE:
        return jsonify({"error": "Priority scan queue is not configured"}), 500

    try:
        message = json.loads(PRIORITY_QUEUE_MESSAGE_TEMPLATE)
        message["repository"]["url"] = f"git@github.com:{repo}.git"
        message["repository"]["commit"] = commit
        message["repository"]["tag"] = commit[:10]
        message["aws_environment"] = environment

        queue_url = get_queue_url(PRIORITY_SQS_QUEUE_NAME)
        send_message(queue_url, json.dumps(message))

        return jsonify({"error": None, "message": "Scan request queued successfully!"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.errorhandler(404)
def page_not_found(e):
    # Note that we set the 404 status explicitly
    return "Not Found", 404


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
