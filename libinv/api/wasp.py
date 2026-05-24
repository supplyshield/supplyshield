from flask import Blueprint
from flask import jsonify
from flask import request

from libinv.base import ScopedSession
from libinv.models import Wasp

wasp = Blueprint("wasp", __name__, template_folder="templates")


@wasp.route("/", methods=["GET"])
def wasp_main():
    return "wasp service"


@wasp.route("/get_wasp_by_id", methods=["GET"])
def get_wasp_by_id():
    wasp_id = request.args.get("id")
    if not wasp_id:
        return jsonify({"error": "id parameter missing"}), 400

    uuid = wasp_id.split("/")[0]
    session = ScopedSession()
    result = session.query(Wasp).filter_by(uuid=uuid).first()
    if result:
        return (
            jsonify({"repository_id": result.repository_id, "environment": result.environment}),
            200,
        )
    return jsonify({"error": "Wasp not found"}), 404
