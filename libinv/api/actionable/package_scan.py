from flask import jsonify
from flask import redirect
from flask import render_template
from flask import request
from flask import url_for
from univers.versions import MavenVersion

from libinv.base import Session
from libinv.models import Actionable
from libinv.models import ActionablePackageAvailableVersion

from libinv.api.actionable import actionable


@actionable.route("/v3/package_scan", methods=["GET"])
def safe_upgrades():
    actionable_id = request.args.get("actionable_id")
    version_in_use = request.args.get("version_in_use")
    repository_id = request.args.get("repository_id")
    env = request.args.get("env", "prod")

    if not actionable_id or not version_in_use:
        return jsonify({"error": "actionable_id or version_in_use parameter missing"}), 400

    results = []
    with Session() as session:
        available_versions = (
            session.query(ActionablePackageAvailableVersion)
            .filter_by(actionable_id=actionable_id)
            .all()
        )
        for version in available_versions:
            results.append(
                {
                    "version": version.version,
                    "scan_status": version.scan_status,
                    "vulnerabilities": version.vulns_count,
                    "epss_score": version.epss_score,
                    "vulnerability_severities": version.vulnerability_severities,
                    "is_latest": version.is_latest,
                    "updated_at": version.updated_at,
                }
            )
        if available_versions:
            package_url = available_versions[0].actionable.package_url
        else:
            actionable = session.query(Actionable).filter_by(uuid=actionable_id).first()
            if actionable:
                package_url = actionable.package_url
            else:
                return jsonify({"error": "Actionable package not found"}), 404

    results = sorted(results, key=lambda v: MavenVersion(v["version"]), reverse=True)
    return render_template(
        "package_scan.html",
        results=results,
        actionable_id=actionable_id,
        version_in_use=version_in_use,
        package_url=package_url,
        repository_id=repository_id,
        env=env,
    )


@actionable.route("/v3/request_package_scan", methods=["POST"])
def request_package_scan():
    actionable_id = request.form.get("actionable_id")
    version = request.form.get("version")
    version_in_use = request.form.get("version_in_use")
    with Session() as session:
        actionable_package = (
            session.query(ActionablePackageAvailableVersion)
            .filter_by(actionable_id=actionable_id, version=version)
            .first()
        )
        if actionable_package:
            actionable_package.scan_and_update_results(session=session, is_rescan=True)
            return redirect(
                url_for(
                    "actionable.safe_upgrades",
                    actionable_id=actionable_id,
                    version_in_use=version_in_use,
                )
            )
        else:
            return jsonify({"error": "Package not found"}), 404
