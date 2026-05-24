from flask import jsonify
from flask import render_template
from flask import request

from libinv import logger
from libinv.base import Session
from libinv.models import Actionable

from libinv.api.actionable import actionable
from libinv.api.actionable._common import fetch_repository


@actionable.route("/v2/", methods=["GET"])
def actionables_v2():
    repository_id = request.args.get("repository_id")
    environment = request.args.get("env", "prod")
    format = request.args.get("format", "html")
    commit_id = "N/A"
    jenkins_url = "N/A"

    if not repository_id or not environment:
        return jsonify({"error": "repository_id or env parameter missing"}), 400

    repository = fetch_repository(repository_id)
    with Session() as session:
        actionable_packages = Actionable.get_actionable(session, repository_id, environment)
        results = []

        for package in actionable_packages:
            current_version = package.available_version.version

            if (
                not package.available_version.vulns_count
                or package.available_version.vulns_count == 0
            ):
                continue

            latest_version = package.available_version.actionable.get_latest(session)

            secure_versions = None
            secure_versions = [
                safe_version.version
                for safe_version in package.available_version.actionable.get_safe_versions(session)
            ]

            try:
                parsed_purl = package.available_version.parsed_purl
                package_type = parsed_purl.type
                package_namespace = parsed_purl.namespace
                package_name = parsed_purl.name
            except Exception as exc:
                logger.exception("failed to parse purl for actionable package: %s", exc)
                package_type = "unknown"
                package_namespace = "N/A"
                package_name = (
                    package.available_version.package_url.split("/")[-1]
                    if "/" in package.available_version.package_url
                    else package.available_version.package_url
                )

            results.append(
                {
                    "secure_version_available": len(secure_versions) > 0,
                    "full_package_url": package.available_version.package_url,
                    "package_type": package_type,
                    "package_namespace": package_namespace,
                    "package_name": package_name,
                    "current_version": current_version,
                    "current_version_score": package.available_version.score,
                    "latest_version_score": latest_version.score,
                    "suggested_versions": secure_versions,
                    "versionless_id": package.available_version.actionable.uuid,
                }
            )

        if len(actionable_packages) > 0:
            commit_id = actionable_packages[0].wasp.commit
            jenkins_url = actionable_packages[0].wasp.jenkins_url
            build_timestamp = actionable_packages[0].wasp.created_at
        else:
            build_timestamp = None

        results = sorted(results, key=lambda x: x["secure_version_available"], reverse=True)

    include_epss = False

    if format == "json":
        return jsonify(
            {
                "commit_id": commit_id,
                "jenkins_url": jenkins_url,
                "build_timestamp": build_timestamp,
                "results": results,
            }
        )

    return render_template(
        "actionables_dashboard.html",
        repository=repository,
        selected_env=environment,
        suggested_versions=results,
        commit_id=commit_id,
        jenkins_url=jenkins_url,
        build_timestamp=build_timestamp,
        include_epss=include_epss,
    )


@actionable.route("/v3/", methods=["GET"])
def actionables_v3():
    repository_id = request.args.get("repository_id")
    environment = request.args.get("env", "prod")
    format = request.args.get("format", "html")
    commit_id = "N/A"
    jenkins_url = "N/A"

    if not repository_id or not environment:
        return jsonify({"error": "repository_id or env parameter missing"}), 400

    repository = fetch_repository(repository_id)

    with Session() as session:
        actionable_packages = Actionable.get_actionable(session, repository_id, environment)
        results = []

        for package in actionable_packages:
            current_version = package.available_version.version

            if (
                not package.available_version.vulns_count
                or package.available_version.vulns_count == 0
            ):
                continue

            latest_version = package.available_version.actionable.get_latest(session)

            secure_versions = None
            secure_versions = [
                safe_version.version
                for safe_version in package.available_version.actionable.get_safe_versions(session)
            ]

            try:
                parsed_purl = package.available_version.parsed_purl
                package_type = parsed_purl.type
                package_namespace = parsed_purl.namespace
                package_name = parsed_purl.name
            except Exception as exc:
                logger.exception("failed to parse purl for actionable package: %s", exc)
                package_type = "unknown"
                package_namespace = "N/A"
                package_name = (
                    package.available_version.package_url.split("/")[-1]
                    if "/" in package.available_version.package_url
                    else package.available_version.package_url
                )

            results.append(
                {
                    "secure_version_available": len(secure_versions) > 0,
                    "full_package_url": package.available_version.package_url,
                    "package_type": package_type,
                    "package_namespace": package_namespace,
                    "package_name": package_name,
                    "current_version": current_version,
                    "current_version_score": package.available_version.score,
                    "current_version_epss_score": package.available_version.epss_score,
                    "epss_score": package.available_version.epss_score,  # For template compatibility
                    "latest_version_score": latest_version.score if latest_version else None,
                    "latest_version_epss_score": (
                        latest_version.epss_score if latest_version else None
                    ),
                    "suggested_versions": secure_versions,
                    "versionless_id": package.available_version.actionable.uuid,
                }
            )

        if len(actionable_packages) > 0:
            commit_id = actionable_packages[0].wasp.commit
            jenkins_url = actionable_packages[0].wasp.jenkins_url
            build_timestamp = actionable_packages[0].wasp.created_at
        else:
            build_timestamp = None

        results = sorted(results, key=lambda x: x["secure_version_available"], reverse=True)

    include_epss = any(result.get("epss_score") is not None for result in results)

    if format == "json":
        return jsonify(
            {
                "commit_id": commit_id,
                "jenkins_url": jenkins_url,
                "build_timestamp": build_timestamp,
                "results": results,
            }
        )

    return render_template(
        "actionables_dashboard.html",
        repository=repository,
        selected_env=environment,
        suggested_versions=results,
        commit_id=commit_id,
        jenkins_url=jenkins_url,
        build_timestamp=build_timestamp,
        include_epss=include_epss,
    )
