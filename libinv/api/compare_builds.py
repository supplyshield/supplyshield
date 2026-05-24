import logging

from flask import Blueprint
from flask import jsonify
from flask import redirect
from flask import render_template
from flask import request
from flask import url_for
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import sessionmaker

from libinv.api.actionable import fetch_repository
from libinv.base import engine
from libinv.models import Wasp
from libinv.scio_models import ScanpipeProject

logger = logging.getLogger(__name__)

compare_builds = Blueprint("compare_builds", __name__, template_folder="templates")


def get_scancode_results(wasp_id):
    """
    Get scancode results for a given wasp_id
    """
    Session = sessionmaker(bind=engine)
    session = Session()

    try:
        packages = session.execute(
            text(
                """select 
            CONCAT('pkg:',sd.type,'/', sd.namespace,'/', sd.name,'@', sd.version,'?', sd.qualifiers) as "purl", affected_by_vulnerabilities 
            from 
            scanpipe_project sp 
            left join scanpipe_discoveredpackage sd on sd.project_id = sp.uuid
            where wasp_uuid_id = :wasp_id
            order by purl 
            """
            ),
            {"wasp_id": wasp_id},
        ).fetchall()
        return packages
    except SQLAlchemyError:
        logger.exception("get_scancode_results failed for wasp_id=%s", wasp_id)
        raise
    finally:
        session.close()


def count_of_vulnerable_packages(packages):
    """
    Get count of vulnerable packages
    """
    count = 0
    for package in packages:
        if package.affected_by_vulnerabilities:
            count += 1
    return count


@compare_builds.route("/builds", methods=["GET"])
def get_diff_builds():
    """
    Get top 20 builds and their diff for a given repository_id and environment
    """
    repository_id = request.args.get("repository_id")
    env = request.args.get("env")
    if not repository_id or not env:
        return jsonify({"error": "repository_id or env parameter missing"}), 400

    repository = fetch_repository(repository_id)
    if not repository:
        return jsonify({"error": "Repository not found"}), 404

    Session = sessionmaker(bind=engine)
    session = Session()

    try:
        # NOTE: This query joins on scanpipe_project.wasp_uuid_id, which is not
        # exposed via scancodeio's ProjectFilterSet (verified in Sprint 14 against
        # scanpipe/api/views.py). Migrating to HTTP requires either:
        #   1. Upstream patch to add `wasp_uuid_id` to ProjectFilterSet.Meta.fields, OR
        #   2. A SupplyShield-side proxy endpoint, OR
        #   3. Maintaining a wasp_uuid → project_uuid mapping in libinv.
        # Until any of those land, this route keeps the direct SQL join.
        wasps = (
            session.query(Wasp)
            .join(ScanpipeProject, ScanpipeProject.wasp_uuid_id == Wasp.uuid)
            .filter(Wasp.repository_id == repository_id)
            .filter(Wasp.environment == env)
            .order_by(Wasp.created_at.desc())
            .limit(20)
            .all()
        )
        if not wasps:
            return jsonify({"error": "No wasps found"}), 404

        wasp_left = request.args.get("wasp_left")
        wasp_right = request.args.get("wasp_right")

        if wasp_left and wasp_right:
            wasp_left = session.query(Wasp).filter_by(uuid=wasp_left).first()
            wasp_right = session.query(Wasp).filter_by(uuid=wasp_right).first()

            packages_left = get_scancode_results(wasp_left.uuid)
            packages_right = get_scancode_results(wasp_right.uuid)

            vulnerabilities_count_left = count_of_vulnerable_packages(packages_left)
            vulnerabilities_count_right = count_of_vulnerable_packages(packages_right)

            return render_template(
                "compare_builds.html",
                packages_left=packages_left,
                packages_right=packages_right,
                repository=repository,
                selected_env=env,
                wasps=wasps,
                wasp_left=wasp_left,
                wasp_right=wasp_right,
                vulnerabilities_count_left=vulnerabilities_count_left,
                vulnerabilities_count_right=vulnerabilities_count_right,
                title="BuildDiff",
            )
    except SQLAlchemyError:
        logger.exception("get_diff_builds failed for repository_id=%s env=%s", repository_id, env)
        return jsonify({"error": "An error occurred. Check server logs."}), 500
    finally:
        session.close()

    return render_template(
        "compare_builds.html", wasps=wasps, repository=repository, selected_env=env
    )
