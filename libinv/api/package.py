import logging

from flask import Blueprint
from flask import jsonify
from flask import redirect
from flask import render_template
from flask import request
from flask import url_for
from packageurl import PackageURL
from sqlalchemy import func

from libinv.base import Session
from libinv.models import Actionable
from libinv.models import ActionablePackageAvailableVersion
from libinv.models import get_or_create

logger = logging.getLogger(__name__)

package = Blueprint("package", __name__, template_folder="templates")


@package.route("/v3/packages", methods=["GET"])
def packages_index():
    search = request.args.get("search", "").strip()
    try:
        page = max(1, int(request.args.get("page", 1)))
    except ValueError:
        page = 1
    try:
        per_page = min(200, max(1, int(request.args.get("per_page", 50))))
    except ValueError:
        per_page = 50
    fmt = request.args.get("format", "html")

    with Session() as session:
        # Subquery: version count per actionable
        versions_count_sq = (
            session.query(
                ActionablePackageAvailableVersion.actionable_id,
                func.count(ActionablePackageAvailableVersion.uuid).label("versions_count"),
            )
            .group_by(ActionablePackageAvailableVersion.actionable_id)
            .subquery()
        )

        # Subquery: latest version string per actionable
        latest_version_sq = (
            session.query(
                ActionablePackageAvailableVersion.actionable_id,
                ActionablePackageAvailableVersion.version.label("latest_version"),
            )
            .filter(ActionablePackageAvailableVersion.is_latest == True)
            .subquery()
        )

        query = (
            session.query(
                Actionable,
                func.coalesce(versions_count_sq.c.versions_count, 0).label("versions_count"),
                latest_version_sq.c.latest_version,
            )
            .outerjoin(versions_count_sq, versions_count_sq.c.actionable_id == Actionable.uuid)
            .outerjoin(latest_version_sq, latest_version_sq.c.actionable_id == Actionable.uuid)
        )

        if search:
            query = query.filter(Actionable.package_url.ilike(f"%{search}%"))

        total = query.count()
        rows = (
            query.order_by(Actionable.updated_at.desc())
            .offset((page - 1) * per_page)
            .limit(per_page)
            .all()
        )

        results = []
        for pkg, versions_count, latest_version in rows:
            try:
                parsed = PackageURL.from_string(pkg.package_url)
                pkg_type = parsed.type
                pkg_namespace = parsed.namespace or ""
                pkg_name = parsed.name
            except Exception:
                pkg_type = "unknown"
                pkg_namespace = ""
                pkg_name = (
                    pkg.package_url.split("/")[-1]
                    if "/" in pkg.package_url
                    else pkg.package_url
                )

            results.append(
                {
                    "uuid": pkg.uuid,
                    "package_url": pkg.package_url,
                    "package_type": pkg_type,
                    "package_namespace": pkg_namespace,
                    "package_name": pkg_name,
                    "versions_count": versions_count,
                    "latest_version": latest_version,
                    "updated_at": (
                        pkg.updated_at.strftime("%Y-%m-%d %H:%M")
                        if pkg.updated_at
                        else "N/A"
                    ),
                }
            )

    total_pages = (total + per_page - 1) // per_page

    if fmt == "json":
        return jsonify(
            {
                "results": results,
                "total": total,
                "page": page,
                "per_page": per_page,
                "total_pages": total_pages,
            }
        )

    return render_template(
        "actionables_index.html",
        results=results,
        search=search,
        page=page,
        per_page=per_page,
        total=total,
        total_pages=total_pages,
    )


@package.route("/v3/onboard", methods=["GET", "POST"])
def new_actionable():
    if request.method != "POST":
        return render_template("onboard_package.html", message=None, category=None)

    package_url = request.form.get("package_url")
    if not package_url:
        return render_template(
            "onboard_package.html", message="Package URL is required", category="danger"
        )

    try:
        purl = PackageURL.from_string(package_url)
    except ValueError:
        return render_template(
            "onboard_package.html",
            message="Invalid Package URL format",
            category="danger",
        )

    try:
        versionless_purl = PackageURL(
            type=purl.type, namespace=purl.namespace, name=purl.name
        ).to_string()

        with Session() as session:
            actionable, created = get_or_create(
                session, Actionable, package_url=versionless_purl
            )
            session.refresh(actionable)
            if created or not actionable.available_versions:
                logger.info(f"Onboarding or updating package {versionless_purl}")
                try:
                    actionable.fetch_and_store_versions()
                    session.expire_all()
                    session.refresh(actionable)
                except Exception as e:
                    logger.error(f"Error fetching versions: {e}")
                    return render_template(
                        "onboard_package.html",
                        message=f"Created/Found actionable but failed to fetch versions: {str(e)}",
                        category="warning",
                    )

            if not actionable.available_versions:
                return render_template(
                    "onboard_package.html",
                    message=f"Package {versionless_purl} onboarded, but no versions were found in PURLDB.",
                    category="warning",
                )

            return redirect(
                url_for(
                    "actionable.safe_upgrades",
                    actionable_id=actionable.uuid,
                )
            )

    except Exception as e:
        logger.error(f"Error in onboarding: {e}")
        return render_template(
            "onboard_package.html",
            message=f"An error occurred: {str(e)}",
            category="danger",
        )
