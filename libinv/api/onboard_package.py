import logging

from flask import Blueprint
from flask import redirect
from flask import render_template
from flask import request
from flask import url_for
from packageurl import PackageURL

from libinv.base import Session
from libinv.models import Actionable
from libinv.models import get_or_create

logger = logging.getLogger(__name__)

onboard_package = Blueprint("onboard_package", __name__, template_folder="templates")


@onboard_package.route("/new_actionable", methods=["GET", "POST"])
def new_actionable():
    if request.method != "POST":
        return render_template("onboard_package.html", message=None, category=None)

    package_url = request.form.get("package_url")
    if not package_url:
        return render_template("onboard_package.html", message="Package URL is required", category="danger")

    try:
        # Parse and validate Package URL
        purl = PackageURL.from_string(package_url)
    except ValueError:
        return render_template("onboard_package.html", message="Invalid Package URL format", category="danger")
    
    try:
        # Create versionless PURL as Actionable stores versionless URLs
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
                # Sprint 48.1: ``session`` is now required (keyword-only).
                try:
                    actionable.fetch_and_store_versions(session=session)
                    # Refresh to see if we have versions now
                    session.expire_all()
                    session.refresh(actionable)
                except Exception:
                    logger.exception("Error fetching versions for %s", versionless_purl)
                    message = (
                        "Created/Found actionable but failed to fetch versions. "
                        "Check server logs."
                    )
                    category = "warning"
                    return render_template(
                        "onboard_package.html", message=message, category=category
                    )

            if not actionable.available_versions:
                message = f"Package {versionless_purl} onboarded, but no versions were found in PURLDB."
                category = "warning"
                return render_template(
                    "onboard_package.html", message=message, category=category
                )

            return redirect(
                url_for(
                    "actionable.safe_upgrades",
                    actionable_id=actionable.uuid,
                    version_in_use="dummy",
                    repository_id="dummy",
                )
            )

    except Exception:
        logger.exception("Error in onboarding package")
        return render_template(
            "onboard_package.html",
            message="An error occurred. Check server logs.",
            category="danger",
        )
