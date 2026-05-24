import logging

from flask import jsonify
from flask import render_template
from flask import request
from packageurl import PackageURL

from libinv.api.actionable.queries.package_details import PackageDetailsQuery
from libinv.base import Session
from libinv.services.scancodeio_client import get_default_client

from libinv.api.actionable import actionable

logger = logging.getLogger(__name__)


def _vulns_of(pkg):
    """Return the ``affected_by_vulnerabilities`` collection for either an
    ORM ``DiscoveredPackage`` (SQL path) or a DTO ``dict`` (HTTP path).

    Both paths feed into the same downstream CVE-extraction loop; this
    helper normalises attribute-vs-key access so the loop body is
    storage-agnostic.
    """
    if isinstance(pkg, dict):
        return pkg.get("affected_by_vulnerabilities", []) or []
    return getattr(pkg, "affected_by_vulnerabilities", []) or []


def _pkg_field(pkg, field):
    """Return ``field`` from either an ORM instance or a DTO ``dict``."""
    if isinstance(pkg, dict):
        return pkg.get(field)
    return getattr(pkg, field, None)


@actionable.route("/v3/package-details", methods=["GET"])
def package_details():
    """
    Display detailed CVE and EPSS information for a specific package
    """
    package_url = request.args.get("package_url")
    version = request.args.get("version")

    if not package_url or not version:
        return jsonify({"error": "package_url and version parameters required"}), 400

    query = PackageDetailsQuery(package_url=package_url, version=version)

    with Session() as session:
        actionable_package = query.fetch_actionable_package(session)

    try:
        if actionable_package:
            parsed_purl = actionable_package.parsed_purl
        else:
            parsed_purl = PackageURL.from_string(package_url)

        package_info = {
            "type": parsed_purl.type,
            "namespace": parsed_purl.namespace,
            "name": parsed_purl.name,
            "version": version,
            "full_url": package_url,
        }
    except Exception as exc:
        logger.exception("failed to parse purl for package_url=%s: %s", package_url, exc)
        package_info = {
            "type": "unknown",
            "namespace": "N/A",
            "name": package_url.split("/")[-1] if "/" in package_url else package_url,
            "version": version,
            "full_url": package_url,
        }

    with Session() as session:
        # Use the actionable_package we already queried above
        if not actionable_package:
            actionable_package = query.fetch_actionable_package(session)

        cve_details = []
        if actionable_package and actionable_package.scancode_project_uuid:
            # Gated HTTP migration: when LIBINV_SCIO_USE_HTTP is set and the
            # ScancodeioClient is configured, fetch discovered packages via
            # the HTTP API instead of reflecting the scio DB directly. On any
            # HTTP failure we fall back to the SQL path so the route still
            # functions when scancodeio is unreachable.
            http_client = get_default_client()
            discovered_packages = None
            if http_client is not None:
                try:
                    discovered_packages = http_client.list_discovered_packages(
                        actionable_package.scancode_project_uuid
                    )
                except Exception as exc:
                    logger.warning(
                        "SCIO HTTP list_discovered_packages failed for %s: %s; "
                        "falling back to SQL",
                        actionable_package.scancode_project_uuid,
                        exc,
                    )
                    discovered_packages = None

            if discovered_packages is None:
                # SQL path (default; also used when HTTP fails).
                discovered_packages = query.fetch_discovered_packages_sql(
                    session, actionable_package.scancode_project_uuid
                )

            # Extract CVEs from vulnerability data
            cve_set = set()
            cve_sources = {}  # Track which discovered package each CVE came from

            for discovered_pkg in discovered_packages:
                vulns = _vulns_of(discovered_pkg)
                if vulns:
                    for vuln in vulns:
                        try:
                            aliases = vuln.get("aliases", [])
                            cve_ids = [alias for alias in aliases if alias.startswith("CVE-")]

                            for cve in cve_ids:
                                cve_upper = cve.upper()
                                cve_set.add(cve_upper)
                                if cve_upper not in cve_sources:
                                    cve_sources[cve_upper] = []

                                # Create a unique key for this package
                                pkg_name = _pkg_field(discovered_pkg, "name") or "Unknown"
                                pkg_version = _pkg_field(discovered_pkg, "version") or "Unknown"
                                package_key = f"{pkg_name}_{pkg_version}"

                                # Check if this package is already in the sources for this CVE
                                existing_packages = [
                                    f"{s['package_name']}_{s['package_version']}"
                                    for s in cve_sources[cve_upper]
                                ]
                                if package_key not in existing_packages:
                                    cve_sources[cve_upper].append(
                                        {
                                            "package_name": pkg_name,
                                            "package_version": pkg_version,
                                            "vulnerability_data": vuln,
                                        }
                                    )
                        except (AttributeError, TypeError):
                            logger.error(f"Error processing vulnerability data: {vuln}")

            # Get EPSS scores for these CVEs
            if cve_set:
                epss_dict = query.fetch_epss_records(session, cve_set)

                # Build CVE details list
                for cve in sorted(cve_set):
                    epss_record = epss_dict.get(cve)
                    cve_detail = {
                        "cve": cve,
                        "epss_score": epss_record.epss_score if epss_record else None,
                        "epss_percentile": epss_record.epss_percentile if epss_record else None,
                        "epss_date": epss_record.epss_date if epss_record else None,
                        "updated_at": epss_record.updated_at if epss_record else None,
                        "sources": cve_sources.get(cve, []),
                        "cvss_score": None,  # Will be populated later
                    }
                    cve_details.append(cve_detail)

        # Sort CVEs by EPSS score (highest first)
        cve_details.sort(key=lambda x: x["epss_score"] or 0, reverse=True)

        # Get repositories that use this package version
        repositories_using_package = []
        if actionable_package:
            repositories_using_package = query.fetch_repositories_using_package(
                session, actionable_package.uuid
            )

        # Add CVSS scores to CVE details for consistent classification
        for cve_detail in cve_details:
            cve = cve_detail["cve"]
            cve_detail["cvss_score"] = None

            # Try to get CVSS score from vulnerability data if no EPSS
            if not cve_detail["epss_score"]:
                for source in cve_detail.get("sources", []):
                    try:
                        vuln_data = source.get("vulnerability_data", {})
                        cvss_data = vuln_data.get("cvss", [])
                        if cvss_data and isinstance(cvss_data, list) and len(cvss_data) > 0:
                            cvss_metrics = cvss_data[0].get("metrics", {})
                            cvss_score = cvss_metrics.get("baseScore")
                            if cvss_score:
                                cve_detail["cvss_score"] = cvss_score
                                break
                    except (AttributeError, TypeError, KeyError):
                        continue

        def classify_severity_for_stats(cve_detail):
            """Classify severity based on EPSS score with CVSS fallback"""
            epss_score = cve_detail.get("epss_score")
            cvss_score = cve_detail.get("cvss_score")

            # Primary: Use EPSS score if available
            if epss_score is not None:
                if epss_score > 0.8:
                    return "critical"
                elif epss_score > 0.7:
                    return "high"
                elif epss_score > 0.5:
                    return "medium"
                else:
                    return "low"

            # Fallback: Use CVSS score if available
            elif cvss_score is not None:
                if cvss_score >= 9.0:
                    return "critical"
                elif cvss_score >= 7.0:
                    return "high"
                elif cvss_score >= 4.0:
                    return "medium"
                elif cvss_score > 0:
                    return "low"

            # No score available
            return "unknown"

        # Calculate severity counts using consistent classification
        classified_severities = [classify_severity_for_stats(cve) for cve in cve_details]
        critical_count = len([s for s in classified_severities if s == "critical"])
        high_count = len([s for s in classified_severities if s == "high"])
        medium_count = len([s for s in classified_severities if s == "medium"])
        low_count = len([s for s in classified_severities if s == "low"])

        package_stats = {
            "total_cves": len(cve_details),
            "cves_with_epss": len([c for c in cve_details if c["epss_score"] is not None]),
            "max_epss_score": max(
                [c["epss_score"] for c in cve_details if c["epss_score"] is not None], default=0
            ),
            "avg_epss_score": (
                sum([c["epss_score"] for c in cve_details if c["epss_score"] is not None])
                / max(len([c for c in cve_details if c["epss_score"] is not None]), 1)
                if cve_details
                else 0
            ),
            "critical_cves": critical_count,
            "high_cves": high_count,
            "medium_cves": medium_count,
            "low_cves": low_count,
        }

    return render_template(
        "package_details.html",
        package_info=package_info,
        cve_details=cve_details,
        package_stats=package_stats,
        repositories_using_package=repositories_using_package,
    )
