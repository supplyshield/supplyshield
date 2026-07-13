from datetime import datetime, timezone

from flask import Blueprint
from flask import jsonify
from flask import redirect
from flask import render_template
from flask import request
from flask import url_for
from packageurl import PackageURL
from sqlalchemy import and_
from sqlalchemy import distinct
from sqlalchemy import func
from sqlalchemy import or_
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import sessionmaker
from univers.versions import MavenVersion

from libinv import logger
from libinv.base import Session
from libinv.base import engine
from libinv.models import EPSS
from libinv.models import Actionable
from libinv.models import ActionablePackageAvailableVersion
from libinv.models import Repository
from libinv.models import Repository_ActionablePackageAvailableVersion
from libinv.models import ServiceStatus
from libinv.models import Wasp
from libinv.scio_models import DiscoveredPackage
from libinv.scio_models import VulnerablePath
from libinv.cli.sync_service_status import _upsert
from libinv.scripts.deployment_status import fetch_service_status

actionable = Blueprint("actionable", __name__, template_folder="templates")


def fetch_repository(repository_id):
    try:
        Session = sessionmaker(bind=engine)
        conn = Session()
        result = conn.query(Repository).filter_by(id=repository_id).first()
        return result
    except SQLAlchemyError as e:
        conn.rollback()
        print(str(e))
    finally:
        conn.close()


@actionable.route("/v2/", methods=["GET"])
def actionables_v2():
    repository_id = request.args.get("repository_id")
    environment = request.args.get("env", "prod")
    format = request.args.get("format", "html")
    commit_id = "N/A"
    jenkins_url = "N/A"

    if not repository_id or not environment:
        return jsonify({"error": "repository_id or env parameter missing"}), 500

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
                package.version
                for package in package.available_version.actionable.get_safe_versions(session)
            ]

            try:
                parsed_purl = package.available_version.parsed_purl
                package_type = parsed_purl.type
                package_namespace = parsed_purl.namespace
                package_name = parsed_purl.name
            except:
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
        return jsonify({"error": "repository_id or env parameter missing"}), 500

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
                package.version
                for package in package.available_version.actionable.get_safe_versions(session)
            ]

            try:
                parsed_purl = package.available_version.parsed_purl
                package_type = parsed_purl.type
                package_namespace = parsed_purl.namespace
                package_name = parsed_purl.name
            except:
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

    with Session() as session:
        svc_status = (
            session.query(ServiceStatus)
            .filter_by(repository_id=repository_id, environment=environment)
            .first()
        )

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
        svc_status=svc_status,
    )


@actionable.route("/v3/package-details", methods=["GET"])
def package_details():
    """
    Display detailed CVE and EPSS information for a specific package
    """
    package_url = request.args.get("package_url")
    version = request.args.get("version")
    fmt = request.args.get("format", "html")

    if not package_url or not version:
        return jsonify({"error": "package_url and version parameters required"}), 400

    with Session() as session:
        actionable_package = (
            session.query(ActionablePackageAvailableVersion)
            .filter(ActionablePackageAvailableVersion.package_url == package_url)
            .filter(ActionablePackageAvailableVersion.version == version)
            .first()
        )

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
    except:
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
            actionable_package = (
                session.query(ActionablePackageAvailableVersion)
                .filter(ActionablePackageAvailableVersion.package_url == package_url)
                .filter(ActionablePackageAvailableVersion.version == version)
                .first()
            )

        cve_details = []
        if actionable_package and actionable_package.scancode_project_uuid:
            # Get all packages for this project from scanpipe_discoveredpackage
            discovered_packages = (
                session.query(DiscoveredPackage)
                .filter(DiscoveredPackage.project_id == actionable_package.scancode_project_uuid)
                .all()
            )

            # Extract CVEs from vulnerability data
            cve_set = set()
            cve_sources = {}  # Track which discovered package each CVE came from

            for discovered_pkg in discovered_packages:
                vulns = getattr(discovered_pkg, "affected_by_vulnerabilities", [])
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
                                package_key = f"{discovered_pkg.name or 'Unknown'}_{discovered_pkg.version or 'Unknown'}"

                                # Check if this package is already in the sources for this CVE
                                existing_packages = [
                                    f"{s['package_name']}_{s['package_version']}"
                                    for s in cve_sources[cve_upper]
                                ]
                                if package_key not in existing_packages:
                                    cve_sources[cve_upper].append(
                                        {
                                            "package_name": discovered_pkg.name or "Unknown",
                                            "package_version": discovered_pkg.version or "Unknown",
                                            "vulnerability_data": vuln,
                                        }
                                    )
                        except (AttributeError, TypeError):
                            logger.error(f"Error processing vulnerability data: {vuln}")

            # Get EPSS scores for these CVEs
            if cve_set:
                epss_records = session.query(EPSS).filter(EPSS.cve.in_(list(cve_set))).all()

                epss_dict = {record.cve: record for record in epss_records}

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
            repo_usage = (
                session.query(
                    Repository.id,
                    Repository.name,
                    Repository.org,
                    Repository.provider,
                    Repository.pod,
                    Repository.subpod,
                    Repository_ActionablePackageAvailableVersion.environment,
                )
                .join(
                    Repository_ActionablePackageAvailableVersion,
                    Repository.id == Repository_ActionablePackageAvailableVersion.repository_id,
                )
                .filter(
                    Repository_ActionablePackageAvailableVersion.actionable_package_version_id
                    == actionable_package.uuid
                )
                .all()
            )

            repositories_using_package = [
                {
                    "id": repo.id,
                    "name": repo.name,
                    "org": repo.org,
                    "provider": repo.provider,
                    "pod": repo.pod,
                    "subpod": repo.subpod,
                    "environment": repo.environment,
                }
                for repo in repo_usage
            ]

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

    if fmt == "json":
        # Serialize date fields before returning
        for cve in cve_details:
            cve["epss_date"] = str(cve["epss_date"]) if cve["epss_date"] else None
            cve["updated_at"] = str(cve["updated_at"]) if cve["updated_at"] else None
        return jsonify(
            {
                "package_info": package_info,
                "cve_details": cve_details,
                "package_stats": package_stats,
                "repositories_using_package": repositories_using_package,
            }
        )

    return render_template(
        "package_details.html",
        package_info=package_info,
        cve_details=cve_details,
        package_stats=package_stats,
        repositories_using_package=repositories_using_package,
    )


@actionable.route("/v3/repositories", methods=["GET"])
def repositories_listing():
    """
    Display a list of all repositories with filters and statistics
    """

    # Get filter parameters
    environment_filter = request.args.get("environment", "")
    pod_filter = request.args.get("pod", "")
    org_filter = request.args.get("org", "")
    search_query = request.args.get("search", "")
    has_vulnerabilities = request.args.get("has_vulnerabilities", "")
    priority_filter = request.args.get("priority", "")
    live_status_filter = request.args.get("live_status", "")
    format = request.args.get("format", "")

    with Session() as session:
        # Base query for repository statistics
        base_query = (
            session.query(
                Repository.id,
                Repository.name,
                Repository.org,
                Repository.provider,
                Repository.pod,
                Repository.subpod,
                Repository_ActionablePackageAvailableVersion.environment,
                func.count(
                    distinct(
                        Repository_ActionablePackageAvailableVersion.actionable_package_version_id
                    )
                ).label("total_packages"),
                func.count(distinct(ActionablePackageAvailableVersion.uuid))
                .filter(ActionablePackageAvailableVersion.vulns_count > 0)
                .label("vulnerable_packages"),
                func.max(ActionablePackageAvailableVersion.epss_score).label("max_epss_score"),
            )
            .join(
                Repository_ActionablePackageAvailableVersion,
                Repository.id == Repository_ActionablePackageAvailableVersion.repository_id,
            )
            .join(
                ActionablePackageAvailableVersion,
                Repository_ActionablePackageAvailableVersion.actionable_package_version_id
                == ActionablePackageAvailableVersion.uuid,
            )
        )

        # Apply filters
        if environment_filter:
            base_query = base_query.filter(
                Repository_ActionablePackageAvailableVersion.environment == environment_filter
            )

        if pod_filter:
            base_query = base_query.filter(Repository.pod == pod_filter)

        if org_filter:
            base_query = base_query.filter(Repository.org == org_filter)

        if search_query:
            base_query = base_query.filter(
                or_(
                    Repository.name.ilike(f"%{search_query}%"),
                    Repository.org.ilike(f"%{search_query}%"),
                )
            )

        # Group by repository and environment
        base_query = base_query.group_by(
            Repository.id,
            Repository.name,
            Repository.org,
            Repository.provider,
            Repository.pod,
            Repository.subpod,
            Repository_ActionablePackageAvailableVersion.environment,
        )

        # Apply vulnerability filter
        if has_vulnerabilities == "true":
            base_query = base_query.having(
                func.count(distinct(ActionablePackageAvailableVersion.uuid)).filter(
                    ActionablePackageAvailableVersion.vulns_count > 0
                )
                > 0
            )
        elif has_vulnerabilities == "false":
            base_query = base_query.having(
                func.count(distinct(ActionablePackageAvailableVersion.uuid)).filter(
                    ActionablePackageAvailableVersion.vulns_count > 0
                )
                == 0
            )

        # Apply priority filter based on EPSS scores
        if priority_filter == "p0":
            base_query = base_query.having(
                func.max(ActionablePackageAvailableVersion.epss_score) > 0.8
            )
        elif priority_filter == "p1":
            base_query = base_query.having(
                and_(
                    func.max(ActionablePackageAvailableVersion.epss_score) > 0.7,
                    func.max(ActionablePackageAvailableVersion.epss_score) <= 0.8,
                )
            )
        elif priority_filter == "p2":
            base_query = base_query.having(
                and_(
                    func.max(ActionablePackageAvailableVersion.epss_score) > 0.5,
                    func.max(ActionablePackageAvailableVersion.epss_score) <= 0.7,
                )
            )
        elif priority_filter == "p3":
            base_query = base_query.having(
                func.max(ActionablePackageAvailableVersion.epss_score) <= 0.5
            )
        elif priority_filter == "no_epss":
            base_query = base_query.having(
                func.max(ActionablePackageAvailableVersion.epss_score).is_(None)
            )

        # Order by repository name and environment
        repositories_data = base_query.order_by(
            Repository.name, Repository_ActionablePackageAvailableVersion.environment
        ).all()

        # Get filter options
        all_environments = (
            session.query(distinct(Repository_ActionablePackageAvailableVersion.environment))
            .order_by(Repository_ActionablePackageAvailableVersion.environment)
            .all()
        )
        all_pods = (
            session.query(distinct(Repository.pod))
            .filter(Repository.pod.isnot(None))
            .order_by(Repository.pod)
            .all()
        )
        all_orgs = session.query(distinct(Repository.org)).order_by(Repository.org).all()

        # Process data into repository groups
        repositories = {}
        for repo_data in repositories_data:
            repo_key = f"{repo_data.id}_{repo_data.name}_{repo_data.org}"
            if repo_key not in repositories:
                repositories[repo_key] = {
                    "id": repo_data.id,
                    "name": repo_data.name,
                    "org": repo_data.org,
                    "provider": repo_data.provider,
                    "pod": repo_data.pod,
                    "subpod": repo_data.subpod,
                    "environments": {},
                    "total_packages": 0,
                    "total_vulnerable": 0,
                    "max_epss_score": 0,
                }

            repositories[repo_key]["environments"][repo_data.environment] = {
                "total_packages": repo_data.total_packages,
                "vulnerable_packages": repo_data.vulnerable_packages,
                "max_epss_score": repo_data.max_epss_score or 0,
            }

            # Update totals
            repositories[repo_key]["total_packages"] += repo_data.total_packages
            repositories[repo_key]["total_vulnerable"] += repo_data.vulnerable_packages
            repositories[repo_key]["max_epss_score"] = max(
                repositories[repo_key]["max_epss_score"], repo_data.max_epss_score or 0
            )

        # Add priority classification to each repository
        for repo in repositories.values():
            epss_score = repo["max_epss_score"]
            if epss_score is None or epss_score == 0:
                repo["priority"] = "no_epss"
                repo["priority_label"] = "No EPSS Data"
                repo["priority_color"] = "var(--text-muted)"
            elif epss_score > 0.8:
                repo["priority"] = "p0"
                repo["priority_label"] = "P0 - Critical"
                repo["priority_color"] = "var(--critical)"
            elif epss_score > 0.7:
                repo["priority"] = "p1"
                repo["priority_label"] = "P1 - High"
                repo["priority_color"] = "var(--high)"
            elif epss_score > 0.5:
                repo["priority"] = "p2"
                repo["priority_label"] = "P2 - Medium"
                repo["priority_color"] = "var(--medium)"
            else:
                repo["priority"] = "p3"
                repo["priority_label"] = "P3 - Low"
                repo["priority_color"] = "var(--low)"

        # Convert to list and sort
        repositories_list = sorted(repositories.values(), key=lambda x: x["name"])

        # Calculate summary statistics
        total_repositories = len(repositories_list)
        repositories_with_vulns = len([r for r in repositories_list if r["total_vulnerable"] > 0])
        repositories_without_vulns = total_repositories - repositories_with_vulns
        total_packages = sum(r["total_packages"] for r in repositories_list)
        total_vulnerable_packages = sum(r["total_vulnerable"] for r in repositories_list)

        # Calculate priority statistics
        p0_count = len([r for r in repositories_list if r["priority"] == "p0"])
        p1_count = len([r for r in repositories_list if r["priority"] == "p1"])
        p2_count = len([r for r in repositories_list if r["priority"] == "p2"])
        p3_count = len([r for r in repositories_list if r["priority"] == "p3"])
        no_epss_count = len([r for r in repositories_list if r["priority"] == "no_epss"])

        summary_stats = {
            "total_repositories": total_repositories,
            "repositories_with_vulnerabilities": repositories_with_vulns,
            "repositories_without_vulnerabilities": repositories_without_vulns,
            "total_packages": total_packages,
            "total_vulnerable_packages": total_vulnerable_packages,
            "vulnerability_percentage": round(
                (repositories_with_vulns / max(total_repositories, 1)) * 100, 1
            ),
            "p0_repositories": p0_count,
            "p1_repositories": p1_count,
            "p2_repositories": p2_count,
            "p3_repositories": p3_count,
            "no_epss_repositories": no_epss_count,
        }

        filter_options = {
            "environments": [env[0] for env in all_environments],
            "pods": [pod[0] for pod in all_pods],
            "orgs": [org[0] for org in all_orgs],
        }

        current_filters = {
            "environment": environment_filter,
            "pod": pod_filter,
            "org": org_filter,
            "search": search_query,
            "has_vulnerabilities": has_vulnerabilities,
            "priority": priority_filter,
            "live_status": live_status_filter,
        }

    # Batch-fetch service statuses for all repos in the result set
    repo_ids = [r["id"] for r in repositories_list]
    with Session() as session:
        svc_rows = (
            session.query(ServiceStatus)
            .filter(ServiceStatus.repository_id.in_(repo_ids))
            .all()
        )
    status_map = {(s.repository_id, s.environment): s for s in svc_rows}

    if live_status_filter == "active":
        repositories_list = [
            r for r in repositories_list
            if any(
                status_map.get((r["id"], env)) and
                status_map[(r["id"], env)].status == "active"
                for env in r["environments"]
            )
        ]
    elif live_status_filter == "no_tasks":
        repositories_list = [
            r for r in repositories_list
            if any(
                status_map.get((r["id"], env)) and
                status_map[(r["id"], env)].status == "active" and
                (status_map[(r["id"], env)].running_count or 0) == 0
                for env in r["environments"]
            )
        ]
    elif live_status_filter == "no_data":
        repositories_list = [
            r for r in repositories_list
            if not any(
                status_map.get((r["id"], env)) and
                status_map[(r["id"], env)].status == "active"
                for env in r["environments"]
            )
        ]

    if format == "json":
        def _svc_dict(s):
            if not s:
                return None
            return {
                "status": s.status,
                "health_status": s.health_status,
                "running_count": s.running_count,
                "desired_count": s.desired_count,
                "last_healthy_at": s.last_healthy_at.isoformat() if s.last_healthy_at else None,
                "captured_at": s.captured_at.isoformat() if s.captured_at else None,
            }

        enriched = []
        for repo in repositories_list:
            r = dict(repo)
            r["live_status"] = {
                env: _svc_dict(status_map.get((repo["id"], env)))
                for env in repo["environments"]
            }
            enriched.append(r)

        return jsonify({
            "repositories": enriched,
            "summary_stats": summary_stats,
            "filter_options": filter_options,
            "current_filters": current_filters,
        })

    return render_template(
        "repositories_listing.html",
        repositories=repositories_list,
        summary_stats=summary_stats,
        filter_options=filter_options,
        current_filters=current_filters,
        status_map=status_map,
        no_filters=(
            environment_filter == ""
            and pod_filter == ""
            and org_filter == ""
            and search_query == ""
            and has_vulnerabilities == ""
            and priority_filter == ""
            and live_status_filter == ""
        ),
    )


@actionable.route("/v3/status/refresh", methods=["POST"])
def refresh_service_status():
    repository_id = request.args.get("repository_id")
    environment = request.args.get("env")

    if not repository_id or not environment:
        return jsonify({"error": "repository_id and env are required"}), 400

    try:
        repository_id_int = int(repository_id)
    except ValueError:
        return jsonify({"error": "repository_id must be an integer"}), 400

    repo = fetch_repository(repository_id_int)
    if not repo:
        return jsonify({"error": "repository not found"}), 404

    with Session() as session:
        valid_envs = {
            row[0] for row in session.query(Wasp.environment)
            .filter(Wasp.repository_id == repository_id_int)
            .distinct()
        }
    if environment not in valid_envs:
        return jsonify({"error": "invalid environment"}), 400

    normalized = fetch_service_status(repo.name, environment)
    normalized["repository_id"] = repository_id_int
    normalized["captured_at"] = datetime.now(tz=timezone.utc)

    _upsert([normalized])

    return redirect(f"/actionable/v3/?repository_id={repository_id_int}&env={environment}")


@actionable.route("/v3/statistics", methods=["GET"])
def statistics_dashboard():
    """
    Display comprehensive statistics about packages, vulnerabilities, and EPSS scores
    """
    try:
        with Session() as session:
            session.execute(text("SET statement_timeout = '30s'"))

        package_stats = session.query(
            func.count(ActionablePackageAvailableVersion.uuid).label("total_packages"),
            func.count(ActionablePackageAvailableVersion.uuid)
            .filter(ActionablePackageAvailableVersion.vulns_count > 0)
            .label("vulnerable_packages"),
            func.count(ActionablePackageAvailableVersion.uuid)
            .filter(ActionablePackageAvailableVersion.epss_score.isnot(None))
            .label("packages_with_epss"),
            func.sum(ActionablePackageAvailableVersion.vulns_count).label("total_vulnerabilities"),
        ).first()

        # Calculate EPSS priority distributions
        p0_packages = (
            session.query(func.count(ActionablePackageAvailableVersion.uuid))
            .filter(
                and_(
                    ActionablePackageAvailableVersion.epss_score > 0.8,
                    ActionablePackageAvailableVersion.vulns_count > 0,
                )
            )
            .scalar()
            or 0
        )

        p1_packages = (
            session.query(func.count(ActionablePackageAvailableVersion.uuid))
            .filter(
                and_(
                    ActionablePackageAvailableVersion.epss_score > 0.7,
                    ActionablePackageAvailableVersion.epss_score <= 0.8,
                    ActionablePackageAvailableVersion.vulns_count > 0,
                )
            )
            .scalar()
            or 0
        )

        p2_packages = (
            session.query(func.count(ActionablePackageAvailableVersion.uuid))
            .filter(
                and_(
                    ActionablePackageAvailableVersion.epss_score > 0.5,
                    ActionablePackageAvailableVersion.epss_score <= 0.7,
                    ActionablePackageAvailableVersion.vulns_count > 0,
                )
            )
            .scalar()
            or 0
        )

        p3_packages = (
            session.query(func.count(ActionablePackageAvailableVersion.uuid))
            .filter(
                and_(
                    ActionablePackageAvailableVersion.epss_score <= 0.5,
                    ActionablePackageAvailableVersion.epss_score.isnot(None),
                    ActionablePackageAvailableVersion.vulns_count > 0,
                )
            )
            .scalar()
            or 0
        )

        no_epss_packages = (
            session.query(func.count(ActionablePackageAvailableVersion.uuid))
            .filter(
                and_(
                    ActionablePackageAvailableVersion.epss_score.is_(None),
                    ActionablePackageAvailableVersion.vulns_count > 0,
                )
            )
            .scalar()
            or 0
        )

        # Extract values from the aggregated query
        total_packages = package_stats.total_packages or 0
        vulnerable_packages = package_stats.vulnerable_packages or 0
        packages_with_epss = package_stats.packages_with_epss or 0
        total_vulnerabilities = package_stats.total_vulnerabilities or 0

        # For now, skip detailed severity statistics to avoid performance issues
        # TODO: Implement more efficient severity calculation if needed
        critical_vulns = 0
        high_vulns = 0
        medium_vulns = 0
        low_vulns = 0

        # Get repository statistics
        total_repositories = session.query(func.count(distinct(Repository.id))).scalar() or 0

        repositories_with_vulns = (
            session.query(func.count(distinct(Repository.id)))
            .join(
                Repository_ActionablePackageAvailableVersion,
                Repository.id == Repository_ActionablePackageAvailableVersion.repository_id,
            )
            .join(
                ActionablePackageAvailableVersion,
                Repository_ActionablePackageAvailableVersion.actionable_package_version_id
                == ActionablePackageAvailableVersion.uuid,
            )
            .filter(ActionablePackageAvailableVersion.vulns_count > 0)
            .scalar()
            or 0
        )

        repositories_without_vulns = total_repositories - repositories_with_vulns

        # Calculate repository priority distributions
        repo_p0_count = (
            session.query(func.count(distinct(Repository.id)))
            .join(
                Repository_ActionablePackageAvailableVersion,
                Repository.id == Repository_ActionablePackageAvailableVersion.repository_id,
            )
            .join(
                ActionablePackageAvailableVersion,
                Repository_ActionablePackageAvailableVersion.actionable_package_version_id
                == ActionablePackageAvailableVersion.uuid,
            )
            .filter(
                and_(
                    ActionablePackageAvailableVersion.epss_score > 0.8,
                    ActionablePackageAvailableVersion.vulns_count > 0,
                )
            )
            .scalar()
            or 0
        )

        repo_p1_count = (
            session.query(func.count(distinct(Repository.id)))
            .join(
                Repository_ActionablePackageAvailableVersion,
                Repository.id == Repository_ActionablePackageAvailableVersion.repository_id,
            )
            .join(
                ActionablePackageAvailableVersion,
                Repository_ActionablePackageAvailableVersion.actionable_package_version_id
                == ActionablePackageAvailableVersion.uuid,
            )
            .filter(
                and_(
                    ActionablePackageAvailableVersion.epss_score > 0.7,
                    ActionablePackageAvailableVersion.epss_score <= 0.8,
                    ActionablePackageAvailableVersion.vulns_count > 0,
                )
            )
            .scalar()
            or 0
        )

        repo_p2_count = (
            session.query(func.count(distinct(Repository.id)))
            .join(
                Repository_ActionablePackageAvailableVersion,
                Repository.id == Repository_ActionablePackageAvailableVersion.repository_id,
            )
            .join(
                ActionablePackageAvailableVersion,
                Repository_ActionablePackageAvailableVersion.actionable_package_version_id
                == ActionablePackageAvailableVersion.uuid,
            )
            .filter(
                and_(
                    ActionablePackageAvailableVersion.epss_score > 0.5,
                    ActionablePackageAvailableVersion.epss_score <= 0.7,
                    ActionablePackageAvailableVersion.vulns_count > 0,
                )
            )
            .scalar()
            or 0
        )

        repo_p3_count = (
            session.query(func.count(distinct(Repository.id)))
            .join(
                Repository_ActionablePackageAvailableVersion,
                Repository.id == Repository_ActionablePackageAvailableVersion.repository_id,
            )
            .join(
                ActionablePackageAvailableVersion,
                Repository_ActionablePackageAvailableVersion.actionable_package_version_id
                == ActionablePackageAvailableVersion.uuid,
            )
            .filter(
                and_(
                    ActionablePackageAvailableVersion.epss_score <= 0.5,
                    ActionablePackageAvailableVersion.epss_score.isnot(None),
                    ActionablePackageAvailableVersion.vulns_count > 0,
                )
            )
            .scalar()
            or 0
        )

        repo_no_epss_count = (
            session.query(func.count(distinct(Repository.id)))
            .join(
                Repository_ActionablePackageAvailableVersion,
                Repository.id == Repository_ActionablePackageAvailableVersion.repository_id,
            )
            .join(
                ActionablePackageAvailableVersion,
                Repository_ActionablePackageAvailableVersion.actionable_package_version_id
                == ActionablePackageAvailableVersion.uuid,
            )
            .filter(
                and_(
                    ActionablePackageAvailableVersion.epss_score.is_(None),
                    ActionablePackageAvailableVersion.vulns_count > 0,
                )
            )
            .scalar()
            or 0
        )

        # Get environment statistics
        env_stats = (
            session.query(
                Repository_ActionablePackageAvailableVersion.environment,
                func.count(
                    distinct(Repository_ActionablePackageAvailableVersion.repository_id)
                ).label("repo_count"),
                func.count(
                    distinct(
                        Repository_ActionablePackageAvailableVersion.actionable_package_version_id
                    )
                ).label("package_count"),
            )
            .group_by(Repository_ActionablePackageAvailableVersion.environment)
            .order_by(Repository_ActionablePackageAvailableVersion.environment)
            .all()
        )

        # Get pod-wise vulnerable packages with EPSS severity buckets - limit to top 20 pods for performance
        pod_stats_query = (
            session.query(
                Repository.pod.label("pod"),
                func.count(distinct(ActionablePackageAvailableVersion.uuid))
                .filter(ActionablePackageAvailableVersion.vulns_count > 0)
                .label("vulnerable_packages"),
                func.count(distinct(ActionablePackageAvailableVersion.uuid))
                .filter(
                    and_(
                        ActionablePackageAvailableVersion.vulns_count > 0,
                        ActionablePackageAvailableVersion.epss_score > 0.8,
                    )
                )
                .label("p0"),
                func.count(distinct(ActionablePackageAvailableVersion.uuid))
                .filter(
                    and_(
                        ActionablePackageAvailableVersion.vulns_count > 0,
                        ActionablePackageAvailableVersion.epss_score > 0.7,
                        ActionablePackageAvailableVersion.epss_score <= 0.8,
                    )
                )
                .label("p1"),
                func.count(distinct(ActionablePackageAvailableVersion.uuid))
                .filter(
                    and_(
                        ActionablePackageAvailableVersion.vulns_count > 0,
                        ActionablePackageAvailableVersion.epss_score > 0.5,
                        ActionablePackageAvailableVersion.epss_score <= 0.7,
                    )
                )
                .label("p2"),
                func.count(distinct(ActionablePackageAvailableVersion.uuid))
                .filter(
                    and_(
                        ActionablePackageAvailableVersion.vulns_count > 0,
                        ActionablePackageAvailableVersion.epss_score <= 0.5,
                    )
                )
                .label("p3"),
            )
            .join(
                Repository_ActionablePackageAvailableVersion,
                Repository.id == Repository_ActionablePackageAvailableVersion.repository_id,
            )
            .join(
                ActionablePackageAvailableVersion,
                Repository_ActionablePackageAvailableVersion.actionable_package_version_id
                == ActionablePackageAvailableVersion.uuid,
            )
            .filter(Repository.pod.isnot(None))
            .group_by(Repository.pod)
            .order_by(func.count(distinct(ActionablePackageAvailableVersion.uuid)).desc())
            .all()
        )

        # Get organization statistics - simplified for performance
        org_stats = (
            session.query(
                Repository.org,
                func.count(distinct(Repository.id)).label("repo_count"),
            )
            .group_by(Repository.org)
            .order_by(func.count(distinct(Repository.id)).desc())
            .limit(10)
            .all()
        )

        statistics = {
            "package_stats": {
                "total_packages": total_packages,
                "vulnerable_packages": vulnerable_packages,
                "packages_without_vulnerabilities": total_packages - vulnerable_packages,
                "packages_with_epss": packages_with_epss,
                "vulnerability_percentage": round(
                    (vulnerable_packages / max(total_packages, 1)) * 100, 1
                ),
                "epss_coverage_percentage": round(
                    (packages_with_epss / max(total_packages, 1)) * 100, 1
                ),
                "p0_packages": p0_packages,
                "p1_packages": p1_packages,
                "p2_packages": p2_packages,
                "p3_packages": p3_packages,
                "no_epss_packages": no_epss_packages,
            },
            "vulnerability_stats": {
                "total_vulnerabilities": total_vulnerabilities,
                "critical_vulnerabilities": critical_vulns,
                "high_vulnerabilities": high_vulns,
                "medium_vulnerabilities": medium_vulns,
                "low_vulnerabilities": low_vulns,
                "avg_vulns_per_vulnerable_package": round(
                    total_vulnerabilities / max(vulnerable_packages, 1), 2
                ),
            },
            "repository_stats": {
                "total_repositories": total_repositories,
                "repositories_with_vulnerabilities": repositories_with_vulns,
                "repositories_without_vulnerabilities": repositories_without_vulns,
                "vulnerability_percentage": round(
                    (repositories_with_vulns / max(total_repositories, 1)) * 100, 1
                ),
                "p0_repositories": repo_p0_count,
                "p1_repositories": repo_p1_count,
                "p2_repositories": repo_p2_count,
                "p3_repositories": repo_p3_count,
                "no_epss_repositories": repo_no_epss_count,
            },
            "environment_stats": [
                {
                    "environment": env.environment,
                    "repository_count": env.repo_count,
                    "package_count": env.package_count,
                }
                for env in env_stats
            ],
            "pod_stats": [
                {
                    "pod": row.pod,
                    "vulnerable_packages": row.vulnerable_packages,
                    "p0": row.p0,
                    "p1": row.p1,
                    "p2": row.p2,
                    "p3": row.p3,
                }
                for row in pod_stats_query
            ],
            "organization_stats": [
                {
                    "organization": org.org,
                    "repository_count": org.repo_count,
                }
                for org in org_stats
            ],
        }

        return render_template("statistics.html", statistics=statistics)

    except Exception as e:
        logger.error(f"Error loading statistics dashboard: {str(e)}")
        # Return a simple error page or redirect to a safe page
        return render_template(
            "statistics.html",
            statistics={
                "package_stats": {"total_packages": 0, "vulnerable_packages": 0},
                "vulnerability_stats": {"total_vulnerabilities": 0},
                "repository_stats": {"total_repositories": 0},
                "environment_stats": [],
                "pod_stats": [],
                "organization_stats": [],
                "error": "Unable to load statistics due to high load. Please try again later.",
            },
        )


@actionable.route("/v3/package_scan", methods=["GET"])
def safe_upgrades():
    actionable_id = request.args.get("actionable_id")
    version_in_use = request.args.get("version_in_use") or None
    repository_id = request.args.get("repository_id")
    env = request.args.get("env", "prod")
    fmt = request.args.get("format", "html")

    if not actionable_id:
        return jsonify({"error": "actionable_id parameter missing"}), 400

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
                    "vulnerabilitiy_severities": version.vulnerabilitiy_severities_epss,
                    "is_latest": version.is_latest,
                    "updated_at": str(version.updated_at) if version.updated_at else None,
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

    if fmt == "json":
        return jsonify(
            {
                "package_url": package_url,
                "actionable_id": actionable_id,
                "version_in_use": version_in_use,
                "results": results,
            }
        )

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
