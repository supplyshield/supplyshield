from flask import render_template
from flask import request
from sqlalchemy import and_
from sqlalchemy import distinct
from sqlalchemy import func
from sqlalchemy import or_

from libinv.base import Session
from libinv.models import ActionablePackageAvailableVersion
from libinv.models import Repository
from libinv.models import Repository_ActionablePackageAvailableVersion

from libinv.api.actionable import actionable


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
        }

    return render_template(
        "repositories_listing.html",
        repositories=repositories_list,
        summary_stats=summary_stats,
        filter_options=filter_options,
        current_filters=current_filters,
        no_filters=(
            environment_filter == ""
            and pod_filter == ""
            and org_filter == ""
            and search_query == ""
            and has_vulnerabilities == ""
            and priority_filter == ""
        ),
    )
