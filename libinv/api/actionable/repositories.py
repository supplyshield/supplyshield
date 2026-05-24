from flask import render_template
from flask import request

from libinv.base import Session

from libinv.api.actionable import actionable
from libinv.api.actionable.queries.repository_listing import RepositoryListingQuery


@actionable.route("/v3/repositories", methods=["GET"])
def repositories_listing():
    """
    Display a list of all repositories with filters and statistics.

    Sprint 44.1: the query assembly (7 chainable filters / having clauses,
    3 facet aggregates, GROUP BY / ORDER BY) lives in
    :class:`~libinv.api.actionable.queries.repository_listing.RepositoryListingQuery`.
    This handler is now request-binding + response-shaping only; the
    Sprint 31.2 behavioral tests (37 tests covering every branch) are the
    contract.
    """

    # Get filter parameters
    params = {
        "environment": request.args.get("environment", ""),
        "pod": request.args.get("pod", ""),
        "org": request.args.get("org", ""),
        "search": request.args.get("search", ""),
        "has_vulnerabilities": request.args.get("has_vulnerabilities", ""),
        "priority": request.args.get("priority", ""),
    }

    with Session() as session:
        repositories_data, facets = (
            RepositoryListingQuery(session, params)
            .having_environment()
            .having_pod()
            .having_org()
            .having_search()
            .having_vulnerabilities()
            .having_priority()
            .with_facet("environments")
            .with_facet("pods")
            .with_facet("orgs")
            .execute()
        )

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
            "environments": facets.get("environments", []),
            "pods": facets.get("pods", []),
            "orgs": facets.get("orgs", []),
        }

        current_filters = {
            "environment": params["environment"],
            "pod": params["pod"],
            "org": params["org"],
            "search": params["search"],
            "has_vulnerabilities": params["has_vulnerabilities"],
            "priority": params["priority"],
        }

    return render_template(
        "repositories_listing.html",
        repositories=repositories_list,
        summary_stats=summary_stats,
        filter_options=filter_options,
        current_filters=current_filters,
        no_filters=(
            params["environment"] == ""
            and params["pod"] == ""
            and params["org"] == ""
            and params["search"] == ""
            and params["has_vulnerabilities"] == ""
            and params["priority"] == ""
        ),
    )
