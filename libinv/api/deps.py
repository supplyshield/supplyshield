from urllib.parse import urlencode

from flask import Blueprint
from flask import jsonify
from flask import render_template
from flask import request
from sqlalchemy import text

from libinv.base import engine

deps = Blueprint("deps", __name__)


@deps.route("/v1/reverse", methods=["GET"])
def reverse_deps():
    package_name = request.args.get("package_name", "").strip()
    package_namespace = request.args.get("package_namespace", "").strip()
    package_type = request.args.get("package_type", "").strip()
    package_version = request.args.get("package_version", "").strip()
    environment = request.args.get("environment", "").strip()
    try:
        page = max(1, int(request.args.get("page", 1)))
    except (ValueError, TypeError):
        page = 1
    try:
        per_page = min(200, max(1, int(request.args.get("per_page", 50))))
    except (ValueError, TypeError):
        per_page = 50
    fmt = request.args.get("format", "html")

    results = []
    total = 0
    total_pages = 0

    filter_sql = text("""
        SELECT
            array_agg(DISTINCT package_type ORDER BY package_type) AS package_types,
            array_agg(DISTINCT environment ORDER BY environment) AS environments
        FROM dashboard.all_deps
    """)

    with engine.connect() as db_conn:
        row = db_conn.execute(filter_sql).fetchone()
        package_types = list(row.package_types or [])
        environments = list(row.environments or [])

        if package_name or package_namespace:
            offset = (page - 1) * per_page
            conditions = []
            params = {}

            if package_name:
                conditions.append("package_name ILIKE :package_name")
                params["package_name"] = f"%{package_name}%"
            if package_namespace:
                conditions.append("package_namespace ILIKE :package_namespace")
                params["package_namespace"] = f"%{package_namespace}%"
            if package_type:
                conditions.append("package_type = :package_type")
                params["package_type"] = package_type
            if package_version:
                conditions.append("package_version ILIKE :package_version")
                params["package_version"] = f"%{package_version}%"
            if environment:
                conditions.append("environment = :environment")
                params["environment"] = environment

            where_clause = " AND ".join(conditions)

            count_sql = text(f"SELECT COUNT(*) FROM dashboard.all_deps WHERE {where_clause}")
            data_sql = text(f"""
                SELECT
                    repository_name, org, provider, pod, subpod, environment,
                    package_type, package_namespace, package_name, package_version,
                    purl, latest_scan_at, repository_id
                FROM dashboard.all_deps
                WHERE {where_clause}
                ORDER BY repository_name, environment
                LIMIT :limit OFFSET :offset
            """)

            total = db_conn.execute(count_sql, params).scalar()
            rows = db_conn.execute(
                data_sql, {**params, "limit": per_page, "offset": offset}
            ).fetchall()

            total_pages = (total + per_page - 1) // per_page
            results = [dict(row._mapping) for row in rows]

    if fmt == "json":
        return jsonify({
            "results": [
                {
                    **r,
                    "latest_scan_at": r["latest_scan_at"].isoformat()
                    if r["latest_scan_at"]
                    else None,
                }
                for r in results
            ],
            "total": total,
            "page": page,
            "per_page": per_page,
            "total_pages": total_pages,
        })

    base_qs = urlencode({
        k: v for k, v in {
            "package_name": package_name,
            "package_namespace": package_namespace,
            "package_type": package_type,
            "package_version": package_version,
            "environment": environment,
            "per_page": per_page,
        }.items() if v
    })

    return render_template(
        "reverse_deps.html",
        results=results,
        total=total,
        page=page,
        per_page=per_page,
        total_pages=total_pages,
        base_qs=base_qs,
        current_filters={
            "package_name": package_name,
            "package_namespace": package_namespace,
            "package_type": package_type,
            "package_version": package_version,
            "environment": environment,
        },
        package_types=package_types,
        environments=environments,
        title="Reverse Dependency Search",
    )