import logging
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import date, datetime

import click
import requests
from sqlalchemy import bindparam, text
from packageurl import PackageURL

from libinv.base import conn
from libinv.cli.cli import cli
from libinv.env import EXCLUDED_PACKAGE_SUBSTRINGS

logger = logging.getLogger(__name__)

OSV_QUERYBATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{}"

DEFAULT_MAX_WORKERS = 8
DEFAULT_BATCH_SIZE = 50


@cli.command("scan-all-packages")
@click.option(
    "--max-workers",
    type=int,
    default=DEFAULT_MAX_WORKERS,
    show_default=True,
    help="Number of concurrent OSV scan workers.",
)
@click.option(
    "--batch-size",
    type=int,
    default=DEFAULT_BATCH_SIZE,
    show_default=True,
    help="How many PURLs to send per OSV batch request.",
)
def scan_all_packages(max_workers: int, batch_size: int):
    """
        Scan all unique packages in the security database for vulnerabilities
    """
    logger.info("Starting scan for all packages!")
    all_purls = [row[0] for row in get_all_packages()]
    total = len(all_purls)

    purl_to_vuln: dict[str, list] = {}

    def _chunks(items, size):
        size = max(1, size or 1)
        for i in range(0, len(items), size):
            yield items[i : i + size]

    def _scan_batch(purl_batch: list[str]):
        # Each worker gets its own session; requests.Session is not guaranteed
        # to be thread-safe when shared.
        with requests.Session() as session:
            summaries_by_purl = start_scan_for_packages_batch(purl_batch, session)
            result: dict[str, list] = {}
            for purl, advisory_summaries in summaries_by_purl.items():
                vuln_details = fetch_vulnerability_details(advisory_summaries, session)
                result[purl] = vuln_details
            return result

    max_workers = max(1, max_workers or 1)
    batch_size = max(1, batch_size or 1)

    logger.info(
        "Starting OSV scan for %d packages with %d workers, batch size %d",
        total,
        max_workers,
        batch_size,
    )

    batches = list(_chunks(all_purls, batch_size))

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_batch = {
            executor.submit(_scan_batch, batch): batch for batch in batches
        }

        scanned = 0
        for future in as_completed(future_to_batch):
            batch = future_to_batch[future]
            try:
                batch_result = future.result()
                purl_to_vuln.update(batch_result)
            except Exception:
                logger.exception("Failed to scan batch starting with %s", batch[0])
            scanned += len(batch)
            logger.info("Scanned %d/%d packages", scanned, total)

    upsert_all_package_scans(purl_to_vuln)
    return purl_to_vuln


def get_all_packages():
    stmt = text("SELECT DISTINCT(purl) FROM dashboard.all_deps;")
    results = conn.execute(stmt)
    return results


def is_supported(package):
    if package.namespace:
        if any(sub in package.namespace for sub in EXCLUDED_PACKAGE_SUBSTRINGS):
            return False
    elif package.type in ["npm", "pypi"]:
        return False
    else:
        return True
    return True


def start_scan_for_packages_batch(purls: list[str], session: requests.Session):
    """
    Query OSV with multiple PURLs in a single /v1/querybatch call.

    Note: This currently does a single-page fetch per PURL. If OSV ever
    returns a next_page_token for a PURL, additional calls would be
    required to follow pagination for that package.
    """
    if not purls:
        return {}

    payload = {
        "queries": [{"package": {"purl": purl}} for purl in purls],
    }

    out: dict[str, list] = {purl: [] for purl in purls}

    try:
        resp = session.post(OSV_QUERYBATCH_URL, json=payload, timeout=30)
        resp.raise_for_status()
    except requests.RequestException as e:
        logger.exception("OSV batch query failed for %d packages: %s", len(purls), e)
        return out

    data = resp.json() or {}
    results = data.get("results", []) or []

    for idx, purl in enumerate(purls):
        if idx >= len(results):
            break
        result = results[idx] or {}
        vulns = result.get("vulns") or []
        out[purl] = vulns

    return out


def fetch_vulnerability_details(vuln_summaries, session: requests.Session):
    details = []
    for v in vuln_summaries:
        vuln_id = v.get("id")
        if not vuln_id:
            continue

        try:
            resp = session.get(OSV_VULN_URL.format(vuln_id), timeout=30)
            resp.raise_for_status()
        except requests.RequestException as e:
            logger.exception("OSV vuln fetch failed for %s: %s", vuln_id, e)
            continue

        vuln_data = resp.json()
        details.append(vuln_data)

    return details


def upsert_all_package_scans(purl_to_vuln: dict):
    """
    Persist all scanned packages in one round trip: load existing json, merge vulns in
    Python, then batch upsert via INSERT ... ON CONFLICT (requires unique purl).
    """
    logger.info("Trying to upsert scan data...")
    if not purl_to_vuln:
        logger.info("Failed: purl_to_vuln is empty")
        return

    scanned_at = date.today()
    purls = list(purl_to_vuln.keys())

    existing_stmt = text(
        "SELECT purl, vulnerabilities FROM libinv.all_package_vuln_scans "
        "WHERE purl IN :purls"
    ).bindparams(bindparam("purls", expanding=True))
    existing_rows = conn.execute(existing_stmt, {"purls": purls}).fetchall()
    existing_by_purl = {row[0]: (row[1] or []) for row in existing_rows}

    def _vulns_to_db(vulns: list):
        # Store NULL instead of JSON empty array to avoid lots of `[]` in the DB.
        return json.dumps(vulns) if vulns else None
    batch_size = 10000

    try:
        upsert_stmt = text(
            """
            INSERT INTO libinv.all_package_vuln_scans (purl, vulnerabilities, scanned_at)
            VALUES (:purl, CAST(:vulns AS jsonb), :scanned_at)
            ON CONFLICT (purl) DO UPDATE SET
                vulnerabilities = EXCLUDED.vulnerabilities,
                scanned_at = EXCLUDED.scanned_at
            """
        )

        params = [
            {
                "purl": purl,
                "vulns": _vulns_to_db(merge_vulns(existing_by_purl.get(purl, []), new_vulns)),
                "scanned_at": scanned_at,
            }
            for purl, new_vulns in purl_to_vuln.items()
        ]

        for i in range(0, len(params), batch_size):
            batch = params[i : i + batch_size]
            conn.execute(upsert_stmt, batch)

        conn.commit()
    except Exception as e:
        logger.info(f"Upsert failed: {e}")
        conn.rollback()
    
    logger.info("Successfully updated the package scan data.")


def merge_vulns(existing: list, new: list):
    """
    Merge by vuln id. Keep existing entries, only add new ones.
    If same id exists and new has a later modified time, replace.
    """
    def _parse_dt(s):
        if not s:
            return None
        try:
            return datetime.fromisoformat(s.replace("Z", "+00:00"))
        except Exception:
            return None

    by_id = {}

    for v in existing:
        vid = v.get("id") if isinstance(v, dict) else None
        if not vid:
            continue
        by_id[vid] = v

    for v in new:
        vid = v.get("id") if isinstance(v, dict) else None
        if not vid:
            continue

        if vid not in by_id:
            by_id[vid] = v
            continue

        existing_mod = _parse_dt(by_id[vid].get("modified")) if isinstance(by_id[vid], dict) else None
        new_mod = _parse_dt(v.get("modified")) if isinstance(v, dict) else None

        if new_mod and (not existing_mod or new_mod > existing_mod):
            by_id[vid] = v

    return list(by_id.values())