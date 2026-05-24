# ScanCode.io HTTP Contract (Sprint 14 Scaffolding)

## Goal

Replace the SQL-reflection coupling in `libinv/scio_models.py` — which
introspects the `scanpipe_project` and `scanpipe_discoveredpackage` tables at
module-import time via `sqlalchemy.inspect(engine).has_table(...)` — with a
typed HTTP contract against scancodeio's REST API. The reflection makes
libinv silently fragile: any upstream migration to the `scanpipe_*` schema
breaks libinv at import without a compile-time signal.

This sprint delivers **scaffolding only**. No caller is migrated; no real
HTTP call is issued. The new `libinv/services/scancodeio_client.py`
defines the contract and stubs every method with `NotImplementedError`.

## Current state — catalog of scanpipe_* hits in libinv

A grep across `libinv/**/*.py` for `DiscoveredPackage`, `ScanpipeProject`,
and `scanpipe_` returns 28 hits, broken down by access pattern:

### Classification A — plain ORM on `DiscoveredPackage`

Easy to replace with a single client call.

| File | Lines | Query |
|---|---|---|
| `libinv/models.py` | 1175-1195 | `func.sum(func.jsonb_array_length(...))` filtered by `project_id` — total vuln count |
| `libinv/models.py` | 1372-1379 | `session.query(DiscoveredPackage).filter(project_id=uuid).all()` — used by `get_cves` |
| `libinv/cli/epss.py` | 63-67   | Same shape — per-project listing, drives the EPSS update loop |
| `libinv/cli/epss.py` | 197-202 | Same shape — re-issued inside `calculate-package-epss` |
| `libinv/api/actionable/package_details.py` | 72-76 | Same shape — per-package CVE drill-down endpoint |

### Classification B — raw `text(...)` SQL

Needs either an aggregate endpoint upstream or client-side aggregation.

| File | Lines | Query |
|---|---|---|
| `libinv/models.py` | 1199-1240 | Recursive CTE bucketing `affected_by_vulnerabilities` into `critical/high/medium/low/unknown` |
| `libinv/api/compare_builds.py` | 31-43 | Raw SELECT joining `scanpipe_project sp` and `scanpipe_discoveredpackage sd` on wasp |
| `libinv/api/compare_builds.py` | 82-89 | ORM JOIN `Wasp ↔ ScanpipeProject` on `wasp_uuid_id` |

### Classification C — import-time reflection

Disappears entirely once HTTP replaces SQL.

| File | Lines |
|---|---|
| `libinv/scio_models.py` | 10-36 — both `ScanpipeProject` and `DiscoveredPackage` reflected |
| `libinv/conftest.py` | 10-11 — `MagicMock` shims used by pytest |
| `libinv/models.py` | 68-70 — fallback `DiscoveredPackage = None` when reflection fails |

Total: **5 hits in A**, **3 hits in B**, **3 hits in C**. (The remaining
hits are comments, log strings, and imports of the classification-C names.)

## Proposed contract

All methods live on `libinv.services.scancodeio_client.ScancodeioClient`.

| Method | Replaces | Returns |
|---|---|---|
| `get_project(project_uuid)` | reflected `ScanpipeProject` access | `ScanpipeProjectDTO` |
| `list_projects_for_wasp(wasp_uuid)` | `Wasp.join(ScanpipeProject)` in `compare_builds.py` | `list[ScanpipeProjectDTO]` |
| `list_discovered_packages(project_uuid, only_vulnerable=False)` | classification-A queries | `list[DiscoveredPackageDTO]` |
| `iter_discovered_packages(project_uuid, only_vulnerable=False)` | EPSS batch loops | `Iterable[DiscoveredPackageDTO]` |
| `get_severity_counts(project_uuid)` | recursive-CTE query in `models.py` | `list[SeverityCountDTO]` |
| `get_vulnerability_count(project_uuid)` | `_get_vulnerabilities_count` jsonb-sum query | `int` |
| `list_cve_ids_for_project(project_uuid)` | EPSS + `package_details.py` CVE-extract loops | `list[str]` |

The TypedDicts (`DiscoveredPackageDTO`, `ScanpipeProjectDTO`,
`SeverityCountDTO`) sit on the same module and document the exact field
subset libinv consumes — they are deliberately **narrower** than the
upstream DRF serializer to keep the contract small.

### Endpoint mapping

Verified against `scancode.io/scanpipe/api/views.py::ProjectViewSet`:

- `get_project` → `GET /api/projects/<uuid>/`
- `list_discovered_packages` / `iter_discovered_packages` →
  `GET /api/projects/<uuid>/packages/` (paginated, follow `next`)
- `list_projects_for_wasp` → `GET /api/projects/?wasp_uuid_id=<uuid>`
  (the filter does **not** exist upstream today — see Open Questions)
- `get_severity_counts`, `get_vulnerability_count`,
  `list_cve_ids_for_project` → derived client-side from the
  `packages/` endpoint until/unless dedicated aggregate endpoints land

## Migration plan

1. **Sprint 14 (this sprint):** scaffold the client and document the
   contract. Nothing else changes; `LIBINV_SCIO_USE_HTTP` defaults to
   off and `get_default_client()` returns `None`.
2. **Sprint 15:** implement real HTTP behind each method, with pagination,
   retries, and a recorded-cassette test suite. Keep both paths live —
   each call site checks `get_default_client()`; if `None`, fall back to
   the existing SQL/ORM path.
3. **Sprint 15 cont.:** migrate the five Classification-A call sites one
   at a time, each behind its own PR, with the env flag flipped on in
   staging only.
4. **Sprint 16:** migrate the three Classification-B sites; this is the
   harder cut because of the wasp join and the severity CTE.
5. **Sprint 16:** flip `LIBINV_SCIO_USE_HTTP=true` as the default; keep
   the SQL fallback for one release cycle to roll back fast.
6. **Sprint 17:** delete `libinv/scio_models.py`, drop the
   `DiscoveredPackage`/`ScanpipeProject` imports across the codebase,
   and remove the `conftest.py` mocks.

## Open questions

1. **`wasp_uuid_id` filter.** `scanpipe_project.wasp_uuid_id` is a
   SupplyShield-specific column. Does it already appear in upstream's
   `ProjectFilterSet`, or do we need a patch (and if so, fork or PR
   upstream)?
2. **Severity aggregate.** Should `get_severity_counts` be a dedicated
   upstream endpoint (faster, fewer round-trips) or client-side
   aggregation (zero upstream coupling)? The current CTE is fast
   because the DB does the JSONB work; pulling N packages back over
   HTTP just to count `CRITICAL/HIGH/...` substrings may regress.
3. **Pagination defaults.** Upstream uses DRF's default page size (50?
   100?). Some projects in production have >10k discovered packages —
   `iter_discovered_packages` is mandatory; `list_*` will need a page
   size cap to avoid OOM.
4. **Auth.** Token auth via `Authorization: Token <key>` is assumed.
   Confirm that's how staging is configured before Sprint 15.
5. **Concurrency.** Should the client hold a single `requests.Session`
   for the process, or one per request? The EPSS batch job is the
   hot path and benefits from connection reuse.
6. **Error semantics.** Today an SQL failure raises
   `SQLAlchemyError`. The HTTP path will raise `requests.HTTPError` —
   callers that swallow `SQLAlchemyError` need updating; that audit is
   part of Sprint 15.
