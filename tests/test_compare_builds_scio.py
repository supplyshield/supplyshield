"""Sprint 23 — documents why compare_builds.py can't yet migrate to HTTP."""


def test_compare_builds_documents_scio_migration_blocker():
    """The route must document why the wasp_uuid_id query can't go via HTTP."""
    import pathlib
    src = pathlib.Path("libinv/api/compare_builds.py").read_text(encoding="utf-8")
    # The blocker note must mention wasp_uuid_id and ProjectFilterSet.
    assert "wasp_uuid_id" in src
    assert "ProjectFilterSet" in src or "upstream" in src
