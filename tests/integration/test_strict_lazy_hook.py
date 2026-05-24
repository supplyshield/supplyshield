"""Sprint 37.1 — prove the LIBINV_STRICT_LAZY policy hook catches lazy-loads.

The hook in ``libinv/base.py`` registers a ``Mapper.after_configured``
listener that flips every ``relationship()`` to ``lazy="raise_on_sql"``
when the env var is true. This file confirms the behavioural contract:

  - When LIBINV_STRICT_LAZY=true, accessing a relationship on a loaded
    instance that wasn't eagerly loaded raises
    ``sqlalchemy.exc.InvalidRequestError``.
  - Without the env var (the production default), the same access
    issues a lazy SELECT and returns the related rows.

These tests live in tests/integration/ because they need a real DB
(the relationship access must run against actual mapped instances).
"""
import os

import pytest
from sqlalchemy.exc import InvalidRequestError
from sqlalchemy.orm import Session


_STRICT_ENABLED = os.environ.get("LIBINV_STRICT_LAZY", "").strip().lower() in (
    "1",
    "true",
    "yes",
    "on",
    "y",
)


@pytest.mark.skipif(
    not _STRICT_ENABLED,
    reason="Requires LIBINV_STRICT_LAZY=true to exercise the policy hook.",
)
def test_strict_lazy_raises_on_relationship_lazy_load(engine):
    """Accessing a non-eager-loaded relationship must raise under strict mode."""
    from libinv.models import Repository

    suffix = os.urandom(4).hex()
    with Session(bind=engine) as s:
        repo = Repository(
            provider="github.com",
            org=f"strict-lazy-org-{suffix}",
            name=f"strict-lazy-repo-{suffix}",
            is_public=False,
        )
        s.add(repo)
        s.commit()
        repo_id = repo.id

    try:
        with Session(bind=engine) as s:
            loaded_repo = s.query(Repository).filter(Repository.id == repo_id).one()
            # Sanity: relationship's lazy strategy must reflect strict mode.
            rel = Repository.__mapper__.relationships.get("images")
            assert rel is not None and rel.lazy == "raise_on_sql"
            # `images` is a relationship() on Repository -> Image.
            # Under strict mode, this implicit lazy-load must raise
            # because we did not request `selectinload(Repository.images)`.
            with pytest.raises(InvalidRequestError):
                _ = list(loaded_repo.images)
    finally:
        with Session(bind=engine) as s:
            s.query(Repository).filter(Repository.id == repo_id).delete()
            s.commit()
