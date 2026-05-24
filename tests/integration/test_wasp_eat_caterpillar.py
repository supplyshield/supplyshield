"""Sprint 32.3 — integration tests for ``Wasp.eat_caterpillar_message``.

The SQS message parser is the entry point for every build event the system
ingests. It validates the message JSON-schema, gates on the excluded-repo
list, creates / fetches the ``Repository`` row, then inserts a ``Wasp`` row
to record the eaten message.

Coverage (≥6 SQS message shapes per the plan):
  1. Well-formed message → one Wasp row, repository linked.
  2. Missing required top-level key (``aws_environment``) → ``MalformedCaterpillarMessage``.
  3. Missing required nested key (``repository.url``) → ``MalformedCaterpillarMessage``.
  4. Unknown event type (``type`` field is not 'Bridge') → still well-formed,
     accepted as-is (the parser does not gate on ``type``); a Wasp row is
     written so we know the schema is permissive here.
  5. Malformed JSON-shape (top-level is a list, not an object) →
     ``MalformedCaterpillarMessage``.
  6. Duplicate message: feeding the same payload twice produces TWO Wasp
     rows but only ONE Repository (the ``Wasp.uuid`` differs each call
     because of the ``default=uuid4`` server default — that's the
     documented "duplicate message-id" outcome).
  7. Very-large payload: a 2KB-ish ``commit_author`` body should still be
     accepted (``raw_message`` is a 2048-char column; we stay under that
     limit so the parser doesn't slice).
  8. Excluded-repo gate: when the repo URL falls in ``EXCLUDED_REPOS``,
     ``eat_caterpillar_message`` returns ``None`` and writes nothing.
"""
from __future__ import annotations

import copy
import json
from unittest.mock import patch

import pytest


@pytest.fixture(autouse=True)
def patch_engine(engine, monkeypatch):
    """Rebind ``libinv.base`` globals to the integration DB engine."""
    import libinv.base

    monkeypatch.setattr(libinv.base, "engine", engine)
    libinv.base.Session.configure(bind=engine)
    libinv.base.ScopedSession.configure(bind=engine)
    yield
    libinv.base.ScopedSession.remove()


@pytest.fixture
def cleanup_wasps_and_repos(engine):
    """After each test, delete any Wasp + Repository rows we created."""
    test_repo_names = {"libinv-wasp-tests"}
    yield test_repo_names

    from sqlalchemy.orm import Session

    from libinv.models import Repository
    from libinv.models import Wasp

    with Session(bind=engine) as s:
        # Wasps point at the repository — delete them first.
        repos = (
            s.query(Repository).filter(Repository.name.in_(list(test_repo_names))).all()
        )
        repo_ids = [r.id for r in repos]
        if repo_ids:
            s.query(Wasp).filter(Wasp.repository_id.in_(repo_ids)).delete(
                synchronize_session=False
            )
            for r in repos:
                s.delete(r)
            s.commit()


def _baseline_message() -> dict:
    """A well-formed metapod / wasp payload (mirrors the docstring example)."""
    return {
        "repository": {
            "url": "git@github.com:acme/libinv-wasp-tests.git",
            "commit": "0" * 40,
            "tag": "v1.0.0",
        },
        "aws_environment": "stage",
        "job_url": "https://jenkins.example/build/1",
        "buildx_enabled": "1",
        "type": "Bridge",
        "timestamp": "2024-09-20-03:45:42",
        "ecr_image": [
            {
                "name": "111.dkr.ecr.ap-south-1.amazonaws.com/svc",
                "digest": "sha256:" + ("0" * 64),
                "type": "Image",
                "platform": {"architecture": "amd64", "os": "linux"},
            }
        ],
    }


def _new_session(engine):
    from sqlalchemy.orm import Session

    return Session(bind=engine)


# ---------------------------------------------------------------------------
# Scenario 1 — well-formed message
# ---------------------------------------------------------------------------
def test_well_formed_message_creates_wasp_and_repository(
    engine, cleanup_wasps_and_repos
):
    from libinv.models import Repository
    from libinv.models import Wasp

    msg = _baseline_message()
    with _new_session(engine) as s:
        wasp = Wasp.eat_caterpillar_message(msg, session=s)
        assert wasp is not None
        assert wasp.environment == "stage"
        assert wasp.commit == "0" * 40
        assert wasp.tag == "v1.0.0"
        assert wasp.jenkins_url == "https://jenkins.example/build/1"
        assert wasp.ate_successfully is True
        # raw_message must round-trip the original payload.
        assert json.loads(wasp.raw_message) == msg
        # Repository was linked.
        assert wasp.repository is not None
        assert wasp.repository.name == "libinv-wasp-tests"
        assert wasp.repository.provider == "github.com"
        assert wasp.repository.org == "acme"

    # And from a fresh session, one row exists.
    with _new_session(engine) as s2:
        repo = (
            s2.query(Repository).filter(Repository.name == "libinv-wasp-tests").one()
        )
        assert (
            s2.query(Wasp).filter(Wasp.repository_id == repo.id).count() == 1
        )


# ---------------------------------------------------------------------------
# Scenario 2 — missing required top-level key
# ---------------------------------------------------------------------------
def test_missing_required_top_level_key_raises_malformed(engine, cleanup_wasps_and_repos):
    from libinv.exceptions import MalformedCaterpillarMessage
    from libinv.models import Repository
    from libinv.models import Wasp

    msg = _baseline_message()
    del msg["aws_environment"]  # required by schema → ValidationError → False
    with _new_session(engine) as s:
        with pytest.raises(MalformedCaterpillarMessage):
            Wasp.eat_caterpillar_message(msg, session=s)
        # No partial state — scope the assertion to OUR test repository so
        # other tests' rows in the shared DB don't pollute the check.
        repo_id_subq = (
            s.query(Repository.id)
            .filter(Repository.name.in_(list(cleanup_wasps_and_repos)))
            .subquery()
        )
        assert s.query(Wasp).filter(Wasp.repository_id.in_(repo_id_subq)).count() == 0


# ---------------------------------------------------------------------------
# Scenario 3 — missing required nested key
# ---------------------------------------------------------------------------
def test_missing_required_nested_key_raises_malformed(engine, cleanup_wasps_and_repos):
    from libinv.exceptions import MalformedCaterpillarMessage
    from libinv.models import Wasp

    msg = _baseline_message()
    del msg["repository"]["url"]  # required inside the nested schema
    with _new_session(engine) as s:
        with pytest.raises(MalformedCaterpillarMessage):
            Wasp.eat_caterpillar_message(msg, session=s)


# ---------------------------------------------------------------------------
# Scenario 4 — unknown event type still parses (schema is permissive on `type`)
# ---------------------------------------------------------------------------
def test_unknown_event_type_still_accepted(engine, cleanup_wasps_and_repos):
    """The schema marks ``type`` as a free-form string. The parser should
    accept arbitrary values — there's no allow-list. We assert the row was
    written so a future regression that *adds* gating is detected here.
    """
    from libinv.models import Wasp

    msg = _baseline_message()
    msg["type"] = "SomeFutureEvent"
    with _new_session(engine) as s:
        wasp = Wasp.eat_caterpillar_message(msg, session=s)
        assert wasp is not None
        assert wasp.raw_message  # was persisted


# ---------------------------------------------------------------------------
# Scenario 5 — wrong top-level JSON shape
# ---------------------------------------------------------------------------
def test_top_level_list_is_malformed(engine, cleanup_wasps_and_repos):
    from libinv.exceptions import MalformedCaterpillarMessage
    from libinv.models import Wasp

    # The schema requires ``type == 'object'`` at the top level. A list
    # fails validation immediately.
    with _new_session(engine) as s:
        with pytest.raises(MalformedCaterpillarMessage):
            Wasp.eat_caterpillar_message([1, 2, 3], session=s)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Scenario 6 — duplicate payload yields TWO Wasp rows (the parser is not
# message-id-dedup'd; each eaten message is its own row).
# ---------------------------------------------------------------------------
def test_duplicate_payload_creates_distinct_wasp_rows(engine, cleanup_wasps_and_repos):
    from libinv.models import Repository
    from libinv.models import Wasp

    msg = _baseline_message()
    # Snapshot scalar attrs *inside* the session — once the session closes
    # the instance is detached and attribute access triggers a refresh
    # against a now-closed session (DetachedInstanceError).
    with _new_session(engine) as s:
        w1 = Wasp.eat_caterpillar_message(copy.deepcopy(msg), session=s)
        w2 = Wasp.eat_caterpillar_message(copy.deepcopy(msg), session=s)
        assert w1 is not None
        assert w2 is not None
        w1_uuid, w2_uuid = w1.uuid, w2.uuid
        w1_id, w2_id = w1.id, w2.id

    assert w1_uuid != w2_uuid  # default=uuid4 → unique
    assert w1_id != w2_id

    with _new_session(engine) as s2:
        repo = (
            s2.query(Repository).filter(Repository.name == "libinv-wasp-tests").one()
        )
        assert s2.query(Wasp).filter(Wasp.repository_id == repo.id).count() == 2


# ---------------------------------------------------------------------------
# Scenario 7 — very-large payload (under the 2048-char raw_message column).
# ---------------------------------------------------------------------------
def test_large_payload_under_column_limit_is_accepted(engine, cleanup_wasps_and_repos):
    from libinv.models import Wasp

    msg = _baseline_message()
    # Keep total raw_message size < 2048 chars to fit the column.
    # The schema allows ``commit_author`` so we use that as filler.
    msg["repository"]["commit_author"] = "alice" * 200  # 1000 chars
    with _new_session(engine) as s:
        wasp = Wasp.eat_caterpillar_message(msg, session=s)
        assert wasp is not None
        assert len(wasp.raw_message) > 1000


# ---------------------------------------------------------------------------
# Scenario 8 — excluded-repo gate
# ---------------------------------------------------------------------------
def test_excluded_repo_returns_none_and_writes_nothing(
    engine, cleanup_wasps_and_repos, monkeypatch
):
    from libinv.models import Repository
    from libinv.models import Wasp

    msg = _baseline_message()
    # Stub the exclusion predicate to True so we don't have to mutate the
    # env var which is parsed at import time.
    with patch("libinv.models.is_excluded_repo", return_value=True):
        with _new_session(engine) as s:
            result = Wasp.eat_caterpillar_message(msg, session=s)
            assert result is None
            # No partial state for THIS test's repo (other tests share the DB).
            repo_id_subq = (
                s.query(Repository.id)
                .filter(Repository.name.in_(list(cleanup_wasps_and_repos)))
                .subquery()
            )
            assert (
                s.query(Wasp).filter(Wasp.repository_id.in_(repo_id_subq)).count() == 0
            )


# ---------------------------------------------------------------------------
# Scenario 9 — additional shape coverage: missing `repository` key entirely
# ---------------------------------------------------------------------------
def test_missing_repository_object_raises_malformed(engine, cleanup_wasps_and_repos):
    from libinv.exceptions import MalformedCaterpillarMessage
    from libinv.models import Wasp

    msg = _baseline_message()
    del msg["repository"]
    with _new_session(engine) as s:
        with pytest.raises(MalformedCaterpillarMessage):
            Wasp.eat_caterpillar_message(msg, session=s)
