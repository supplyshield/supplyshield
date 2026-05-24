"""Sprint 32.1 — integration tests for ``libinv.cli.bridge`` ``connect``.

The CLI command ``libinv connect <repositories_dir>`` builds a commit-map
across every git repository under ``<repositories_dir>`` and uses that
map to back-fill ``Image.repository_id`` for Image rows that previously
had ``repository_id=None``.

Scenarios per the row 06 contract:
  1. Happy path — a cloned repo + an Image row whose tag matches a
     commit-id-prefix in the repo → the Image gets a repository_id and
     a corresponding Repository row exists.
  2. VCS clone failure — passing a directory that is NOT a git
     repository: ``build_commit_map_for_one_repository`` swallows the
     ``InvalidGitRepositoryError`` and returns ``{}``. The connect
     command must exit cleanly, no Repository state corruption.
  3. Duplicate commit-map entries — when the same commit-prefix appears
     in MULTIPLE repositories, ``connect_image_with_commit_map`` records
     the collision but still deterministically chooses ``repos[0]`` and
     bridges the Image to that one.

We use ``click.testing.CliRunner`` per the contract. The multiprocess
``process_map`` is patched out to run serially in-process — keeps the
test deterministic and avoids needing a forkable pickle of the
SQLAlchemy session.
"""
from __future__ import annotations

import uuid
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock
from unittest.mock import patch

import pytest


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture(autouse=True)
def _bind_engine(engine, monkeypatch):
    """Rebind libinv.base globals to the integration engine."""
    import libinv.base

    monkeypatch.setattr(libinv.base, "engine", engine)
    libinv.base.Session.configure(bind=engine)
    libinv.base.ScopedSession.configure(bind=engine)
    yield
    libinv.base.ScopedSession.remove()


@pytest.fixture
def runner():
    from click.testing import CliRunner

    return CliRunner()


@pytest.fixture
def cleanup_bridge_rows(engine):
    """Tear down any Repository / Image / Account rows our test created."""
    test_token = uuid.uuid4().hex[:8]
    state = {
        "token": test_token,
        "repository_ids": [],
        "image_ids": [],
        "account_ids": [],
    }
    yield state

    from sqlalchemy.orm import Session

    from libinv.models import Account
    from libinv.models import Image
    from libinv.models import Repository

    with Session(bind=engine) as s:
        if state["image_ids"]:
            s.query(Image).filter(Image.id.in_(state["image_ids"])).delete(
                synchronize_session=False
            )
        if state["repository_ids"]:
            s.query(Repository).filter(
                Repository.id.in_(state["repository_ids"])
            ).delete(synchronize_session=False)
        # Also delete any new Repositories created by the SUT keyed on test_token
        for repo in s.query(Repository).filter(
            Repository.name.like(f"%{test_token}%")
        ).all():
            s.delete(repo)
        if state["account_ids"]:
            s.query(Account).filter(Account.id.in_(state["account_ids"])).delete(
                synchronize_session=False
            )
        s.commit()


def _seed_account_and_image(engine, name: str, tag: str, cleanup_state: dict) -> int:
    """Insert an Image row with repository_id=None. Returns the Image.id.

    Image NOT NULL columns: name, account_id, digest, platform. Account
    NOT NULL columns: account_id, name. We satisfy both.
    """
    from sqlalchemy.orm import Session

    from libinv.models import Account
    from libinv.models import Image

    # Account.id is String(12); use the token (8 hex chars) directly.
    acct_id = cleanup_state["token"][:12]
    with Session(bind=engine) as s:
        acct = Account(id=acct_id, name="bridge-test")
        s.add(acct)
        s.commit()
        cleanup_state["account_ids"].append(acct.id)

        img = Image(
            name=name,
            account_id=acct.id,
            digest=f"sha256:{'b' * 60}",
            tag=tag,
            platform="linux/amd64",
            repository_id=None,
        )
        s.add(img)
        s.commit()
        cleanup_state["image_ids"].append(img.id)
        return img.id


def _fake_git_repo(url: str) -> Any:
    """Build a MagicMock that quacks like git.Repo with ``.remotes.origin.url``."""
    fake = MagicMock()
    fake.remotes.origin.url = url
    return fake


def _serial_process_map(func, *iterables, **kwargs):
    """In-process replacement for ``tqdm.contrib.concurrent.process_map``."""
    return [func(*args) for args in zip(*iterables)]


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
def test_happy_path_image_bridged_to_repository(
    engine, runner, cleanup_bridge_rows, tmp_path, monkeypatch
):
    """Image row with a tag matching a fake commit-map entry → Image.repository_id set."""
    from libinv.models import Repository
    from libinv.models import get_or_create
    from sqlalchemy.orm import Session

    token = cleanup_bridge_rows["token"]
    repo_name = f"bridge-happy-{token}"

    # Pre-create the target Repository so ``get_or_create`` in bridge.py
    # doesn't trip on Repository's NOT NULL ``provider`` / ``org`` columns
    # (the CLI itself only passes ``name=`` — a known limitation of the
    # current command; the bridge then UPDATEs the existing row).
    with Session(bind=engine) as s:
        repo = Repository(name=repo_name, org="bridge-org", provider="github.com")
        s.add(repo)
        s.commit()
        cleanup_bridge_rows["repository_ids"].append(repo.id)
        expected_repo_id = repo.id

    tag = "abc1234567"  # 10 chars — len(image.tag) == 10 gate
    image_id = _seed_account_and_image(engine, "svc-happy", tag, cleanup_bridge_rows)

    # Build a fake commit-map: tag → [fake_repo_pointing_at_repo_name]
    fake_repo = _fake_git_repo(f"git@github.com:bridge-org/{repo_name}.git")
    commit_map = {tag: [fake_repo]}

    # Patch the multiprocess flow with our serial helper + return the
    # commit-map we constructed.
    sub_dir = tmp_path / repo_name
    sub_dir.mkdir()

    from libinv.cli.bridge import connect as connect_cmd

    def _fake_build_map(*_args, **_kwargs):
        return commit_map

    with patch("libinv.cli.bridge.process_map", side_effect=_serial_process_map), patch(
        "libinv.cli.bridge.build_commit_map_for_one_repository",
        side_effect=_fake_build_map,
    ):
        result = runner.invoke(connect_cmd, [str(tmp_path)])

    assert result.exit_code == 0, f"connect failed: {result.output}\n{result.exception}"

    # Image was bridged.
    from libinv.models import Image

    with Session(bind=engine) as s:
        bridged_image = s.query(Image).filter(Image.id == image_id).one()
        assert bridged_image.repository_id is not None, (
            "Image.repository_id was not populated by the connect command"
        )
        # In the happy path, the repository updated is the one matching the
        # fake commit-map (existing repo_name).
        assert bridged_image.repository_id == expected_repo_id


def test_invalid_git_dir_does_not_corrupt_state(
    engine, runner, cleanup_bridge_rows, tmp_path
):
    """Non-git dir in repositories_dir → build_commit_map returns {}; Image
    stays unbridged; no Repository state corrupted.
    """
    from sqlalchemy.orm import Session

    from libinv.models import Image
    from libinv.models import Repository

    token = cleanup_bridge_rows["token"]
    # An Image row, but no commit-map will match it.
    tag = "deadbeef01"  # 10 chars
    image_id = _seed_account_and_image(engine, "svc-noop", tag, cleanup_bridge_rows)

    # repositories_dir contains one subdir that is NOT a git repo.
    sub_dir = tmp_path / f"not-a-repo-{token}"
    sub_dir.mkdir()

    # Count Repository rows before.
    with Session(bind=engine) as s:
        repos_before = s.query(Repository).count()

    from libinv.cli.bridge import connect as connect_cmd

    # Patch process_map to serial AND let build_commit_map_for_one_repository
    # run for real — it must handle the non-git dir gracefully (InvalidGitRepositoryError).
    with patch("libinv.cli.bridge.process_map", side_effect=_serial_process_map):
        result = runner.invoke(connect_cmd, [str(tmp_path)])

    assert result.exit_code == 0, (
        f"connect crashed on a non-git dir: {result.output}\n{result.exception}"
    )

    # Image untouched.
    with Session(bind=engine) as s:
        image_after = s.query(Image).filter(Image.id == image_id).one()
        assert image_after.repository_id is None, (
            "Image was bridged even though no commit-map matched its tag"
        )
        repos_after = s.query(Repository).count()
        assert repos_after == repos_before, (
            "Repository table grew despite no match — state corruption"
        )


def test_duplicate_commit_map_entries_deterministic_resolution(
    engine, runner, cleanup_bridge_rows, tmp_path
):
    """When the same commit prefix appears in multiple fake repos, the SUT:

    * records the collision (logged via ``click.echo``), AND
    * deterministically picks ``repos[0]`` and bridges Image to it.

    We assert (a) exit_code==0 and (b) Image.repository_id is one of the
    candidate repos' IDs (we make BOTH candidates pre-exist so the
    get_or_create path is a clean UPDATE).
    """
    from sqlalchemy.orm import Session

    from libinv.models import Image
    from libinv.models import Repository

    token = cleanup_bridge_rows["token"]
    primary_name = f"bridge-primary-{token}"
    secondary_name = f"bridge-secondary-{token}"

    with Session(bind=engine) as s:
        primary = Repository(name=primary_name, org="ada", provider="github.com")
        secondary = Repository(name=secondary_name, org="cyrus", provider="github.com")
        s.add_all([primary, secondary])
        s.commit()
        cleanup_bridge_rows["repository_ids"].extend([primary.id, secondary.id])
        primary_id = primary.id

    tag = "cafe123456"  # 10 chars
    image_id = _seed_account_and_image(engine, "svc-dup", tag, cleanup_bridge_rows)

    # Two repos collide on the same tag prefix.
    fake_primary = _fake_git_repo(f"git@github.com:ada/{primary_name}.git")
    fake_secondary = _fake_git_repo(f"git@github.com:cyrus/{secondary_name}.git")
    commit_map = {tag: [fake_primary, fake_secondary]}

    sub_dir = tmp_path / "collide"
    sub_dir.mkdir()

    from libinv.cli.bridge import connect as connect_cmd

    with patch("libinv.cli.bridge.process_map", side_effect=_serial_process_map), patch(
        "libinv.cli.bridge.build_commit_map_for_one_repository",
        return_value=commit_map,
    ):
        result = runner.invoke(connect_cmd, [str(tmp_path)])

    assert result.exit_code == 0, (
        f"connect crashed on duplicate commit-map entries: {result.output}\n"
        f"{result.exception}"
    )
    # Collision must be reported in the output.
    assert "Collisions" in result.output

    # Image was bridged to repos[0] (deterministic — primary).
    with Session(bind=engine) as s:
        image_after = s.query(Image).filter(Image.id == image_id).one()
        assert image_after.repository_id == primary_id, (
            f"Expected Image bridged to primary repo {primary_id}, "
            f"got {image_after.repository_id}"
        )


def test_short_tag_is_skipped(engine, runner, cleanup_bridge_rows, tmp_path):
    """Sanity test on the ``len(image.tag) != 10`` guard at bridge.py:64.

    An image with a non-10-char tag must NOT be bridged, even if the
    commit-map contains a matching prefix.
    """
    from sqlalchemy.orm import Session

    from libinv.models import Image

    image_id = _seed_account_and_image(
        engine, "svc-short", "abc", cleanup_bridge_rows
    )

    # commit_map has 10-char keys, our image has a 3-char tag → no match.
    commit_map = {"abc1234567": [_fake_git_repo("git@github.com:org/anything.git")]}

    sub_dir = tmp_path / "short"
    sub_dir.mkdir()

    from libinv.cli.bridge import connect as connect_cmd

    with patch("libinv.cli.bridge.process_map", side_effect=_serial_process_map), patch(
        "libinv.cli.bridge.build_commit_map_for_one_repository",
        return_value=commit_map,
    ):
        result = runner.invoke(connect_cmd, [str(tmp_path)])

    assert result.exit_code == 0
    with Session(bind=engine) as s:
        img = s.query(Image).filter(Image.id == image_id).one()
        assert img.repository_id is None
