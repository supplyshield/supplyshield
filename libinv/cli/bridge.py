from __future__ import annotations

import itertools
import logging
from collections import defaultdict
from pathlib import Path
from typing import Any

import click
from git import InvalidGitRepositoryError
from git import Repo
from tqdm.contrib.concurrent import process_map
from tqdm.contrib.logging import logging_redirect_tqdm

from libinv.base import Session
from libinv.cli.cli import cli
from libinv.models import Image
from libinv.models import Repository
from libinv.models import get_or_create

logger = logging.getLogger("bridge")


@cli.command()
@click.argument("repositories_dir", type=click.Path(exists=True))
def connect(repositories_dir: str) -> None:
    """
    Retrive tags from each Image in the database for which repository is not present and populate it
    by looking at corresponding tag in repositories_dir
    """
    conn = Session()
    images = list(
        conn.query(Image.name, Image.tag)
        .filter_by(repository_id=None)
        .group_by(Image.name, Image.tag)
    )
    click.echo(f"Found {len(images)} images (by name and tag) without any repository")
    with logging_redirect_tqdm():
        click.echo("Building unit commit maps")
        dirs = list(Path(repositories_dir).iterdir())
        unit_commit_maps = process_map(build_commit_map_for_one_repository, dirs, chunksize=50)
        click.echo("Combining unit commit maps")
        commit_map = defaultdict(list)  # 10-commit: [repo,names]
        for unit_commit_map in unit_commit_maps:
            for commit in unit_commit_map:
                commit_map[commit].extend(unit_commit_map[commit])

        click.echo("Connecting images to repositories")
        commit_map_it = (commit_map for _ in range(len(images)))
        unit_collisions = process_map(
            connect_image_with_commit_map, images, commit_map_it, chunksize=100
        )
        collisions = list(itertools.chain(*unit_collisions))
        click.echo("Collisions: ")
        for commit, repos in collisions:
            for repo in repos:
                click.echo(f"{commit}\t{repo.remotes.origin.url}")


def connect_image_with_commit_map(image: Any, commit_map: dict[str, list[Any]]) -> list[Any]:
    collisions = []
    conn = Session()
    logger.info(f"Processing {image.name} with tag {image.tag}")
    if not image.tag or len(image.tag) != 10:
        logger.info("Tag length is not equal to 10, skipping")
        return collisions

    repos = commit_map.get(image.tag)
    if not repos:
        logger.info(f"[-] Could not find repository for {image.name}")
        return collisions
    if len(repos) > 1:
        collisions.append((image.tag, repos))

    repo = repos[0]
    repo_name = repo.remotes.origin.url.split(".git")[0].split("/")[-1]
    repository, created = get_or_create(conn, Repository, name=repo_name)

    if created:
        logger.debug(f"Inserted new repository: {repository}")
    else:
        logger.debug(f"Existing repository: {repository}")

    image_instances = list(conn.query(Image).filter_by(name=image.name, tag=image.tag))
    for image_instance in image_instances:
        image_instance.repository_id = repository.id
        conn.add(image_instance)
    conn.commit()
    logger.info(f"[+] Populated repository for {len(image_instances)} {image.name} instances")

    return collisions


def build_commit_map_for_one_repository(
    repository_dir: Path, commit_id_len: int = 10
) -> dict[str, list[Any]]:
    commit_map = {}
    if not repository_dir.is_dir():
        return {}

    try:
        repo = Repo(repository_dir)
    except InvalidGitRepositoryError:
        return {}

    for commit in repo.iter_commits("--all"):
        commit_map[str(commit)[:commit_id_len]] = [repo]
    return commit_map
