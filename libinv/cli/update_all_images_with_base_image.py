from __future__ import annotations

from typing import Any

from tqdm.contrib.concurrent import process_map

from libinv import Image
from libinv import Session
from libinv import detect_and_update_base_image
from libinv.cli.cli import cli


def detect_and_update_base_image_by_id(image_id: int) -> Any:
    with Session() as session:
        image = Image.get_by_id(session, image_id)
        return detect_and_update_base_image(session, image)


@cli.command()
def update_all_images_with_base_images() -> None:
    """
    Trigger this when a new base image is introduced and we didn't know about it earlier.
    """
    session = Session()
    image_ids = Image.get_all_dev_image_ids(session)
    process_map(detect_and_update_base_image_by_id, image_ids, chunksize=100)
