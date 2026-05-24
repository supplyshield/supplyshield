import json
import logging
from tarfile import TarFile
from typing import List

from sqlalchemy import and_
from sqlalchemy.orm import Session as OrmSession

from libinv.base import conn
from libinv.models import ORGSRE_ACCOUNT_ID
from libinv.models import Image
from libinv.models import Layer
from libinv.scanners.image_scanner.image_tarball import ImageTarBall
from libinv.scanners.image_scanner.logger import logger


def save_layer_information_for_image(session: OrmSession, image: Image, image_tar: ImageTarBall):
    tf = TarFile(image_tar.filename)
    file = tf.extractfile("manifest.json")
    manifest = json.load(file)

    if len(manifest) != 1:
        raise ValueError(
            f"Expected exactly 1 manifest entry, got {len(manifest)}"
        )

    logger.info("Saving layer information")
    manifest = manifest[0]
    layers = manifest["Layers"]
    for seq, layer_entry in enumerate(layers):
        layer_id, _, _ = layer_entry.partition(".tar.gz")
        layer = session.query(Layer).filter_by(image_id=image.id, seq=seq).one_or_none()

        if layer and layer.id == layer_id:
            logger.debug(f"Existing: {image} already has layer {layer}")
        else:
            layer = Layer(image_id=image.id, id=layer_id, seq=seq)
            session.add(layer)
            logger.debug(f"Updated: {image} for layer {layer}")
    session.commit()
    logger.info("Layer information saved")


def detect_and_update_parent_image(image: Image):
    """
    Detects and updates the parent_image field in the database for the given image.
    parent image need not be orgsre image, it can be any other image. For orgsre only parent
    images, see detect_and_update_base_image
    """
    logger.info("Detecting parent image")
    first_layer = image.sorted_layers[0]

    # TODO: check possiblilty of eager loading layers
    # TODO: We can optimize this by only taking orgsre images as candidates but
    # then we will lose ability to detect non-orgsre base images (from within ecr)
    # if it even so happens
    candidates = (
        conn.query(Image)
        .join(Image.layers)
        .filter(
            and_(Layer.id == first_layer.id, Layer.seq == first_layer.seq, Image.id != image.id)
        )
    )

    parent_image = detect_parent_image(image=image, candidates=candidates)
    if not parent_image:
        logging.debug(f"No parent image found for {image}")
        return

    image.parent_image_id = parent_image.id
    conn.add(image)
    conn.commit()
    print(f"[+] parent image updated for: {image} to {parent_image}")


def detect_and_update_base_image(session: OrmSession, image: Image):
    logger.info("Detecting base image")
    try:
        first_layer = image.sorted_layers[0]
    except IndexError:
        logger.warn(f"No layer found for {image} {image.id}")
        return False

    # TODO: check possiblilty of eager loading layers
    candidates = (
        session.query(Image)
        .join(Image.layers)
        .filter(
            and_(
                Layer.id == first_layer.id,
                Layer.seq == first_layer.seq,
                Image.id != image.id,
                Image.account_id == ORGSRE_ACCOUNT_ID,
            )
        )
    )

    base_image = detect_parent_image(image=image, candidates=candidates)
    if not base_image:
        logging.debug(f"No base image found for {image}")
        return False

    image.base_image_id = base_image.id
    session.add(image)
    session.commit()
    print(f"[+] base image updated for: {image} to {base_image}")
    return True


def detect_parent_image(image: Image, candidates: List):
    matching_layer_images = []
    for candidate in candidates:
        logger.debug(f"Trying candidate: {candidate}")
        if candidate.is_parent_image_of(image):
            matching_layer_images.append(candidate)
            logger.debug(f"Matched candidate: {candidate}")

    if not matching_layer_images:
        return

    parent_image = max(matching_layer_images, key=lambda x: len(x.layers))
    logger.debug(f"[+] parent image found: {parent_image}")
    return parent_image
