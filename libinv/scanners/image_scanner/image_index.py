from typing import Iterator
from typing import Optional

from attrs import define

from libinv.scanners.image_scanner.ecr import EcrClient
from libinv.scanners.image_scanner.image_tarball import ImageNotFoundException
from libinv.scanners.image_scanner.image_tarball import ImageTarBall
from libinv.scanners.image_scanner.logger import logger


@define
class ImageIndex:
    """
    Implement this to vaguely represent multi arch ImageIndex
    """

    registry: str
    name: str
    digest: Optional[str] = None
    tag: Optional[str] = None
    insecure: Optional[bool] = False

    def __str__(self):
        name = f"{self.registry}/{self.name}"
        if self.tag:
            name += f":{self.tag}"
        if self.digest:
            name += f"@{self.digest}"
        return name

    def get_platforms(self):
        # TODO: Implement this properly
        yield "linux/arm64"
        yield "linux/amd64"

    def pull_images_if_not_exist(self) -> Iterator["ImageTarBall"]:
        for platform in self.get_platforms():
            logger.info(f"Pulling image {self} for {platform}")
            try:
                yield ImageTarBall(
                    registry=self.registry,
                    name=self.name,
                    digest=self.digest,
                    tag=self.tag,
                    platform=platform,
                    insecure=self.insecure,
                )
            except ImageNotFoundException as exc:
                if exc.is_invalid_arch:
                    logger.info(f"Invalid guess {platform}, continuing")
                    continue
                raise


class AWSImageIndex(ImageIndex):
    """
    Vaguely represents AWS multi arch ImageIndex
    """

    boto3_ecr_client = None

    def __init__(self, *, boto3_ecr_client, account_id, name, digest):
        # login to ecr
        self.boto3_ecr_client = boto3_ecr_client
        ecr_client = EcrClient(boto3_ecr_client=boto3_ecr_client)
        super().__init__(registry=ecr_client.registry, name=name, digest=digest)
        self.fetch_tag()

    def fetch_tag(self, local_install=False):
        """
        Return tag from AWS ECR, also populate the tag in ImageIndex
        """
        logger.debug(f"Querying AWS ECR for image tag for {self}")
        registryId, _, _ = self.registry.partition(".")
        description = self.boto3_ecr_client.describe_images(
            registryId=registryId,
            repositoryName=self.name,
            imageIds=[
                {"imageDigest": self.digest},
            ],
        )
        # Above query will match exactly one image with exactly one tag
        try:
            tag = description["imageDetails"][0]["imageTags"][0]
            self.tag = tag
            logger.debug(f"[+] Image tag found, tag: {self.tag}")
            return tag
        except KeyError:
            logger.debug("Tag not found")


class ORGSREImageIndex(ImageIndex):
    def __init__(self, *, name, tag):
        # auth somehow
        registry = None
        super().__init__(registry=registry, name=name, tag=tag, insecure=True)


class DockerHubImageIndex(ImageIndex):
    def __init__(self, *, name, tag):
        registry = "registry.hub.docker.com"
        super().__init__(registry=registry, name=name, tag=tag, insecure=True)
