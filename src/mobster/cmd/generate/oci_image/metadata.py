"""Pydantic classes for parsing SBOM metadata files."""

from mobster.image import PULLSPEC_PATTERN, DIGEST_PATTERN
from pydantic import BaseModel, Field

class ImageData(BaseModel):
    """Image information provided by each entry of SBOMMetadata."""

    pullspec: str = Field(pattern=PULLSPEC_PATTERN)
    digest: str = Field(pattern=DIGEST_PATTERN)


class SBOMMetadata(BaseModel):
    """Dataclass describing an OCI image and its dependency images."""

    # the OCI image that was built
    image: ImageData
    # images used as base images for builder stages
    # order is significant, last base image is the "parent" image
    base_images: list[ImageData] = []
    # any extra images to be included in the SBOM
    # such as "external" images (COPY --from=image)
    extra_images: list[ImageData] = []
