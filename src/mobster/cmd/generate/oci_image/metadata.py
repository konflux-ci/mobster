"""Pydantic classes for parsing SBOM metadata files."""
import pydantic


class ImageData(pydantic.BaseModel):
    """Image information provided by each entry of SBOMMetadata."""

    pullspec: str
    digest: str


class SBOMMetadata(pydantic.BaseModel):
    """Dataclass describing an OCI image and its dependency images."""

    # the OCI image that was built
    image: ImageData
    # images used as base images for builder stages
    # order is significant, last base image is the "parent" image
    base_images: list[ImageData] = []
    # any extra images to be included in the SBOM
    # such as "external" images (COPY --from=image)
    extra_images: list[ImageData] = []
