"""Dataclasses for parsing SBOM metadata files provided by buildprobe."""

from dataclasses import dataclass
from typing import Any, Self

from mobster.error import SBOMError


@dataclass
class ImageData:
    """Image information provided by each entry of SBOMMetadata."""

    pullspec: str
    digest: str

    @classmethod
    def from_dict(cls, data: dict[str, str]) -> Self:
        """Create a new ImageData from a dict."""
        try:
            pullspec = data["pullspec"]
            digest = data["digest"]
            return cls(pullspec, digest)
        except KeyError as e:
            raise SBOMError("invalid pullspec/digest") from e


@dataclass
class SBOMMetadata:
    """Dataclass describing an OCI image and its dependency images."""

    # the OCI image that was built
    image: ImageData
    # images used as base images for builder stages
    # order is significant, last base image is the "parent" image
    base_images: list[ImageData]
    # any extra images to be included in the SBOM
    # such as "external" images (COPY --from=image)
    extra_images: list[ImageData]

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Self:
        """
        Create a new SBOMMetadata from a dict.
        (This also attempts to map any contained ImageData with
        ImageData.from_dict.)
        """
        try:
            image = ImageData.from_dict(data["image"])
        except KeyError as e:
            raise SBOMError("Invalid image in metadata") from e
        base_images = []
        if "base_images" in data:
            for image_data in data["base_images"]:
                base_images.append(ImageData.from_dict(image_data))
        extra_images = []
        if "extra_images" in data:
            for image_data in data["extra_images"]:
                extra_images.append(ImageData.from_dict(image_data))
        return cls(image, base_images, extra_images)
