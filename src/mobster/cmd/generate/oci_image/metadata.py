"""Pydantic classes for parsing SBOM metadata files."""

from pydantic import BaseModel, Field, model_validator

from mobster.image import DIGEST_PATTERN, PULLSPEC_DIGEST_PATTERN, Image


class ImageData(BaseModel):
    """Image information provided by each entry of SBOMMetadata."""

    pullspec: str = Field(pattern=PULLSPEC_DIGEST_PATTERN)
    digest: str = Field(pattern=DIGEST_PATTERN)

    @model_validator(mode="after")
    def _strip_digest_from_pullspec(self) -> "ImageData":
        if "@" in self.pullspec:
            self.pullspec = self.pullspec.split("@")[0]
        return self

    def to_image(self, arch: str | None = None) -> Image:
        # if the pullspec has a tag then we need to use
        # from_image_index_url_and_digest to init
        if ":" in self.pullspec:
            return Image.from_image_index_url_and_digest(
                self.pullspec, self.digest, arch
            )
        # otherwise we can just init directly w/o a class method
        return Image(self.pullspec, self.digest, arch=arch)


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
