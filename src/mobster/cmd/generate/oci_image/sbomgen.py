from dataclasses import dataclass

@dataclass
class ImageData:
    pullspec: str
    digest: str

    @classmethod
    def from_dict(cls, data: dict):
        try:
            pullspec = data["pullspec"]
            digest = data["digest"]
            return cls(pullspec, digest)
        except KeyError:
            raise Exception("invalid pullspec/digest")

@dataclass
class SBOMMetadata:
    # the image that was built
    image: ImageData
    # images used as base images for builder stages
    # order is significant, last base image is the "parent" image
    base_images: list[ImageData]
    # any extra images to be included in the SBOM
    # such as "external" images (COPY --from=image)
    extra_images: list[ImageData]

    @classmethod
    def from_dict(cls, data: dict):
        try:
            image = ImageData.from_dict(data["image"])
        except KeyError:
            raise Exception("Invalid image in metadata")
        base_images = []
        if "base_images" in data:
            for image_data in data["base_images"]:
                base_images.append(ImageData.from_dict(image_data))
        extra_images = []
        if "extra_images" in data:
            for image_data in data["extra_images"]:
                extra_images.append(ImageData.from_dict(image_data))
        return cls(image, base_images, extra_images)
