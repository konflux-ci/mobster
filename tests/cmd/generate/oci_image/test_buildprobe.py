import pytest

from mobster.cmd.generate.oci_image.buildprobe import ImageData, SBOMMetadata
from mobster.error import SBOMError


def test_imagedata_ok() -> None:
    pullspec = "quay.io/asdf:123"
    digest = "sha256:1234567890123456789012345678901212345678901234567890123456789012"
    imagedata = ImageData.from_dict(
        {
            "pullspec": pullspec,
            "digest": digest,
        }
    )
    assert imagedata.pullspec == pullspec
    assert imagedata.digest == digest


def test_imagedata_bad() -> None:
    with pytest.raises(SBOMError):
        ImageData.from_dict({})


def test_sbommetadata_ok() -> None:
    pullspec = "quay.io/asdf:123"
    digest = "sha256:1234567890123456789012345678901212345678901234567890123456789012"
    sbom_metadata = SBOMMetadata.from_dict(
        {
            "image": {
                "pullspec": pullspec,
                "digest": digest,
            },
            "base_images": [
                {
                    "pullspec": pullspec,
                    "digest": digest,
                }
            ],
            "extra_images": [
                {
                    "pullspec": pullspec,
                    "digest": digest,
                }
            ],
        }
    )
    assert sbom_metadata.image.pullspec == pullspec
    assert sbom_metadata.image.digest == digest
    assert sbom_metadata.base_images[0].pullspec == pullspec
    assert sbom_metadata.base_images[0].digest == digest
    assert sbom_metadata.extra_images[0].pullspec == pullspec
    assert sbom_metadata.extra_images[0].digest == digest


def test_sbommetadata_bad() -> None:
    with pytest.raises(SBOMError):
        SBOMMetadata.from_dict({})
