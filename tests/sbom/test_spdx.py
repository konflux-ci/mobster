from spdx_tools.spdx.model.document import CreationInfo
from spdx_tools.spdx.model.package import Package

from mobster.image import Image
from mobster.sbom import spdx


def test_get_package() -> None:
    mock_image = Image.from_image_index_url_and_digest(
        "registry/repo:tag", "sha256:1234567890abcdef"
    )
    result = spdx.get_image_package(mock_image, "fake_spdx_id")

    assert isinstance(result, Package)
    assert result.spdx_id == "fake_spdx_id"
    assert result.name == mock_image.name
    assert result.checksums[0].value == mock_image.digest_hex_val


def test_get_creation_info() -> None:
    result = spdx.get_creation_info("foo-bar")

    assert isinstance(result, CreationInfo)
    assert result.spdx_id == "SPDXRef-DOCUMENT"
