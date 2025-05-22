from cyclonedx.model.component import (
    Component,
    ComponentType,
)

from mobster.image import Image
from mobster.sbom import cyclonedx


def test_get_component() -> None:
    mock_image = Image.from_image_index_url_and_digest(
        "registry/repo:tag", "sha256:1234567890abcdef"
    )
    result = cyclonedx.get_component(
        mock_image,
    )

    assert isinstance(result, Component)
    assert result.type == ComponentType.CONTAINER
    assert result.name == mock_image.name
    assert result.hashes[0].content == mock_image.digest_hex_val
