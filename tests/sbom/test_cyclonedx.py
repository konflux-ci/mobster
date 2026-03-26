from cyclonedx.model.component import (
    Component,
    ComponentType,
)
from cyclonedx.model.contact import OrganizationalEntity

from mobster.image import Image
from mobster.sbom import cyclonedx


def test_get_manufacturer() -> None:
    result = cyclonedx.get_manufacturer()
    assert isinstance(result, OrganizationalEntity)
    assert result.name == "Red Hat"


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
