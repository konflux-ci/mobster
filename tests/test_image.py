from typing import Any
from unittest.mock import patch

import pytest

from mobster.error import SBOMError
from mobster.image import Image, IndexImage


def test_image() -> None:
    """
    Test the from_image_index_url_and_digest method of the Image class.
    """
    image_tag_pullspec = "registry.example.com/repo/image:tag"
    image_digest = (
        "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
    )
    arch = "amd64"

    image = Image.from_image_index_url_and_digest(
        image_tag_pullspec, image_digest, arch
    )

    assert image.repository == "registry.example.com/repo/image"
    assert image.name == "image"
    assert image.digest == image_digest
    assert image.tag == "tag"
    assert image.arch == arch

    assert image.digest_algo == "SHA256"
    assert image.digest_hex_val == (
        "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
    )
    assert (
        image.purl_str()
        == "pkg:oci/image@sha256:1234567890abcdef1234567890abcdef1234567890abcdef123456"
        "7890abcdef?arch=amd64&repository_url=registry.example.com/repo/image"
    )

    assert (
        image.propose_spdx_id()
        == "SPDXRef-image-image-73e355ba72fbb39f9249a171eb05bed259d998d5f747b5001ad42fb"
        "1bda26e6a"
    )

    assert image.propose_cyclonedx_bom_ref() == (
        "BomRef.image-73e355ba72fbb39f9249a171eb05bed259d998d5f747b5001ad42fb1bda26e6a"
    )

    assert (
        image.propose_sbom_name() == "registry.example.com/repo/image@sha256:"
        "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
    )


@pytest.mark.parametrize(
    ["repository", "expected_id"],
    [
        ("repo/name", "SPDXRef-image-name"),
        ("repo/name2", "SPDXRef-image-name2"),
        ("repo/name_stupid", "SPDXRef-image-name-stupid"),
        ("repo/name@weird", "SPDXRef-image-name-weird"),
    ],
)
def test_image_spdx_id(repository: str, expected_id: str) -> None:
    image = Image(repository=repository, digest="sha256:aaaa")
    # drop the last 65 chars - purl digest and separator
    actual = image.propose_spdx_id()[:-65]
    assert actual == expected_id


def test_image_from_oci_artifact_reference() -> None:
    """
    Test the from_oci_artifact_reference method of the Image class.
    """

    with pytest.raises(ValueError):
        Image.from_oci_artifact_reference("foo-bar")
    oci_artifact_reference = (
        "registry.example.com/repo/image:tag@sha256:"
        "1234567890abcdef1234567890abcdef1234567890abcdef123456"
    )
    image = Image.from_oci_artifact_reference(oci_artifact_reference)

    assert image.repository == "registry.example.com/repo/image"
    assert image.name == "image"
    assert (
        image.digest == "sha256:1234567890abcdef1234567890abcdef1234567890abcdef123456"
    )
    assert image.tag == "tag"
    assert image.arch is None

    assert image.digest_algo == "SHA256"
    assert (
        image.digest_hex_val == "1234567890abcdef1234567890abcdef1234567890abcdef123456"
    )


@pytest.mark.parametrize(
    ["manifest", "image"],
    [
        pytest.param(
            {"mediaType": "application/vnd.oci.image.manifest.v1+json"},
            Image("quay.io/repo", "sha256:deadbeef"),
            id="single-arch",
        ),
        pytest.param(
            {
                "mediaType": "application/vnd.oci.image.index.v1+json",
                "manifests": [
                    {"digest": "sha256:aaaaaaaa", "platform": {"architecture": "amd64"}}
                ],
            },
            IndexImage(
                "quay.io/repo",
                "sha256:deadbeef",
                children=[Image("quay.io/repo", "sha256:aaaaaaaa", arch="amd64")],
            ),
            id="multiarch",
        ),
    ],
)
@pytest.mark.asyncio
async def test_image_from_repo_digest(manifest: dict[Any, Any], image: Image) -> None:
    async def fake_get_image_manifest(_: Any) -> dict[Any, Any]:
        return manifest

    with patch(
        "mobster.image.get_image_manifest", side_effect=fake_get_image_manifest
    ) as mock_get_image_manifest:
        assert image == await Image.from_repository_digest_manifest(
            "quay.io/repo", "sha256:deadbeef"
        )
        mock_get_image_manifest.assert_awaited_once_with(image.reference)


@pytest.mark.asyncio
async def test_image_from_repo_digest_unsupported_manifest() -> None:
    manifest = {"mediaType": "unsupported/manifest"}

    async def fake_get_image_manifest(_: Any) -> dict[Any, Any]:
        return manifest

    with patch("mobster.image.get_image_manifest", side_effect=fake_get_image_manifest):
        with pytest.raises(SBOMError):
            await Image.from_repository_digest_manifest(
                "quay.io/repo", "sha256:deadbeef"
            )
