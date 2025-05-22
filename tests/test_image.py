import pytest

from mobster.image import Image


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
