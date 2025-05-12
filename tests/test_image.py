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
        image.purl()
        == "pkg:oci/image@sha256:1234567890abcdef1234567890abcdef1234567890abcdef123456"
        "7890abcdef?arch=amd64&repository_url=registry.example.com/repo/image"
    )

    assert (
        image.propose_spdx_id()
        == "SPDXRef-image-image-73e355ba72fbb39f9249a171eb05bed259d998d5f747b5001ad42fb"
        "1bda26e6a"
    )
