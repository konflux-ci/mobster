from mobster.cmd.generate.oci_image.metadata import ImageData

DIGEST = "sha256:012345678901234567890123456789012"


def test_imagedata_to_image_tag() -> None:
    """Test that ImageData can convert a pullspec with a tag into an Image,
    while preserving the tag."""
    image_data = ImageData(pullspec="example.com/foo:bar", digest=DIGEST)
    image = image_data.to_image()
    assert image.repository == "example.com/foo"
    assert image.tag == "bar"


def test_imagedata_to_image_digest() -> None:
    """Test that ImageData can convert a pullspec with a (redundant) digest."""
    image_data = ImageData(pullspec=f"example.com/foo@{DIGEST}", digest=DIGEST)
    image = image_data.to_image()
    assert image.repository == "example.com/foo"
    assert image.digest == DIGEST

def test_imagedata_to_image_tag_and_digest() -> None:
    """Test that ImageData can convert a pullspec with a (redundant) digest."""
    image_data = ImageData(pullspec=f"example.com/foo:bar@{DIGEST}", digest=DIGEST)
    image = image_data.to_image()
    assert image.repository == "example.com/foo"
    assert image.tag == "bar"
    assert image.digest == DIGEST
