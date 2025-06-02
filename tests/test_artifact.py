import pytest

from mobster.artifact import Artifact


@pytest.fixture
def artifact_example() -> Artifact:
    """
    Example of creating an Artifact object.

    Returns:
        Artifact: An example Artifact object.
    """
    return Artifact(
        filename="example!.txt",
        sha256sum="1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        source="https://example.com/example.txt",
        type="text/plain",
    )


def test_Artifact(artifact_example: Artifact) -> None:
    """
    Test the Artifact class.
    """

    assert artifact_example.filename == "example!.txt"
    assert (
        artifact_example.sha256sum
        == "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
    )
    assert artifact_example.source == "https://example.com/example.txt"
    assert artifact_example.type == "text/plain"
    assert (
        artifact_example.purl_str() == "pkg:generic/example%21.txt?"
        "checksum=sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
        "&download_url=https://example.com/example.txt"
    )

    assert artifact_example.sanitized_filename == "example-.txt"

    assert (
        artifact_example.propose_spdx_id()
        == "SPDXRef-Package-example-.txt-d34b77c91faa7c42b163bcc22c1709ab55c6b"
        "2f3b341386d638fb6988bdba751"
    )
    assert (
        artifact_example.propose_cyclonedx_bom_ref()
        == "BomRef.example-.txt-d34b77c91faa7c42b163bcc22c1709ab55c6b2f3b341386d"
        "638fb6988bdba751"
    )
