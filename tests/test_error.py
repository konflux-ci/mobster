from mobster.error import SBOMVerificationError


def test_sbom_verification_error_message() -> None:
    expected_digest = "sha256:1234567890abcdef"
    actual_digest = "sha256:0987654321fedcba"

    error = SBOMVerificationError(expected_digest, actual_digest)

    assert expected_digest in str(error)
    assert actual_digest in str(error)
