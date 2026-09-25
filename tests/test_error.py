from mobster.error import SBOMError, SBOMVerificationError, format_exception_messages


def test_sbom_verification_error_message() -> None:
    expected_digest = "sha256:1234567890abcdef"
    actual_digest = "sha256:0987654321fedcba"

    error = SBOMVerificationError(expected_digest, actual_digest)

    assert expected_digest in str(error)
    assert actual_digest in str(error)


def test_format_exception_messages_returns_chained_messages_in_one_line() -> None:
    root_error = SBOMError("root error\nwith details")
    wrapped_error = SBOMError("wrapped error")
    wrapped_error.__cause__ = root_error

    assert format_exception_messages(wrapped_error) == (
        "root error\\nwith details <- wrapped error"
    )


def test_format_exception_messages_handles_an_exception_without_cause() -> None:
    assert format_exception_messages(SBOMError("single error")) == "single error"
