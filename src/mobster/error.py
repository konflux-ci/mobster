"""
This module contains errors raised in SBOM generation.
"""


class SBOMError(Exception):
    """
    Exception that can be raised during SBOM generation and enrichment.
    """

    def __init__(self, *args: object, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)


class SBOMVerificationError(SBOMError):
    """
    Exception raised when an SBOM's digest does not match that in the provenance.
    """

    def __init__(
        self, expected: str, actual: str, *args: object, **kwargs: object
    ) -> None:
        self.expected = expected
        self.actual = actual
        message = (
            "SBOM digest verification from provenance failed. "
            f"Expected digest: {expected}, actual digest: {actual}"
        )
        super().__init__(message, *args, **kwargs)
