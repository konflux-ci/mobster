"""
This module contains errors raised in SBOM generation.
"""


class SBOMError(Exception):
    """
    Exception that can be raised during SBOM generation and augmentation.
    """


class SBOMVerificationError(SBOMError):
    """
    Exception raised when an SBOM's digest could not be verified by
    SBOM_BLOB_URL value in the provenance.
    """
