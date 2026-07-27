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


class ContextualWorkflowError(SBOMError):
    """
    Raised when the contextual SBOM workflow cannot be resolved.
    """


class ParentContextualizationError(ContextualWorkflowError):
    """
    Raised when parent content contextualization fails.
    """


class BuilderContextualizationError(ContextualWorkflowError):
    """
    Raised when builder content contextualization fails.
    """
