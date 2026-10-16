"""
This module contains errors raised in SBOM generation.
"""

import traceback


def format_exception_chain_for_log(exc: BaseException) -> str:
    """
    Return the complete exception chain as a single-line string.

    The standard traceback formatter preserves causes and contexts without
    stack frames. Newlines are escaped so the result can be emitted as one log
    record, which is required by log collectors that split shell output into
    separate events.
    """
    exception_lines = traceback.format_exception(exc, limit=0, chain=True)
    formatted_chain = "".join(exception_lines).strip("\n")
    return formatted_chain.replace("\n", "\\n")


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
