"""
This module contains errors raised in SBOM generation.
"""


def format_exception_messages(exc: BaseException) -> str:
    """
    Return chained exception messages as a single-line string.

    Exception causes are traversed from the outer exception towards the root
    cause and returned in root-to-wrapper order. Newlines are escaped so the
    result can be emitted as one log record (important for log
    collectors that split shell output into separate events)
    Used for Contextual workflow.
    """
    messages: list[str] = []
    seen: set[int] = set()
    current: BaseException | None = exc

    while current is not None and id(current) not in seen:
        seen.add(id(current))
        messages.append(str(current).replace("\n", "\\n"))
        current = current.__cause__ or current.__context__

    return " <- ".join(reversed(messages))


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
