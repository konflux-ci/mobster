"""
This module contains Pydantic models for use with the TPA client.
"""

from datetime import datetime
from typing import Annotated

from pydantic import BaseModel, Field


class SbomSummary(BaseModel):
    """
    Model representing an Sbom summary item from the GET /v2/sbom endpoint.
    """

    ingested: datetime = Field(
        ..., description="The timestamp the document was ingested"
    )
    sha256: str
    sha384: str
    sha512: str
    size: Annotated[int, Field(ge=0)]
    authors: list[str] = Field(..., description="Authors of the SBOM")
    data_licenses: list[str]
    document_id: str | None = None
    id: str
    labels: dict[str, str] | None = None
    name: str
    number_of_packages: Annotated[int, Field(ge=0)] = Field(
        ..., description="The number of packages this SBOM has"
    )
    published: datetime | None
    suppliers: list[str] | None = Field(
        default=None, description="Suppliers of the SBOMs content"
    )


class PaginatedSbomSummaryResult(BaseModel):
    """
    Model representing a response from the GET /v2/sbom endpoint.
    """

    items: list[SbomSummary]
    total: Annotated[int, Field(ge=0)]
