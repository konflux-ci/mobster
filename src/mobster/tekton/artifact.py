"""
This module contains data structures used to serialize an SBOM artifact into
the result directory.

The release pipeline in the update-cr-status task merges all JSON files in the
directory into one, so it can be verified for testing purposes. After merging,
the resulting JSON will have this structure:
{
    "sboms": {
        "product": ["https://atlas.net/sboms/urn:uuid:3aaa7f9f-3e01-43a1-8264-935d9a1cdfae"],
        "component": ["https://atlas.net/sboms/urn:uuid:6cc66ae6-5348-4241-89b4-de40eb5a3072"]
    }
}

In the E2E tests, we deserialize the report and verify that all SBOMs have
their Atlas URLs assigned.
"""

from pathlib import Path

import pydantic

from mobster.cmd.upload.upload import TPAUploadReport

COMPONENT_ARTIFACT_NAME = "mobster_component_report.json"
PRODUCT_ARTIFACT_NAME = "mobster_product_report.json"


class ProductArtifact(pydantic.BaseModel):
    """
    Artifact containing URLs of product SBOMs uploaded to Atlas.
    """

    product: list[str]

    @staticmethod
    def from_tpa_report(report: TPAUploadReport) -> "ProductArtifact":
        """
        Build a product artifact from a TPA report.
        """
        return ProductArtifact(product=[success.url for success in report.success])


class ComponentArtifact(pydantic.BaseModel):
    """
    Artifact containing URLs of component SBOMs uploaded to Atlas.
    """

    component: list[str]

    @staticmethod
    def from_tpa_report(report: TPAUploadReport) -> "ComponentArtifact":
        """
        Build a component artifact from a TPA report.
        """
        return ComponentArtifact(component=[success.url for success in report.success])


class SBOMArtifact(pydantic.BaseModel):
    """
    Artifact containing either product or component artifact of SBOMs uploaded
    to Atlas.
    """

    sboms: ProductArtifact | ComponentArtifact

    def write_result(self, result_dir: Path) -> None:
        """
        Write the artifact to the result directory.
        """
        if isinstance(self.sboms, ComponentArtifact):
            name = COMPONENT_ARTIFACT_NAME
        else:
            name = PRODUCT_ARTIFACT_NAME

        with open(result_dir / name, "w", encoding="utf-8") as fp:
            fp.write(self.model_dump_json())


def get_component_artifact(report: TPAUploadReport) -> SBOMArtifact:
    """
    Get a component-type artifact from a TPA report.
    """
    return SBOMArtifact(sboms=ComponentArtifact.from_tpa_report(report))


def get_product_artifact(report: TPAUploadReport) -> SBOMArtifact:
    """
    Get a product-type artifact from a TPA report.
    """
    return SBOMArtifact(sboms=ProductArtifact.from_tpa_report(report))
