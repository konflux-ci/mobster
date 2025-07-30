"""
This module contains data structures used to serialize a Mobster report into
the result directory. The release pipeline then merges all JSON files in the
directory into one, so it can be verified for testing purposes.

In the E2E tests, we deserialize the report and verify that there were no
upload failures and all SBOMs have their Atlas URNs assigned.
"""

from pathlib import Path

import pydantic

from mobster.cmd.upload.upload import TPAUploadReport

COMPONENT_REPORT_NAME = "mobster_component_report.json"
PRODUCT_REPORT_NAME = "mobster_product_report.json"


class ComponentReport(pydantic.BaseModel):
    """
    Container for component-specific mobster report.

    Attributes:
        mobster_component_report: The core mobster report data for components.
    """

    mobster_component_report: TPAUploadReport


class ProductReport(pydantic.BaseModel):
    """
    Container for product-specific mobster report.

    Attributes:
        mobster_product_report: The core mobster report data for products.
    """

    mobster_product_report: TPAUploadReport


def write_report(report: ComponentReport | ProductReport, result_dir: Path) -> None:
    """
    Write the final report to a JSON file.

    Args:
        report: The component or product report to write.
        result_dir: Path to directory where the report JSON will be written.
    """
    if isinstance(report, ComponentReport):
        name = COMPONENT_REPORT_NAME
    else:
        name = PRODUCT_REPORT_NAME

    with open(result_dir / name, "w", encoding="utf-8") as fp:
        fp.write(report.model_dump_json())
