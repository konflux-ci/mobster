from pathlib import Path

import pydantic

from mobster.cmd.upload.upload import TPAUploadReport


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
        name = "mobster_component_report.json"
    else:
        name = "mobster_product_report.json"

    with open(result_dir / name, "w", encoding="utf-8") as fp:
        fp.write(report.model_dump_json())
