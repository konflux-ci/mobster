"""
This script generates an SBOM upload report. It parses the TPA report generated
by "mobster upload tpa" and checks the failed SBOM directory for any leftovers,
that weren't pushed to S3. It then generates a final report based on the type
of SBOMs that were generated. Product and component report types only differ in
the name of the root field. This is because the reports will be merged into a
single JSON before being attached to the Release CR later in the release pipeline.

The main consumer of the report are the e2e tests, that verify that all SBOMs
are either uploaded to Atlas or S3.
"""

import argparse as ap
import os
from dataclasses import dataclass
from enum import Enum, auto
from pathlib import Path

import pydantic

from mobster.cmd.upload.upload import TPAUploadReport, TPAUploadSuccess


class MobsterReport(pydantic.BaseModel):
    """
    Model representing the core mobster report data.

    Attributes:
        tpa: List of successfully uploaded SBOMs to TPA.
        failure: List of paths to SBOMs that failed to upload.
    """

    tpa: list[TPAUploadSuccess]
    failure: list[Path]


class ComponentReport(pydantic.BaseModel):
    """
    Container for component-specific mobster report.

    Attributes:
        mobster_component_report: The core mobster report data for components.
    """

    mobster_component_report: MobsterReport


class ProductReport(pydantic.BaseModel):
    """
    Container for product-specific mobster report.

    Attributes:
        mobster_product_report: The core mobster report data for products.
    """

    mobster_product_report: MobsterReport


class ReportType(Enum):
    """
    Enumeration of supported report types.

    Attributes:
        PRODUCT: Product SBOM report type.
        COMPONENT: Component SBOM report type.
    """

    PRODUCT = auto()
    COMPONENT = auto()


@dataclass
class ReportArgs:
    """
    Arguments for generating the SBOM upload report.

    Attributes:
        tpa_report: Path to the TPA upload report file.
        failed_dir: Directory containing failed SBOM uploads.
        result: Path where the final report will be written.
        type: Type of report to generate (product or component).
    """

    tpa_report: Path
    failed_dir: Path
    result: Path
    type: ReportType


def get_args() -> ReportArgs:
    """
    Parse command line arguments for report generation.

    Returns:
        ReportArgs: Parsed and validated command line arguments.
    """
    parser = ap.ArgumentParser()
    parser.add_argument("--data-dir", type=Path, required=True)
    parser.add_argument("--tpa-report", type=Path, required=True)
    parser.add_argument("--failed-dir", type=Path, required=True)
    parser.add_argument("--result", type=Path, required=True)
    parser.add_argument(
        "--type", choices=[e.name.lower() for e in ReportType], required=True
    )
    raw_args = parser.parse_args()

    return ReportArgs(
        tpa_report=raw_args.data_dir / raw_args.tpa_report,
        failed_dir=raw_args.data_dir / raw_args.failed_dir,
        result=raw_args.data_dir / raw_args.result,
        type=ReportType[raw_args.type.upper()],
    )


def parse_tpa_report(path: Path) -> TPAUploadReport:
    """
    Parse TPA upload report from JSON file.

    Args:
        path: Path to the TPA report JSON file.

    Returns:
        TPAUploadReport: Parsed TPA upload report data.
    """
    with open(path, "rb") as fp:
        return TPAUploadReport.model_validate_json(fp.read())


def generate_report(tpa_report: TPAUploadReport, failed_dir: Path) -> MobsterReport:
    """
    Generate mobster report from TPA report and failed directory.

    Args:
        tpa_report: The parsed TPA upload report.
        failed_dir: Directory containing failed SBOM uploads.

    Returns:
        MobsterReport: Combined report with successful and failed uploads.
    """
    failed = map(Path, os.listdir(failed_dir))

    return MobsterReport(tpa=tpa_report.success, failure=list(failed))


def write_result(report: ComponentReport | ProductReport, result: Path) -> None:
    """
    Write the final report to a JSON file.

    Args:
        report: The component or product report to write.
        result: Path where the report JSON will be written.
    """
    with open(result, "w", encoding="utf-8") as fp:
        fp.write(report.model_dump_json())


def main() -> None:
    """
    Main entry point for the report generation script.

    Parses arguments, generates the report, and writes the result.
    """
    args = get_args()
    tpa_report = parse_tpa_report(args.tpa_report)
    mobster_report = generate_report(tpa_report, args.failed_dir)

    if args.type == ReportType.PRODUCT:
        report: ProductReport | ComponentReport = ProductReport(
            mobster_product_report=mobster_report
        )
    else:
        report = ComponentReport(mobster_component_report=mobster_report)

    write_result(report, args.result)


if __name__ == "__main__":
    main()
