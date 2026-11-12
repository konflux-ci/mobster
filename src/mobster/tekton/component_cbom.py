"""
Script used for processing component SBOMs in Tekton task.
"""

import asyncio

from mobster.cmd.augment.bom import BOMRefDetail
from mobster.cmd.augment.cbom import CBOMAugmenter
from mobster.log import setup_logging
from mobster.tekton.component import (
    ComponentBOMHandler,
    ProcessComponentArgs,
    parse_component_args,
)


class ComponentCBOMHandler(ComponentBOMHandler[ProcessComponentArgs]):
    """
    Class for e2e handling of release-time e2e CBOMs.
    """

    augmenter_class = CBOMAugmenter

    @staticmethod
    async def attest_boms(
        args: ProcessComponentArgs, results: list[BOMRefDetail]
    ) -> None:
        """
        No-op, CBOMs are not attested to public registry.
        """
        return None


def main() -> None:
    """
    Main entry point for component SBOM processing.
    """
    setup_logging(verbose=True)
    args = parse_component_args()
    handler = ComponentCBOMHandler()
    asyncio.run(handler.process_component_boms(args))
