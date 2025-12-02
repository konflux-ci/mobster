"""Run the regeneration script for component or product"""

import asyncio
import logging

from mobster.log import setup_logging
from mobster.regenerate.base import SbomType
from mobster.regenerate.by_release_id import (
    RegenerateReleaseArgs,
    ReleaseSBOMRegenerator,
)
from mobster.regenerate.cli import parse_args
from mobster.regenerate.invalid import FaultySBOMRegenerator, RegenerateArgs
from mobster.regenerate.outage import OutageSBOMGenerator, RegenerateOutageArgs

LOGGER = logging.getLogger(__name__)


def run(sbom_type: SbomType) -> None:
    """Re-generate an SBOM document for a component or product."""
    setup_logging(verbose=True)
    LOGGER.info("Starting component SBOM re-generation.")
    args = parse_args()
    regen: FaultySBOMRegenerator | OutageSBOMGenerator | ReleaseSBOMRegenerator
    if isinstance(args, RegenerateArgs):
        regen = FaultySBOMRegenerator(args, sbom_type)
    elif isinstance(args, RegenerateOutageArgs):
        regen = OutageSBOMGenerator(args, sbom_type)
    elif isinstance(args, RegenerateReleaseArgs):
        regen = ReleaseSBOMRegenerator(args, sbom_type)
    else:
        raise ValueError(f"Invalid arguments received: {args}")
    asyncio.run(regen.regenerate_sboms())
