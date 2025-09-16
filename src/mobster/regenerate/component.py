"""A module for re-generating component SBOM documents."""

import asyncio
import logging

from mobster.log import setup_logging
from mobster.regenerate.base import (
    SbomRegenerator,
    SbomType,
    parse_args,
)

LOGGER = logging.getLogger(__name__)


def main() -> None:
    """Re-generate an SBOM document for a component."""
    setup_logging(verbose=True)
    LOGGER.info("Starting component SBOM re-generation.")
    args = parse_args()
    regen = SbomRegenerator(args, SbomType.COMPONENT)
    asyncio.run(regen.regenerate_sboms())


if __name__ == "__main__":  # pragma: no cover
    main()
