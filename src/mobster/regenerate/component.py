"""A module for re-generating component SBOM documents."""

import logging

from mobster.regenerate.base import (
    SBOMType,
)
from mobster.regenerate.run import run

LOGGER = logging.getLogger(__name__)


def main() -> None:
    """Run component regeneration."""
    run(SBOMType.COMPONENT)


if __name__ == "__main__":  # pragma: no cover
    main()
