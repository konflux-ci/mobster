"""A module for re-generating SBOM documents for products."""

import logging

from mobster.regenerate.base import (
    SBOMType,
)
from mobster.regenerate.run import run

LOGGER = logging.getLogger(__name__)


def main() -> None:
    """Re-generate an SBOM document for a product."""
    run(SBOMType.PRODUCT)


if __name__ == "__main__":  # pragma: no cover
    main()
