"""The main module of the Mobster application."""

import asyncio
import logging
from typing import Any

from mobster import cli

LOGGER = logging.getLogger(__name__)


async def run(args: Any) -> None:
    """
    Run the command based on the provided arguments.

    Args:
        args: The command line arguments.

    """
    command = args.func(args)
    await command.execute()
    await command.save()


def setup_logging(args: Any) -> None:
    """
    Set up logging for the application.

    Args:
        args: The command line arguments.

    """
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    logging.getLogger("asyncio").setLevel(logging.WARNING)

    LOGGER.debug("Logging level set to %s", log_level)


def main() -> None:
    """
    The main function of the Mobster application.
    """

    arg_parser = cli.setup_arg_parser()
    args = arg_parser.parse_args()
    setup_logging(args)
    LOGGER.debug("Arguments: %s", args)

    asyncio.run(run(args))


if __name__ == "__main__":  # pragma: no cover
    main()
