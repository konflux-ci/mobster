"""The main module of the Mobster application."""

import asyncio
import logging
import sys
from typing import Any

from mobster import cli
from mobster.cmd.base import Command
from mobster.log import log_elapsed, setup_logging

LOGGER = logging.getLogger(__name__)


async def run(args: Any) -> None:
    """
    Run the command based on the provided arguments.

    Args:
        args: The command line arguments.

    """
    command: Command = args.func(args)
    with log_elapsed(command.name):
        await command.execute()
        await command.save()
    LOGGER.info("Exiting with code %s.", command.exit_code)
    sys.exit(command.exit_code)


def main() -> None:
    """
    The main function of the Mobster application.
    """

    arg_parser = cli.setup_arg_parser()
    args = arg_parser.parse_args()
    setup_logging(args.verbose)
    LOGGER.debug("Arguments: %s", args)

    asyncio.run(run(args))


if __name__ == "__main__":  # pragma: no cover
    main()
