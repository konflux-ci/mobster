"""The main module of the Mobster application."""

import asyncio
import logging
import sys
from typing import Any

from mobster import cli
from mobster.log import setup_logging

LOGGER = logging.getLogger(__name__)


async def run(args: Any) -> None:
    """
    Run the command based on the provided arguments.

    Args:
        args: The command line arguments.

    """
    command = args.func(args)
    await command.execute()

    ok = await command.save()
    code = 0 if ok else 1
    LOGGER.info("Exiting with code %s.", code)
    sys.exit(code)


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
