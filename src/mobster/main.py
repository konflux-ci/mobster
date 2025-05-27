"""The main module of the Mobster application."""

import asyncio
import sys
from typing import Any

from mobster import cli
from mobster.log import get_mobster_logger, setup_logging

LOGGER = get_mobster_logger()


async def run(args: Any) -> None:
    """
    Run the command based on the provided arguments.

    Args:
        args: The command line arguments.

    """
    command = args.func(args)
    await command.execute()

    # TODO: is this bool approach ok or should we raise a special exception in the subcommands?
    ok = await command.save()
    code = 0 if ok else 1
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
