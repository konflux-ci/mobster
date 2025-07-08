"""
Logging configuration and utility functions.
"""

import logging
import logging.config
import time
from collections.abc import Generator
from contextlib import contextmanager

LOGGER = logging.getLogger(__name__)


def setup_logging(verbose: bool) -> None:
    """
    Set up logging for the application.

    Args:
        args: The command line arguments.

    """
    log_level = logging.DEBUG if verbose else logging.INFO
    logconfig = {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "simple": {"format": "%(asctime)s [%(levelname)s] %(name)s: %(message)s"}
        },
        "handlers": {
            "stderr": {
                "class": "logging.StreamHandler",
                "formatter": "simple",
                "stream": "ext://sys.stderr",
            }
        },
        "loggers": {
            "mobster": {"level": log_level},
        },
        "root": {"level": "WARNING", "handlers": ["stderr"]},
    }

    logging.config.dictConfig(config=logconfig)
    LOGGER.info("Logging level set to %s", log_level)


@contextmanager
def log_elapsed(name: str) -> Generator[None, None, None]:
    """
    Log time elapsed in the with block.

    Example:
        >>> with log_elapsed("sleep"):
                time.sleep(1)
        "sleep completed in 1s"

    Args:
        name: The name of the action to log elapsed time of
    """

    start_time = time.time()
    try:
        yield
    finally:
        elapsed = time.time() - start_time
        LOGGER.debug("%s completed in %.2fs", name, elapsed)
