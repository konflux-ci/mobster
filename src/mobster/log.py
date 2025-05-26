"""
Logging configuration and utility functions.
"""

import logging
import logging.config


def get_mobster_logger() -> logging.Logger:
    """
    Get the logger object with the name "mobster".
    """
    return logging.getLogger("mobster")


logger = get_mobster_logger()


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
    logger.info("Logging level set to %s", log_level)
