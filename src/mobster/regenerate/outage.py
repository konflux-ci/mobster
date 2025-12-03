"""Module for regenerating SBOMs in case of an outage"""

import datetime
import logging
from dataclasses import dataclass

from mobster.regenerate.base import CommonArgs, SbomRegenerator

LOGGER = logging.getLogger(__name__)


@dataclass
class RegenerateOutageArgs(CommonArgs):
    """
    Arguments for SBOM generation if the SBOMs failed
    to be uploaded to Atlas.
    """

    since: datetime.datetime
    until: datetime.datetime


class OutageSbomGenerator(SbomRegenerator):
    """
    This regenerator is intended to be used when infrastructure outages
    appear.
    """

    args: RegenerateOutageArgs

    async def populate_releases(self) -> None:
        """
        regenerate the set of sboms indicated by the cli args
        """
        LOGGER.debug("Gathering SBOM ReleaseIds from S3")
        self.sbom_release_groups = set(
            await self.s3_client.get_release_ids_between(
                since=self.args.since, until=self.args.until
            )
        )
        LOGGER.debug("Found %d SBOM ReleaseIds from S3", len(self.sbom_release_groups))
