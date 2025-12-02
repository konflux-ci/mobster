"""Module for regenerating SBOMs by given release IDs"""

import logging
from dataclasses import dataclass
from pathlib import Path

from mobster.regenerate.base import CommonArgs, SbomRegenerator, SbomType
from mobster.release import ReleaseId

LOGGER = logging.getLogger(__name__)


@dataclass
class RegenerateReleaseArgs(CommonArgs):
    """
    Arguments for SBOM regeneration.

    Attributes:
        release_ids: The release IDs to regenerate.
    """

    release_ids: list[ReleaseId]


class ReleaseSBOMRegenerator(SbomRegenerator):
    """
    Regenerate SBOMs by given release IDs.
    """

    def __init__(self, args: RegenerateReleaseArgs, sbom_type: SbomType):
        super().__init__(args, sbom_type)
        self.args = args
        self.sbom_release_groups = set(args.release_ids)

    async def populate_releases(self) -> None:
        """
        This is a NOOP, the releases are populated in constructor.
        """

    @staticmethod
    def get_releases_from_file(file: Path) -> list[ReleaseId]:
        """
        Parse release IDs from a file. Each release ID is expected
        to be on a separate line.
        Args:
            file: Path to the file to parse.

        Returns: list of Release ID objects
        """
        release_ids = []
        with open(file, encoding="utf-8") as file_stream:
            for line in file_stream:
                string_id = line.strip().strip("\"'")
                release_ids.append(ReleaseId(string_id))
        return release_ids
