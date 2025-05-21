from unittest.mock import MagicMock

import pytest

from mobster.cmd.generate.oci_artifact import GenerateOciArtifactCommand


@pytest.mark.asyncio
async def test_GenerateOciArtifactCommand_execute() -> None:
    command = GenerateOciArtifactCommand(MagicMock())

    assert await command.execute() == {}
