from unittest.mock import MagicMock

import pytest

from mobster.cmd.generate.oci_image import GenerateOciImageCommand


@pytest.mark.asyncio
async def test_GenerateOciImageCommand_execute() -> None:
    command = GenerateOciImageCommand(MagicMock())

    assert await command.execute() == {}
