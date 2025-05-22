from unittest.mock import MagicMock

import pytest

from mobster.cmd.generate.modelcar import GenerateModelcarCommand


@pytest.mark.asyncio
async def test_GenerateModelcarCommand_execute() -> None:
    command = GenerateModelcarCommand(MagicMock())

    assert await command.execute() == {}
