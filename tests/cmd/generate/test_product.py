from unittest.mock import MagicMock

import pytest

from mobster.cmd.generate.product import GenerateProductCommand


@pytest.mark.asyncio
async def test_GenerateProductCommand_execute() -> None:
    command = GenerateProductCommand(MagicMock())

    assert await command.execute() == {}
