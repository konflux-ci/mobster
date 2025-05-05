from unittest.mock import MagicMock

import pytest

from mobster.cmd.augment import AugmentComponentCommand


@pytest.mark.asyncio
async def test_AugmentComponentCommand_execute() -> None:
    command = AugmentComponentCommand(MagicMock())

    assert await command.execute() is None


@pytest.mark.asyncio
async def test_AugmentComponentCommand_save() -> None:
    command = AugmentComponentCommand(MagicMock())
    assert await command.save() is None
