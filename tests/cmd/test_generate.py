from unittest.mock import MagicMock, mock_open, patch

import pytest

from mobster.cmd.generate import (
    GenerateModelcarCommand,
    GenerateOciArtifactCommand,
    GenerateOciImageCommand,
    GenerateOciIndexCommand,
    GenerateProductCommand,
)


@pytest.mark.asyncio
async def test_GenerateOciImageCommand_execute() -> None:
    command = GenerateOciImageCommand(MagicMock())

    assert await command.execute() == {}


@pytest.mark.asyncio
@patch("json.dump")
async def test_GenerateOciImageCommand_save(mock_dump: MagicMock) -> None:
    args = MagicMock()
    args.output = "/tmp/test.json"
    command = GenerateOciImageCommand(args)
    with patch("builtins.open", mock_open()):
        assert await command.save() is None

    mock_dump.assert_called_once()


@pytest.mark.asyncio
async def test_GenerateOciIndexCommand_execute() -> None:
    command = GenerateOciIndexCommand(MagicMock())

    assert await command.execute() == {}


@pytest.mark.asyncio
async def test_GenerateProductCommand_execute() -> None:
    command = GenerateProductCommand(MagicMock())

    assert await command.execute() == {}


@pytest.mark.asyncio
async def test_GenerateModelcarCommand_execute() -> None:
    command = GenerateModelcarCommand(MagicMock())

    assert await command.execute() == {}


@pytest.mark.asyncio
async def test_GenerateOciArtifactCommand_execute() -> None:
    command = GenerateOciArtifactCommand(MagicMock())

    assert await command.execute() == {}
