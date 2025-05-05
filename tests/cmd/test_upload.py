import pytest

from mobster.cmd.upload import TPAUploadCommand


@pytest.mark.asyncio
async def test_TPAUploadCommand_execute() -> None:
    # Test the TPAUploadCommand class
    command = TPAUploadCommand()

    assert await command.execute() is None


@pytest.mark.asyncio
async def test_TPAUploadCommand_save() -> None:
    command = TPAUploadCommand()
    assert await command.save() is None
