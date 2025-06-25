import pytest

from mobster.cmd.base import Command


class MockCommand(Command):
    async def execute(self):
        pass

    async def save(self):
        pass


@pytest.mark.parametrize("value", [0, 1, 255])
def test_exit_code_setter_valid(value):
    cmd = MockCommand(cli_args=None)
    cmd.exit_code = value
    assert cmd.exit_code == value


@pytest.mark.parametrize("value", [-1, 256])
def test_exit_code_setter_invalid(value):
    cmd = MockCommand(cli_args=None)
    with pytest.raises(ValueError):
        cmd.exit_code = value
