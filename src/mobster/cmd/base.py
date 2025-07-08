"""A command execution module."""

from abc import ABC, abstractmethod
from typing import Any


class Command(ABC):
    """An abstract base class for command execution."""

    def __init__(self, cli_args: Any, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.cli_args = cli_args
        self._exit_code = 0

    @property
    def exit_code(self) -> int:
        """
        Get the command exit code.
        """
        return self._exit_code

    @exit_code.setter
    def exit_code(self, value: int) -> None:
        if value < 0 or value > 255:
            raise ValueError("Exit code must be in range <0, 255>.")

        self._exit_code = value

    @property
    def name(self) -> str:
        """
        Name of the command, used for logging purposes.
        """
        return self.__class__.__name__

    @abstractmethod
    async def execute(self) -> Any:
        """
        Execute the command.
        """

    @abstractmethod
    async def save(self) -> None:
        """
        Save the SBOM document.
        """
