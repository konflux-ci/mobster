"""A command execution module."""

from abc import ABC, abstractmethod
from typing import Any


class Command(ABC):
    """An abstract base class for command execution."""

    def __init__(self, cli_args: Any, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.cli_args = cli_args

    @abstractmethod
    async def execute(self) -> Any:
        """
        Execute the command.
        """

    @abstractmethod
    async def save(self) -> bool:
        """
        Save the SBOM document.

        Returns:
            (bool): True if successful, False otherwise
        """
