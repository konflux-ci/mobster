import logging
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mobster.main import main, run

LOGGER = logging.getLogger(__name__)


@patch("mobster.main.run")
@patch("mobster.main.cli.setup_arg_parser")
def test_main(mock_setup_args: MagicMock, mock_run: AsyncMock) -> None:
    mock_args = mock_setup_args.return_value.parse_args.return_value
    mock_args.verbose = True
    main()

    mock_setup_args.assert_called_once()
    mock_setup_args.return_value.parse_args.assert_called_once()

    mock_run.assert_called_once()


@pytest.mark.asyncio
async def test_run(
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mock_args = MagicMock()
    mock_args.func = MagicMock()
    mock_args.func.return_value.execute = AsyncMock()
    mock_args.func.return_value.save = AsyncMock()

    monkeypatch.setattr("sys.exit", lambda _: None)
    await run(mock_args)

    mock_args.func.return_value.execute.assert_called_once()
    mock_args.func.return_value.save.assert_called_once()

    # check that log_elapsed log is present
    assert "completed in" in caplog.text
