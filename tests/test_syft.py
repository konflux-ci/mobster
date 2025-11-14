from unittest.mock import AsyncMock, patch

import pytest

from mobster import syft


@pytest.mark.asyncio
@patch("mobster.syft.run_async_subprocess")
async def test_scan_image(
    mock_run_async: AsyncMock,
) -> None:
    mock_run_async.return_value = (0, b"{}", b"")
    result = await syft.scan_image("example.com/repo:tag")
    mock_run_async.assert_awaited_once_with(
        [
            "syft",
            "scan",
            "example.com/repo:tag",
            "-o",
            "spdx-json@2.3",
        ],
        retry_times=3,
    )
    assert result == {}

    mock_run_async.return_value = (1, b"{}", b"")
    with pytest.raises(RuntimeError):
        await syft.scan_image("example.com/repo:tag")
