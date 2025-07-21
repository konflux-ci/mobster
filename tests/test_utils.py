from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mobster import utils


def test_normalize_file_name() -> None:
    """
    Test the normalize_file_name function.
    """
    assert utils.normalize_file_name("valid_filename.txt") == "valid_filename.txt"
    assert utils.normalize_file_name("invalid|filename.txt") == "invalid_filename.txt"
    assert (
        utils.normalize_file_name("another:invalid?name.txt")
        == "another_invalid_name.txt"
    )
    assert utils.normalize_file_name("quay.io/foo/bar:1") == "quay.io_foo_bar_1"
    assert utils.normalize_file_name("file*name<>.txt") == "file_name__.txt"
    assert (
        utils.normalize_file_name("file/name\\with\\slashes.txt")
        == "file_name_with_slashes.txt"
    )
    assert utils.normalize_file_name("") == ""


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "retry_times, env, exec_results, expected",
    [
        pytest.param(
            0, None, [(0, b"output", b"error")], (0, b"output", b"error"), id="success"
        ),
        pytest.param(
            0,
            {"ENV_VAR": "/usr/bin"},
            [(0, b"output", b"")],
            (0, b"output", b""),
            id="custom-env",
        ),
        pytest.param(
            1,
            None,
            [(1, b"", b"error1"), (0, b"output", b"")],
            (0, b"output", b""),
            id="failure-retry-success",
        ),
        pytest.param(
            2,
            None,
            [(1, b"", b"error1"), (2, b"", b"error2"), (3, b"", b"error3")],
            (3, b"", b"error3"),
            id="all-failures",
        ),
        pytest.param(
            0,
            None,
            [(1, b"", b"error")],
            (1, b"", b"error"),
            id="single-attempt-failure",
        ),
    ],
)
async def test_run_async_subprocess(
    retry_times: int,
    env: dict[str, Any],
    exec_results: list[tuple[int, bytes, bytes]],
    expected: tuple[int, bytes, bytes],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("EXISTING", "VAR")
    with patch("asyncio.create_subprocess_exec") as mock_exec:
        mock_processes = []
        for return_code, stdout, stderr in exec_results:
            mock_process = AsyncMock()
            mock_process.communicate.return_value = (stdout, stderr)
            mock_process.returncode = return_code
            mock_processes.append(mock_process)

        mock_exec.side_effect = mock_processes

        code, stdout, stderr = await utils.run_async_subprocess(
            ["cmd"], env=env, retry_times=retry_times
        )

        assert (code, stdout, stderr) == expected
        assert mock_exec.call_count == min(len(exec_results), retry_times + 1)

        for call in mock_exec.call_args_list:
            # make sure we keep the existing env vars
            assert "EXISTING" in call.kwargs["env"]
            # make sure we pass env vars
            if env is not None:
                assert env.items() <= call.kwargs["env"].items()


@pytest.mark.asyncio
async def test_run_async_subprocess_negative_retry() -> None:
    with pytest.raises(ValueError) as excinfo:
        await utils.run_async_subprocess(["cmd"], retry_times=-1)

    assert "Retry count cannot be negative" in str(excinfo.value)


