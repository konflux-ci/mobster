from json import JSONDecodeError
from unittest.mock import MagicMock, patch

import pytest
from _pytest.logging import LogCaptureFixture

from mobster import utils
from mobster.utils import load_sbom_from_json


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


@pytest.mark.parametrize(
    "input_arch, expected_arch",
    [
        pytest.param("x86_64", "amd64", id="x86_64"),
        pytest.param("aarch64", "arm64", id="aarch64"),
        pytest.param("ppc64", "ppc64le", id="ppc64le"),
        pytest.param("s390", "s390x", id="s390x"),
        pytest.param("unknown_arch", "unknown_arch", id="unknown_arch"),
    ],
)
@patch("mobster.utils.platform.machine")
def test_identify_arch(
    mock_platform: MagicMock, input_arch: str, expected_arch: str
) -> None:
    """
    Test the identify_arch function.
    """
    mock_platform.return_value = input_arch
    arch = utils.identify_arch()
    assert arch == expected_arch


@pytest.mark.asyncio
@pytest.mark.parametrize(["fail"], [(True,), (False,)])
@patch("mobster.utils.open")
@patch("mobster.utils.json")
async def test_load_sbom_from_json(
    mock_json: MagicMock, mock_open: MagicMock, fail: bool, caplog: LogCaptureFixture
) -> None:
    mock_stream = MagicMock()
    mock_stream.read.return_value = "foo"
    mock_open.return_value.__enter__.return_value = mock_stream

    if fail:
        mock_json.load.side_effect = JSONDecodeError("a", "b", 1)
        with pytest.raises(JSONDecodeError):
            await load_sbom_from_json(MagicMock())
            assert (
                "Expected a JSON SBOM. Found different file contents!"
                in caplog.messages
            )
            assert "foo" in caplog.messages
    else:
        await load_sbom_from_json(MagicMock())
        mock_json.load.assert_called_once_with(mock_stream)
