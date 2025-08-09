from pathlib import Path
from unittest.mock import MagicMock

import pytest

from mobster.cmd.upload.oidc import RetryExhaustedException
from mobster.cmd.upload.upload import TPAUploadCommand, UploadExitCode


def test_gather_sboms(tmp_path: Path) -> None:
    (tmp_path / "file1.json").touch()
    (tmp_path / "file2.json").touch()
    (tmp_path / "subdir").mkdir()
    (tmp_path / "subdir" / "file3.json").touch()

    result = TPAUploadCommand.gather_sboms(tmp_path)

    assert len(result) == 3

    result_names = {p.name for p in result}
    expected_names = {"file1.json", "file2.json", "file3.json"}
    assert result_names == expected_names


def test_gather_sboms_nonexistent() -> None:
    with pytest.raises(FileNotFoundError):
        TPAUploadCommand.gather_sboms(Path("/nonexistent"))


@pytest.mark.parametrize(
    "results,expected_exit_code,description",
    [
        ([], 0, "empty results list"),
        ([None, None], 0, "all successful uploads"),
        (
            [RetryExhaustedException()],
            UploadExitCode.TRANSIENT_ERROR.value,
            "only retry exhausted exceptions",
        ),
        ([ValueError()], UploadExitCode.ERROR.value, "only non-transient exceptions"),
        (
            [RetryExhaustedException(), ValueError()],
            UploadExitCode.ERROR.value,
            "mixed exception types",
        ),
    ],
)
def test_set_exit_code(
    results: list[BaseException | None], expected_exit_code: int, description: str
) -> None:
    """
    Test set_exit_code function with various result combinations.
    """
    command = TPAUploadCommand(MagicMock())
    command.set_exit_code(results)
    assert command.exit_code == expected_exit_code


def test_get_oidc_auth_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Test get_oidc_auth() returns None when MOBSTER_TPA_AUTH_DISABLE is true.
    """
    monkeypatch.setenv("MOBSTER_TPA_AUTH_DISABLE", "true")
    assert TPAUploadCommand.get_oidc_auth() is None


def test_get_oidc_auth_enabled_false(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Test get_oidc_auth() creates OIDCClientCredentials when
    MOBSTER_TPA_AUTH_DISABLE is false.
    """
    monkeypatch.setenv("MOBSTER_TPA_AUTH_DISABLE", "false")
    monkeypatch.setenv("MOBSTER_TPA_SSO_TOKEN_URL", "https://test.token.url")
    monkeypatch.setenv("MOBSTER_TPA_SSO_ACCOUNT", "test-account")
    monkeypatch.setenv("MOBSTER_TPA_SSO_TOKEN", "test-token")

    result = TPAUploadCommand.get_oidc_auth()
    assert result is not None
    assert result.token_url == "https://test.token.url"
    assert result.client_id == "test-account"
    assert result.client_secret == "test-token"
