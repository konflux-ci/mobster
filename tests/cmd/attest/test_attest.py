"""Unit tests for the AttestCommand class."""

import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mobster.cmd.attest import AttestCommand
from mobster.error import SBOMError
from mobster.sbom.detect import SBOMFormat

CYCLONEDX_SBOM = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "components": [],
}
SPDX_SBOM = {
    "spdxVersion": "SPDX-2.3",
    "packages": [],
}


@pytest.fixture
def mock_cli_args(tmp_path: Path) -> MagicMock:
    """Create a mock CLI args object with a real SBOM file on disk."""
    sbom_path = tmp_path / "sbom.json"
    sbom_path.write_text(json.dumps(CYCLONEDX_SBOM), encoding="utf-8")

    args = MagicMock()
    args.image_ref = "quay.io/foo/bar@sha256:" + "a" * 64
    args.sbom_path = sbom_path
    args.rekor_url = "https://rekor.example.com"
    args.fulcio_url = "https://fulcio.example.com"
    args.oidc_issuer_url = "https://oidc.example.com"
    args.oidc_token_path = tmp_path / "token"
    return args


@pytest.fixture
def attest_command(mock_cli_args: MagicMock) -> AttestCommand:
    """Create an AttestCommand instance for testing."""
    return AttestCommand(cli_args=mock_cli_args)


class TestAttestCommand:
    """Test suite for AttestCommand."""

    def test_name_property(self, attest_command: AttestCommand) -> None:
        assert attest_command.name == "AttestCommand"

    @pytest.mark.asyncio
    async def test_execute_cyclonedx(self, attest_command: AttestCommand) -> None:
        """A CycloneDX SBOM is attested with the detected format."""
        signer = MagicMock()
        signer.attest_sbom = AsyncMock()

        with patch(
            "mobster.cmd.attest.get_cosign_signer", return_value=signer
        ) as mock_get_signer:
            await attest_command.execute()

        assert attest_command.exit_code == 0

        # The signing config is built from the provided service URLs.
        config = mock_get_signer.call_args.args[0]
        assert config.keyless_token_file == attest_command.cli_args.oidc_token_path
        assert config.url_config.is_keyless_ready()

        signer.attest_sbom.assert_awaited_once_with(
            attest_command.cli_args.sbom_path,
            attest_command.cli_args.image_ref,
            SBOMFormat.CDX_V1_5,
        )

    @pytest.mark.asyncio
    async def test_execute_spdx(self, attest_command: AttestCommand) -> None:
        """The attestation type is detected from an SPDX input file."""
        attest_command.cli_args.sbom_path.write_text(
            json.dumps(SPDX_SBOM), encoding="utf-8"
        )
        signer = MagicMock()
        signer.attest_sbom = AsyncMock()

        with patch("mobster.cmd.attest.get_cosign_signer", return_value=signer):
            await attest_command.execute()

        _, _, detected_format = signer.attest_sbom.await_args.args
        assert detected_format == SBOMFormat.SPDX_2_3
        assert attest_command.exit_code == 0

    @pytest.mark.asyncio
    async def test_execute_signing_failure(self, attest_command: AttestCommand) -> None:
        """A signing failure sets a non-zero exit code instead of raising."""
        signer = MagicMock()
        signer.attest_sbom = AsyncMock(side_effect=SBOMError("boom"))

        with patch("mobster.cmd.attest.get_cosign_signer", return_value=signer):
            await attest_command.execute()

        assert attest_command.exit_code == 1

    @pytest.mark.asyncio
    async def test_save_is_noop(self, attest_command: AttestCommand) -> None:
        # save() is a no-op; it should complete without error.
        await attest_command.save()
        assert attest_command.exit_code == 0
