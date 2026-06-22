"""Unit tests for the EnrichCommand class."""

import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, mock_open, patch

import pytest

from mobster.cmd.cyclonedx_wrapper import CycloneDX1BomWrapper
from mobster.cmd.enrich import EnrichCommand


@pytest.fixture
def mock_cli_args() -> MagicMock:
    """Create a mock CLI args object."""
    args = MagicMock()
    args.sbom = Path("/path/to/sbom.json")
    args.enrichment_file = Path("/path/to/enrichment.json")
    args.output = Path("/path/to/output.json")
    return args


@pytest.fixture
def enrich_command(mock_cli_args: MagicMock) -> EnrichCommand:
    """Create an EnrichCommand instance for testing."""
    return EnrichCommand(cli_args=mock_cli_args)


@pytest.fixture
def mock_sbom_wrapper() -> MagicMock:
    """Create a mock CycloneDX1BomWrapper."""
    wrapper = MagicMock(spec=CycloneDX1BomWrapper)
    wrapper.to_dict.return_value = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": [],
    }
    return wrapper


class TestEnrichCommand:
    """Test suite for EnrichCommand."""

    def test_name_property(self, enrich_command: EnrichCommand) -> None:
        """
        Test that the name property returns the correct command name.
        Covers line 47.
        """
        assert enrich_command.name == "EnrichCommand"

    @pytest.mark.asyncio
    async def test_execute(
        self, enrich_command: EnrichCommand, mock_sbom_wrapper: MagicMock
    ) -> None:
        """
        Test the execute method calls _enrich_sboms and stores the result.
        """
        with patch.object(
            enrich_command, "_enrich_sboms", new_callable=AsyncMock
        ) as mock_enrich:
            mock_enrich.return_value = mock_sbom_wrapper

            result = await enrich_command.execute()

            mock_enrich.assert_called_once()
            assert result == mock_sbom_wrapper
            assert enrich_command._content == mock_sbom_wrapper

    @pytest.mark.asyncio
    async def test_enrich_sboms(
        self, enrich_command: EnrichCommand, mock_sbom_wrapper: MagicMock
    ) -> None:
        """
        Test the _enrich_sboms method calls enrich_sbom with correct paths.
        """
        with patch(
            "mobster.cmd.enrich.enrich_sbom", new_callable=AsyncMock
        ) as mock_enrich_sbom:
            mock_enrich_sbom.return_value = mock_sbom_wrapper

            result = await enrich_command._enrich_sboms()

            mock_enrich_sbom.assert_called_once_with(
                Path("/path/to/sbom.json"), Path("/path/to/enrichment.json")
            )
            assert result == mock_sbom_wrapper

    @pytest.mark.asyncio
    async def test_save_to_file(
        self, enrich_command: EnrichCommand, mock_sbom_wrapper: MagicMock
    ) -> None:
        """
        Test the save method writes SBOM to file when output is specified.
        Covers lines 78-82.
        """
        enrich_command._content = mock_sbom_wrapper
        expected_dict = mock_sbom_wrapper.to_dict.return_value

        m = mock_open()
        with patch("builtins.open", m):
            await enrich_command.save()

        m.assert_called_once_with(Path("/path/to/output.json"), "w", encoding="utf-8")
        handle = m()
        written_content = "".join(call.args[0] for call in handle.write.call_args_list)
        assert json.loads(written_content) == expected_dict

    @pytest.mark.asyncio
    async def test_save_to_stdout(
        self, mock_cli_args: MagicMock, mock_sbom_wrapper: MagicMock
    ) -> None:
        """
        Test the save method prints SBOM to stdout when output is None.
        Covers lines 78-84.
        """
        mock_cli_args.output = None
        enrich_command = EnrichCommand(cli_args=mock_cli_args)
        enrich_command._content = mock_sbom_wrapper
        expected_dict = mock_sbom_wrapper.to_dict.return_value

        with patch("builtins.print") as mock_print:
            await enrich_command.save()

        mock_print.assert_called_once_with(json.dumps(expected_dict))

    @pytest.mark.asyncio
    async def test_dump_sbom_to_dict(self, mock_sbom_wrapper: MagicMock) -> None:
        """
        Test the dump_sbom_to_dict static method calls to_dict on the SBOM.
        """
        expected_dict = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "components": [{"name": "test-component"}],
        }
        mock_sbom_wrapper.to_dict.return_value = expected_dict

        result = await EnrichCommand.dump_sbom_to_dict(mock_sbom_wrapper)

        mock_sbom_wrapper.to_dict.assert_called_once()
        assert result == expected_dict

    @pytest.mark.asyncio
    async def test_full_workflow(
        self, enrich_command: EnrichCommand, mock_sbom_wrapper: MagicMock
    ) -> None:
        """
        Test the full workflow: execute followed by save.
        """
        with patch(
            "mobster.cmd.enrich.enrich_sbom", new_callable=AsyncMock
        ) as mock_enrich_sbom:
            mock_enrich_sbom.return_value = mock_sbom_wrapper

            # Execute
            result = await enrich_command.execute()
            assert result == mock_sbom_wrapper

            # Save
            m = mock_open()
            with patch("builtins.open", m):
                await enrich_command.save()

            # Verify the file was written with the correct content
            m.assert_called_once()
            handle = m()
            written_content = "".join(
                call.args[0] for call in handle.write.call_args_list
            )
            assert json.loads(written_content) == mock_sbom_wrapper.to_dict.return_value
