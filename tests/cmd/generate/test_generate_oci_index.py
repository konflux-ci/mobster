import json
import pathlib
import tempfile
from unittest.mock import MagicMock, patch

import pytest
from spdx_tools.spdx.model.document import CreationInfo
from spdx_tools.spdx.model.package import Package
from spdx_tools.spdx.model.relationship import Relationship, RelationshipType

from mobster.cmd.generate.oci_index import GenerateOciIndexCommand
from mobster.image import Image


@pytest.mark.asyncio
async def test_generate_oci_index_sbom() -> None:
    """
    This test verifies the generation of an OCI index SBOM end-to-end.
    """

    args = MagicMock()
    current_dir = pathlib.Path(__file__).parent.resolve()
    args.index_manifest_path = current_dir.parent.parent / "data/index_manifest.json"
    args.index_image_pullspec = "registry.redhat.io/ubi10-beta/ubi:latest"
    args.index_image_digest = (
        "sha256:4b4976d86eefeedab6884c9d2923206c6c3c2e2471206f97fd9d7aaaecbc04ac"
    )

    expected_output_path = (
        current_dir.parent.parent / "data/index_manifest_sbom.spdx.json"
    )
    with open(expected_output_path, encoding="utf8") as expected_file:
        expected_output = json.load(expected_file)

    command = GenerateOciIndexCommand(args)

    with tempfile.TemporaryDirectory() as temp_dir:
        args.output = pathlib.Path(temp_dir) / "index_manifest_sbom.spdx.json"
        await command.execute()
        await command.save()

        assert command._content is not None
        with open(args.output, encoding="utf8") as result_file:
            result = json.load(result_file)

            # Copy dynamic values from expected output
            result["creationInfo"]["created"] = expected_output["creationInfo"][
                "created"
            ]
            result["documentNamespace"] = expected_output["documentNamespace"]

            assert result == expected_output


def test_GenerateOciIndexCommand_get_package() -> None:
    args = MagicMock()
    command = GenerateOciIndexCommand(args)
    mock_image = Image.from_image_index_url_and_digest(
        "registry/repo:tag", "sha256:1234567890abcdef"
    )
    result = command.get_package(mock_image, "fake_spdx_id")

    assert isinstance(result, Package)
    assert result.spdx_id == "fake_spdx_id"
    assert result.name == mock_image.name
    assert result.checksums[0].value == mock_image.digest_hex_val


def test_GenerateOciIndexCommand_get_index_image_relationship() -> None:
    args = MagicMock()
    command = GenerateOciIndexCommand(args)

    result = command.get_index_image_relationship("fake_spdx_id")

    assert isinstance(result, Relationship)
    assert result.spdx_element_id == command.DOC_ELEMENT_ID
    assert result.relationship_type == RelationshipType.DESCRIBES
    assert result.related_spdx_element_id == "fake_spdx_id"


def test_GenerateOciIndexCommand_get_child_image_relationship() -> None:
    args = MagicMock()
    command = GenerateOciIndexCommand(args)

    result = command.get_child_image_relationship("fake_spdx_id")

    assert isinstance(result, Relationship)
    assert result.spdx_element_id == "fake_spdx_id"
    assert result.relationship_type == RelationshipType.VARIANT_OF
    assert result.related_spdx_element_id == command.INDEX_ELEMENT_ID


@patch(
    "mobster.cmd.generate.oci_index.GenerateOciIndexCommand.get_child_image_relationship"
)
@patch("mobster.cmd.generate.oci_index.GenerateOciIndexCommand.get_package")
@patch("mobster.cmd.generate.oci_index.json.load")
def test_GenerateOciIndexCommand_get_child_packages(
    mock_json_load: MagicMock,
    mock_get_package: MagicMock,
    mock_get_child_image_relationship: MagicMock,
) -> None:
    args = MagicMock()
    args.index_image_pullspec = "registry/repo:tag"
    args.index_image_digest = "sha256:1234567890abcdef"
    command = GenerateOciIndexCommand(args)

    mock_image = Image.from_image_index_url_and_digest(
        "registry/repo:tag", "sha256:1234567890abcdef"
    )
    mock_manifest = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": [
            {
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": "sha256:4b4976d86eefeedab6884c9d2923206c6c3c2e247120"
                "6f97fd9d7aaaecbc04ac",
                "platform": {"architecture": "amd64", "os": "linux"},
            },
            {
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": "sha256:c85623b2a5822b6e101efb05424919da653e7c15e2e3"
                "e150871c48957087d65a",
                "platform": {"architecture": "arm64", "os": "linux"},
            },
            {
                "mediaType": "fake_media_type",
                "digest": "sha256:c856",
            },
        ],
    }
    mock_json_load.return_value = mock_manifest

    result = command.get_child_packages(mock_image)

    assert mock_get_package.call_count == 2
    assert mock_get_child_image_relationship.call_count == 2

    packages, relationships = result
    assert len(packages) == 2
    assert len(relationships) == 2


@patch(
    "mobster.cmd.generate.oci_index.GenerateOciIndexCommand.get_child_image_relationship"
)
@patch("mobster.cmd.generate.oci_index.GenerateOciIndexCommand.get_package")
@patch("mobster.cmd.generate.oci_index.json.load")
def test_GenerateOciIndexCommand_get_child_packages_unknown(
    mock_json_load: MagicMock,
    mock_get_package: MagicMock,
    mock_get_child_image_relationship: MagicMock,
) -> None:
    args = MagicMock()
    args.index_image_pullspec = "registry/repo:tag"
    args.index_image_digest = "sha256:1234567890abcdef"
    command = GenerateOciIndexCommand(args)

    mock_image = Image.from_image_index_url_and_digest(
        "registry/repo:tag", "sha256:1234567890abcdef"
    )
    mock_manifest = {
        "schemaVersion": 2,
        "mediaType": "uknown_media_type",
        "manifests": [],
    }
    mock_json_load.return_value = mock_manifest

    with pytest.raises(ValueError):
        command.get_child_packages(mock_image)


@patch(
    "mobster.cmd.generate.oci_index.GenerateOciIndexCommand.get_child_image_relationship"
)
@patch("mobster.cmd.generate.oci_index.GenerateOciIndexCommand.get_package")
@patch("mobster.cmd.generate.oci_index.json.load")
def test_GenerateOciIndexCommand_get_creation_info(
    mock_json_load: MagicMock,
    mock_get_package: MagicMock,
    mock_get_child_image_relationship: MagicMock,
) -> None:
    args = MagicMock()
    args.index_image_pullspec = "registry/repo:tag"
    args.index_image_digest = "sha256:1234567890abcdef"
    command = GenerateOciIndexCommand(args)

    mock_image = Image.from_image_index_url_and_digest(
        "registry/repo:tag", "sha256:1234567890abcdef"
    )

    result = command.get_creation_info(mock_image)

    assert isinstance(result, CreationInfo)
    assert result.spdx_id == command.DOC_ELEMENT_ID


@pytest.mark.asyncio
@patch("mobster.cmd.generate.oci_index.Document")
@patch("mobster.cmd.generate.oci_index.GenerateOciIndexCommand.get_creation_info")
@patch("mobster.cmd.generate.oci_index.GenerateOciIndexCommand.get_child_packages")
@patch(
    "mobster.cmd.generate.oci_index.GenerateOciIndexCommand.get_index_image_relationship"
)
@patch("mobster.cmd.generate.oci_index.GenerateOciIndexCommand.get_package")
@patch("mobster.cmd.generate.oci_index.Image.from_image_index_url_and_digest")
async def test_GenerateOciIndexCommand_execute(
    mock_image: MagicMock,
    mock_get_package: MagicMock,
    mock_index_relationship: MagicMock,
    mock_child_packages: MagicMock,
    mock_get_creation_info: MagicMock,
    mock_doc: MagicMock,
) -> None:
    command = GenerateOciIndexCommand(MagicMock())

    mock_child_packages.return_value = ([], [])

    result = await command.execute()
    assert result == mock_doc.return_value

    mock_get_package.assert_called_once()
    mock_index_relationship.assert_called_once()
    mock_child_packages.assert_called_once()
    mock_doc.assert_called_once_with(
        creation_info=mock_get_creation_info.return_value,
        packages=[mock_get_package.return_value] + mock_child_packages.return_value[0],
        relationships=[
            mock_index_relationship.return_value,
        ]
        + mock_child_packages.return_value[1],
    )


@pytest.mark.asyncio
@patch("mobster.cmd.generate.oci_index.write_file")
async def test_GenerateOciIndexCommand_save(
    mock_write_file: MagicMock,
) -> None:
    args = MagicMock()
    args.output = "/tmp/test.json"
    command = GenerateOciIndexCommand(args)

    command._content = MagicMock()

    await command.save()

    mock_write_file.assert_called_once_with(
        command._content,
        args.output,
        validate=True,
    )
