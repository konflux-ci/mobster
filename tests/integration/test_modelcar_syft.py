"""Integration tests for modelcar base-image Syft scanning.

Pulls a real UBI micro image so Syft emits LicenseRef-* expressions that
require hasExtractedLicensingInfos — the failure mode unit fixtures miss.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest
from cyclonedx.model.bom import Bom
from spdx_tools.spdx.model.document import Document
from spdx_tools.spdx.parser.parse_anything import parse_file
from spdx_tools.spdx.validation.document_validator import validate_full_spdx_document

from mobster.cmd.generate.modelcar import GenerateModelcarCommand

# Pinned linux/amd64 digest (ubi9/ubi-micro). Syft must be able to pull this.
_UBI_MICRO = (
    "registry.access.redhat.com/ubi9/ubi-micro@"
    "sha256:7e7f79ab747bf2b452e3043dd89f388e92be4c7fdcc8b815b58adf6c99c39c95"
)
_FAKE = (
    "quay.io/example/modelcar-it:test@"
    "sha256:0000000000000000000000000000000000000000000000000000000000000001"
)


def _modelcar_args(sbom_type: str, output: Path) -> MagicMock:
    args = MagicMock()
    args.modelcar_image = _FAKE
    args.base_image = _UBI_MICRO
    args.model_image = _FAKE.replace("modelcar-it", "model-it")
    args.sbom_type = sbom_type
    args.skip_validation = False
    args.output = output
    return args


@pytest.mark.asyncio
@pytest.mark.slow
@pytest.mark.fail_slow("3m")
@pytest.mark.skipif(shutil.which("syft") is None, reason="syft binary not installed")
@pytest.mark.parametrize("sbom_type", ["spdx", "cyclonedx"])
async def test_modelcar_syft_scan_produces_valid_sbom(
    tmp_path: Path,
    sbom_type: str,
) -> None:
    """Generate modelcar SBOM with a real Syft base scan; both formats must validate."""
    output = tmp_path / f"modelcar.{sbom_type}.json"
    command = GenerateModelcarCommand(_modelcar_args(sbom_type, output))

    await command.execute()
    await command.save()

    assert output.is_file()
    assert output.stat().st_size > 0

    if sbom_type == "spdx":
        _assert_valid_spdx(command.content, output)
    else:
        _assert_valid_cyclonedx(command.content, output)


def _assert_valid_spdx(content: Any, output: Path) -> None:
    assert isinstance(content, Document)
    # Composition root + base + model, plus Syft inventory under base.
    assert len(content.packages or []) > 3
    assert content.extracted_licensing_info

    messages = validate_full_spdx_document(content)
    license_msgs = [
        msg
        for msg in messages
        if "Unrecognized license reference" in msg.validation_message
    ]
    assert license_msgs == [], license_msgs
    assert messages == [], messages

    # Round-trip through the writer/parser path used on save.
    parsed = parse_file(str(output))
    assert validate_full_spdx_document(parsed) == []


def _assert_valid_cyclonedx(content: Any, output: Path) -> None:
    assert isinstance(content, Bom)
    assert len(list(content.components)) > 3
    content.validate()

    # Round-trip the written JSON the same way generate loads Syft CDX.
    loaded = Bom.from_json(  # type: ignore[attr-defined]
        json.loads(output.read_text(encoding="utf-8"))
    )
    loaded.validate()
