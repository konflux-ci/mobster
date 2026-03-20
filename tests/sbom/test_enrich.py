from pathlib import Path

import pytest
from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component, ComponentType
from packageurl import PackageURL
from spdx_tools.common.spdx_licensing import spdx_licensing
from spdx_tools.spdx.model.actor import Actor, ActorType
from spdx_tools.spdx.model.document import Document
from spdx_tools.spdx.model.package import Package

from mobster.cmd.generate.oci_image.spdx_utils import (
    get_annotations_by_spdx_id,
    get_package_by_spdx_id,
)
from mobster.sbom.enrich import enrich_sbom


@pytest.fixture
def data_dir() -> Path:
    """Path to the directory for storing SBOM sample test data."""
    return Path(__file__).parent / "test_enrich_data"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "spdx_sbom, owasp_spdx_sbom",
    [
        (Path("llm_compress_spdx.json"), Path("tinyllama_owasp_cdx.json")),
    ],
)
async def test_enrich_sboms_spdx_cdx(
    spdx_sbom: Path,
    owasp_spdx_sbom: Path,
    data_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(data_dir)
    spdx_sbom_path = data_dir / spdx_sbom
    owasp_sbom_path = data_dir / owasp_spdx_sbom

    new_sbom: Bom | Document = await enrich_sbom(spdx_sbom_path, owasp_sbom_path)

    assert isinstance(new_sbom, Document)

    assert new_sbom is not None

    # check that the tooling info got added
    OWASP_tool = Actor(actor_type=ActorType.TOOL, name="OWASP AIBOM Generator")
    assert OWASP_tool in new_sbom.creation_info.creators

    assert len(new_sbom.annotations) == 4
    tinyllama_spdx_id = (
        "SPDXRef-Package-TinyLlama-TinyLlama-1.1B-Chat-v1.0"
        "-fe8a4ea1ffedaf415f4da2f062534de366a451e6"
        "-73b429a44483c2784ea71c729a66a7af241da4feec573255c760b7f94dc49c6f"
    )

    tinyllama_annotations = get_annotations_by_spdx_id(new_sbom, tinyllama_spdx_id)
    assert len(tinyllama_annotations) == 3
    package: Package | None = get_package_by_spdx_id(new_sbom, tinyllama_spdx_id)
    assert package is not None
    assert package.supplier is not None and package.supplier.name == "TinyLlama"  # type: ignore[union-attr]

    lice = spdx_licensing.parse("apache-2.0")
    assert package.license_concluded is not None and package.license_concluded == lice
    assert package.description is None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "llm_compress_cdx, tiny_llama_owasp",
    [
        (Path("llm_compress_cdx.json"), Path("tinyllama_owasp_cdx.json")),
    ],
)
async def test_enrich_sboms_cdx_cdx(
    llm_compress_cdx: Path,
    tiny_llama_owasp: Path,
    data_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(data_dir)
    original_sbom_path = data_dir / llm_compress_cdx
    new_sbom_path = data_dir / tiny_llama_owasp

    new_sbom: Bom | Document = await enrich_sbom(original_sbom_path, new_sbom_path)

    assert isinstance(new_sbom, Bom)

    tiny_llama_purl_str = (
        "pkg:huggingface/TinyLlama/"
        "TinyLlama-1.1B-Chat-v1.0"
        "@fe8a4ea1ffedaf415f4da2f062534de366a451e6"
    )
    tiny_llama_purl = PackageURL.from_string(tiny_llama_purl_str)

    owasp_tool = Component(
        name="OWASP AIBOM Generator",
        type=ComponentType.APPLICATION,
    )

    assert owasp_tool in new_sbom.metadata.tools.components

    for component in new_sbom.components:
        if component.purl == tiny_llama_purl:
            assert component.model_card is not None
            model_card = component.model_card
            assert model_card["properties"] is not None
            assert len(model_card["properties"]) == 10
            assert model_card["modelParameters"] is not None
            assert len(model_card["modelParameters"]) == 5
