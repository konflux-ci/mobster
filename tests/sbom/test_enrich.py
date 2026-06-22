from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest
from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component
from packageurl import PackageURL

from mobster.cmd.cyclonedx_wrapper import CycloneDX1BomWrapper
from mobster.sbom.enrich import (
    CycloneDXEnricher,
    _create_enricher,
    all_purls,
    compare_purls,
    enrich_sbom,
)


@pytest.fixture
def data_dir() -> Path:
    """Path to the directory for storing SBOM sample test data."""
    return Path(__file__).parent / "test_enrich_data"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "llm_compress_cdx, tiny_llama_owasp",
    [
        (Path("llm_compress_cdx.json"), Path("tinyllama_owasp_cdx.json")),
    ],
)
async def test_enrich_sboms_cdx1_no_model_card(
    llm_compress_cdx: Path,
    tiny_llama_owasp: Path,
    data_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(data_dir)
    original_sbom_path = data_dir / llm_compress_cdx
    new_sbom_path = data_dir / tiny_llama_owasp

    new_sbom: CycloneDX1BomWrapper = await enrich_sbom(
        original_sbom_path, new_sbom_path
    )

    model_card_b = {
        "modelParameters": {
            "task": "text-generation",
            "modelArchitecture": "llama",
            "datasets": [
                {
                    "type": "dataset",
                    "name": "cerebras/SlimPajama-627B",
                    "contents": {
                        "url": "https://huggingface.co/datasets/cerebras/SlimPajama-627B"
                    },
                },
                {
                    "type": "dataset",
                    "name": "bigcode/starcoderdata",
                    "contents": {
                        "url": "https://huggingface.co/datasets/bigcode/starcoderdata"
                    },
                },
                {
                    "type": "dataset",
                    "name": "HuggingFaceH4/ultrachat_200k",
                    "contents": {
                        "url": "https://huggingface.co/datasets/HuggingFaceH4/ultrachat_200k"
                    },
                },
                {
                    "type": "dataset",
                    "name": "HuggingFaceH4/ultrafeedback_binarized",
                    "contents": {
                        "url": "https://huggingface.co/datasets/HuggingFaceH4/ultrafeedback_binarized"
                    },
                },
            ],
            "inputs": [{"format": "string"}],
            "outputs": [{"format": "string"}],
        },
        "properties": [
            {"name": "genai:aibom:modelcard:vocabSize", "value": "32000"},
            {"name": "genai:aibom:modelcard:tokenizerClass", "value": "LlamaTokenizer"},
            {
                "name": "serialNumber",
                "value": "urn:uuid:TinyLlama-TinyLlama-1.1B-Chat-v1.0",
            },
        ],
    }

    assert isinstance(new_sbom, CycloneDX1BomWrapper)

    tiny_llama_purl_str = (
        "pkg:huggingface/TinyLlama/"
        "TinyLlama-1.1B-Chat-v1.0"
        "@fe8a4ea1ffedaf415f4da2f062534de366a451e6"
    )
    tiny_llama_purl = PackageURL.from_string(tiny_llama_purl_str)

    for component in new_sbom.sbom.components:
        assert new_sbom.model_cards is not None
        if component.purl == tiny_llama_purl:
            assert new_sbom.model_cards[tiny_llama_purl] is not None
            model_card = new_sbom.model_cards[tiny_llama_purl]
            assert model_card == model_card_b

            assert len(component.external_references) == 8


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "llm_compress_cdx, tiny_llama_owasp",
    [
        (Path("llm_compress_cdx_modelCard.json"), Path("tinyllama_owasp_cdx.json")),
    ],
)
async def test_enrich_sboms_cdx1_model_card(
    llm_compress_cdx: Path,
    tiny_llama_owasp: Path,
    data_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(data_dir)
    original_sbom_path = data_dir / llm_compress_cdx
    new_sbom_path = data_dir / tiny_llama_owasp

    new_sbom: CycloneDX1BomWrapper = await enrich_sbom(
        original_sbom_path, new_sbom_path
    )

    model_card_b = {
        "modelParameters": {
            "task": "text-generation",
            "modelArchitecture": "llama",
            "datasets": [
                {
                    "type": "dataset",
                    "name": "cerebras/SlimPajama-627B",
                    "contents": {
                        "url": "https://huggingface.co/datasets/cerebras/SlimPajama-627B"
                    },
                },
                {
                    "type": "dataset",
                    "name": "bigcode/starcoderdata",
                    "contents": {
                        "url": "https://huggingface.co/datasets/bigcode/starcoderdata"
                    },
                },
                {
                    "type": "dataset",
                    "name": "HuggingFaceH4/ultrachat_200k",
                    "contents": {
                        "url": "https://huggingface.co/datasets/HuggingFaceH4/ultrachat_200k"
                    },
                },
                {
                    "type": "dataset",
                    "name": "HuggingFaceH4/ultrafeedback_binarized",
                    "contents": {
                        "url": "https://huggingface.co/datasets/HuggingFaceH4/ultrafeedback_binarized"
                    },
                },
            ],
            "inputs": [{"format": "string"}],
            "outputs": [{"format": "string"}],
        },
        "properties": [
            {"name": "genai:aibom:modelcard:vocabSize", "value": "32000"},
            {"name": "genai:aibom:modelcard:tokenizerClass", "value": "LlamaTokenizer"},
            {
                "name": "serialNumber",
                "value": "urn:uuid:TinyLlama-TinyLlama-1.1B-Chat-v1.0",
            },
            {"name": "bomFormat", "value": "CycloneDX"},
        ],
    }

    assert isinstance(new_sbom, CycloneDX1BomWrapper)

    tiny_llama_purl_str = (
        "pkg:huggingface/TinyLlama/"
        "TinyLlama-1.1B-Chat-v1.0"
        "@fe8a4ea1ffedaf415f4da2f062534de366a451e6"
    )
    tiny_llama_purl = PackageURL.from_string(tiny_llama_purl_str)

    for component in new_sbom.sbom.components:
        assert new_sbom.model_cards is not None
        if component.purl == tiny_llama_purl:
            assert new_sbom.model_cards[tiny_llama_purl] is not None
            model_card = new_sbom.model_cards[tiny_llama_purl]
            assert model_card == model_card_b

            assert len(component.external_references) == 8


def test_all_purls_with_none_purl() -> None:
    """Test all_purls function when a component has no purl."""
    mock_component_with_purl = MagicMock(spec=Component)
    mock_component_with_purl.purl = PackageURL.from_string("pkg:pypi/test@1.0.0")

    mock_component_without_purl = MagicMock(spec=Component)
    mock_component_without_purl.purl = None

    components = [mock_component_with_purl, mock_component_without_purl]

    result = all_purls(components)

    assert len(result) == 1
    assert PackageURL.from_string("pkg:pypi/test@1.0.0") in result


def test_compare_purls_with_none_version() -> None:
    """Test compare_purls when one purl has None version."""
    p1 = PackageURL(type="pypi", name="test", version=None)
    p2 = PackageURL(type="pypi", name="test", version="1.0.0")

    assert not compare_purls(p1, p2)


def test_compare_purls_truncated_version() -> None:
    """Test compare_purls with truncated versions."""
    p1 = PackageURL(type="pypi", name="test", version="1.0.0abcdefgh")
    p2 = PackageURL(type="pypi", name="test", version="1.0.0abc")

    assert compare_purls(p1, p2)


def test_create_enricher_cyclonedx() -> None:
    """Test _create_enricher creates CycloneDXEnricher for CycloneDX SBOMs."""
    sbom = {"bomFormat": "CycloneDX"}
    enricher = _create_enricher(sbom)
    assert isinstance(enricher, CycloneDXEnricher)


def test_create_enricher_non_cyclonedx() -> None:
    """Test _create_enricher raises ValueError for non-CycloneDX SBOMs."""
    sbom = {"bomFormat": "SPDX"}
    with pytest.raises(ValueError, match="ERROR, expected SBOM to be in CycloneDX"):
        _create_enricher(sbom)


@pytest.mark.asyncio
async def test_enrich_sbom_missing_target() -> None:
    """Test enrich_sbom raises ValueError when target_sbom is None."""
    with pytest.raises(ValueError, match="A target SBOM path and an incoming"):
        await enrich_sbom(None, Path("some_path.json"))  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_enrich_sbom_missing_incoming() -> None:
    """Test enrich_sbom raises ValueError when incoming_sbom is None."""
    with pytest.raises(ValueError, match="A target SBOM path and an incoming"):
        await enrich_sbom(Path("some_path.json"), None)  # type: ignore[arg-type]


def test_get_owasp_tool_not_found() -> None:
    """Test get_owasp_tool raises ValueError when OWASP tool is not found."""
    enricher = CycloneDXEnricher()
    mock_sbom = MagicMock(spec=CycloneDX1BomWrapper)
    mock_tool = MagicMock()
    mock_tool.name = "some-other-tool"
    mock_sbom.sbom = MagicMock(spec=Bom)
    mock_sbom.sbom.metadata.tools.components = [mock_tool]

    with pytest.raises(ValueError, match="OWASP tool not found in SBOM metadata"):
        enricher.get_owasp_tool(mock_sbom)


def test_enrich_components_no_external_refs_in_a() -> None:
    """Test enrich_components when component_a has no external_references."""
    enricher = CycloneDXEnricher()

    mock_sbom_a = MagicMock(spec=CycloneDX1BomWrapper)
    mock_sbom_b = MagicMock(spec=CycloneDX1BomWrapper)

    mock_component_a = MagicMock(spec=Component)
    mock_component_a.purl = PackageURL.from_string("pkg:pypi/test@1.0.0")
    mock_component_a.external_references = None

    mock_component_b = MagicMock(spec=Component)
    mock_component_b.purl = PackageURL.from_string("pkg:pypi/test@1.0.0")
    mock_ext_ref = MagicMock()
    mock_component_b.external_references = [mock_ext_ref]

    mock_sbom_a.model_cards = {}
    mock_sbom_b.model_cards = {mock_component_a.purl: {}}

    enricher.enrich_components(
        mock_sbom_a, mock_sbom_b, mock_component_a, mock_component_b
    )

    assert mock_component_a.external_references == [mock_ext_ref]


def test_merge_model_cards_none_purl() -> None:
    """Test merge_model_cards returns early when component_a.purl is None."""
    enricher = CycloneDXEnricher()

    mock_sbom_a = MagicMock(spec=CycloneDX1BomWrapper)
    mock_sbom_b = MagicMock(spec=CycloneDX1BomWrapper)

    mock_component_a = MagicMock(spec=Component)
    mock_component_a.purl = None

    result = enricher.merge_model_cards(mock_sbom_a, mock_sbom_b, mock_component_a)
    assert result is None


def test_combine_model_parameters() -> None:
    """Test combine_model_parameters merges model parameters correctly."""
    enricher = CycloneDXEnricher()

    param_a = {
        "task": "text-generation",
        "datasets": [{"ref": "dataset1"}],
        "inputs": [{"format": "string"}],
    }

    param_b = {
        "task": "translation",
        "datasets": [{"ref": "dataset2"}],
        "outputs": [{"format": "json"}],
    }

    result = enricher.combine_model_parameters(param_a, param_b)

    assert result["task"] == "text-generation"
    assert len(result["datasets"]) == 2
    assert result["inputs"] == [{"format": "string"}]
    assert result["outputs"] == [{"format": "json"}]


def test_combine_considerations() -> None:
    """Test combine_considerations merges considerations correctly."""
    enricher = CycloneDXEnricher()

    cons_a = {
        "users": ["user1"],
        "useCases": ["case1"],
        "ethicalConsiderations": [{"name": "ethical1"}],
        "environmentalConsiderations": {"energyConsumptions": [{"type": "energy1"}]},
    }

    cons_b = {
        "users": ["user2"],
        "technicalLimitations": ["limit1"],
        "ethicalConsiderations": [{"name": "ethical2"}],
        "environmentalConsiderations": {"energyConsumptions": [{"type": "energy2"}]},
    }

    result = enricher.combine_considerations(cons_a, cons_b)

    assert len(result["users"]) == 2
    assert result["technicalLimitations"] == ["limit1"]
    assert len(result["ethicalConsiderations"]) == 2
    assert len(result["environmentalConsiderations"]["energyConsumptions"]) == 2


def test_combine_environmental_considerations() -> None:
    """Test combine_environmental_considerations merges environmental data."""
    enricher = CycloneDXEnricher()

    env_a = {"energyConsumptions": [{"type": "energy1"}]}

    env_b = {"energyConsumptions": [{"type": "energy2"}]}

    result = enricher.combine_environmental_considerations(env_a, env_b)

    assert len(result["energyConsumptions"]) == 2


def test_merge_general_both_none() -> None:
    """Test merge_general when both inputs are None."""
    enricher = CycloneDXEnricher()

    def dummy_func(a: Any, b: Any) -> Any:
        return a + b

    result = enricher.merge_general(None, None, dummy_func)
    assert result is None


def test_merge_general_a_none() -> None:
    """Test merge_general when first input is None."""
    enricher = CycloneDXEnricher()

    def dummy_func(a: Any, b: Any) -> Any:
        return a + b

    result = enricher.merge_general(None, [1, 2], dummy_func)
    assert result == [1, 2]


def test_merge_general_b_none() -> None:
    """Test merge_general when second input is None."""
    enricher = CycloneDXEnricher()

    def dummy_func(a: Any, b: Any) -> Any:
        return a + b

    result = enricher.merge_general([1, 2], None, dummy_func)
    assert result == [1, 2]


@pytest.mark.asyncio
async def test_cyclonedx_enricher_non_cyclonedx_incoming() -> None:
    """Test CycloneDXEnricher logs exception when incoming SBOM is not CycloneDX."""
    enricher = CycloneDXEnricher()

    target_sbom = {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []}

    incoming_sbom = {"bomFormat": "SPDX", "spdxVersion": "SPDX-2.3"}

    # The method should handle the ValueError and log it
    result = await enricher.enrich(target_sbom, incoming_sbom)

    # Result should still be a valid wrapper, just without enrichment
    assert isinstance(result, CycloneDX1BomWrapper)
