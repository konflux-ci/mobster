from pathlib import Path

import pytest
from packageurl import PackageURL

from mobster.cmd.cyclonedx_wrapper import CycloneDX1BomWrapper
from mobster.sbom.enrich import enrich_sbom


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
