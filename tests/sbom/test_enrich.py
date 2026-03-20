from mobster.sbom.enrich import enrich_sbom
from pathlib import Path
import asyncio
import json

import pytest

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
    owasp_spdx_sbom:Path,
    data_dir: Path,
    monkeypatch: pytest.MonkeyPatch,     
):
    monkeypatch.chdir(data_dir)
    spdx_sbom_path = data_dir / spdx_sbom
    owasp_sbom_path = data_dir / owasp_spdx_sbom

    
    new_sbom = await enrich_sbom(spdx_sbom_path, owasp_sbom_path)
    with open('enriched_sbom.json', 'w') as f:
        json.dump(new_sbom, f, indent=2)

@pytest.mark.asyncio
@pytest.mark.parametrize(
    "spdx_sbom, mock",
    [
        (Path("llm_compress_spdx.json"), Path("mock_enrichment_format.json")),
    ],
)
async def test_enrich_sboms_spdx_json(
    spdx_sbom: Path,
    mock:Path,
    data_dir: Path,
    monkeypatch: pytest.MonkeyPatch,     
):
    monkeypatch.chdir(data_dir)
    spdx_sbom_path = data_dir / spdx_sbom
    mock_sbom_path = data_dir / mock
    
    new_sbom = await enrich_sbom(spdx_sbom_path, mock_sbom_path)
    with open('enriched_sbom_mock.json', 'w') as f:
        json.dump(new_sbom, f, indent=2)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "llm_compress_cdx, tiny_llama_owasp",
    [
        (Path("llm_compress_cdx.json"), Path("tinyllama_owasp_cdx.json")),
    ],
)
async def test_enrich_sboms_cdx_cdx(
    llm_compress_cdx: Path,
    tiny_llama_owasp:Path,
    data_dir: Path,
    monkeypatch: pytest.MonkeyPatch,     
):
    monkeypatch.chdir(data_dir)
    original_sbom_path = data_dir / llm_compress_cdx
    new_sbom_path = data_dir / tiny_llama_owasp
    
    new_sbom = await enrich_sbom(original_sbom_path, new_sbom_path)
    with open('enriched_sbom_new.json', 'w') as f:
        json.dump(new_sbom, f, indent=2)

@pytest.mark.asyncio
@pytest.mark.parametrize(
    "llm_compress_cdx, mock_enrichement",
    [
        (Path("llm_compress_cdx.json"), Path("mock_enrichment_format.json")),
    ],
)
async def test_enrich_sboms_cdx_json(
    llm_compress_cdx: Path,
    mock_enrichement:Path,
    data_dir: Path,
    monkeypatch: pytest.MonkeyPatch,     
):
    monkeypatch.chdir(data_dir)
    original_sbom_path = data_dir / llm_compress_cdx
    mock_sbom_path = data_dir / mock_enrichement
    
    new_sbom = await enrich_sbom(original_sbom_path, mock_sbom_path)
    with open('enriched_sbom_mock.json', 'w') as f:
        json.dump(new_sbom, f, indent=2)