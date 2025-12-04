# Mobster Enrich Architecture

Use Case: Mobster can produce SBOMs in CycloneDX format
Steps:
1. Matches the PURL from A to a PURL in B. Will only enrich the component for which the PURLs match
  The OWASP hugging face tool only keeps the first 8 characters of the version. Therefore, versions of PURLS
  are compared based ont he first 8 characters
2. Adds OWASP AIBOM generator to tools (accounts for version 1.5 and 1.6)
    {
        "name": "owasp-aibom-generator",
        "version": "1.0.2"
    }
3. Enriches the modelCard in the component in A
    a) If the modelCard field does not exist, just copies the whole modelCard over from SBOM B into SBOM A
    b) If the modelCard field does exist, performs a complete merge of model cards (preferring fields in A to B)

Example 1:
SBOM A: [LLM Compress CDX](../../tests/sbom/test_enrich_data/llm_compress_cdx.json)
SBOM B: [Tiny Llama SBOM](../../tests/sbom/test_enrich_data/tinyllama_owasp_cdx.json)
Expected Output: [Enriched SBOM](../../tests/sbom/test_enrich_data/enriched_sbom_cdx.json)
(just adds the whole modelCard from B into A)


Example 2:
SBOM A: [LLM Compress CDX](../../tests/sbom/test_enrich_data/llm_compress_cdx_modelCard.json)
SBOM B: [Tiny Llama SBOM](../../tests/sbom/test_enrich_data/tinyllama_owasp_cdx.json)
Expected Output: [Enriched SBOM](../../tests/sbom/test_enrich_data/enriched_sbom_cdx.json)
(merges two modelCards)