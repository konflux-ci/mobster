# Enriching SBOMS with Mobster

The Mobster tool is capable of enriching SBOMs with AI fields found from scraping Hugging Face repositories of models included in the original SBOM

Usage
```bash
mobster enrich \
	--output output-sbom.json \
	oci-image \
	--sbom sbom.json \
	--enrichment-file enrichmentFile.json \
	--image-pullspec quay.io/konflux-ci/mobster:latest
```
## List of arguments
- `output` -- where to save the SBOM, prints it to STDOUT if this is not specified
- `enrichment-file` -- points to an CycloneDX SBOM file (in JSON format) produced by OWASP AIBOM Generator
- `sbom` -- points to an SBOM file. This can be in either SPDX or CycloneDX format
- `image-pullspec`-- the pullspec of the image processed in the format `<registry>/<repository>:<tag>`


## Example Command
mobster enrich --output enriched_sbom.json oci-image --sbom llm_compress_spdx.json --enrichment-file TinyLlama.json