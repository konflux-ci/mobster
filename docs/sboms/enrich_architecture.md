# Mobster Enrich Architecture

NOTE: Incoming SBOM (B) from OWASP AIBOM Generator will always be of CycloneDX Format

## Case 1: Original SBOM (A) is in SPDX format
Use Case: Mobster can produce SBOMs in SPDX format
Steps
1. Matches the HF PURL from A to a PURL in B. Will only enrich the package for which the PURLs match (ignores the version number)
2. Extracts fields from B (refer to extraction below for how/ what it extracts)
3. Adds OWASP AIBOM generator as a tool in "creators"
    ```"Tool: OWASP AIBOM Generator"```
4. Enriches the package in A with the fields extracted from B. There are three cases for this:
    a) There are three top level fields that are added if they are in B these are:
          CDX          SPDX
      1. suppliedBy -> supplier
      2. description -> description
      3. licenses -> licenseConcluded
    b) AI Specific fields: Adds the AI specific fields as annotations to B.
        NOTE: Currently, Mobster only supports up to SPDX 2.3, and AI fields are introduced in SPDX 3.0.
        Therefore, any specific fields must be added as annotations rather than as top level fields
Example:
SBOM A: [LLM Compress SPDX](../../tests/sbom/test_enrich_data/llm_compress_spdx.json)
```
{
      "SPDXID": "SPDXRef-Package-TinyLlama-TinyLlama-1.1B-Chat-v1.0-fe8a4ea1ffedaf415f4da2f062534de366a451e6-73b429a44483c2784ea71c729a66a7af241da4feec573255c760b7f94dc49c6f",
      "annotations": [
        {
          "annotationDate": "2025-10-29T14:26:43Z",
          "annotationType": "OTHER",
          "annotator": "Tool: cachi2:jsonencoded",
          "comment": "{\"name\": \"cachi2:found_by\", \"value\": \"cachi2\"}"
        }
      ],
      "downloadLocation": "NOASSERTION",
      "externalRefs": [
        {
          "referenceCategory": "PACKAGE_MANAGER",
          "referenceLocator": "pkg:huggingface/TinyLlama/TinyLlama-1.1B-Chat-v1.0@fe8a4ea1ffedaf415f4da2f062534de366a451e6",
          "referenceType": "purl"
        }
      ],
      "filesAnalyzed": true,
      "name": "TinyLlama/TinyLlama-1.1B-Chat-v1.0",
      "versionInfo": "fe8a4ea1ffedaf415f4da2f062534de366a451e6"
    }
```
SBOM B: [Tiny Llama SBOM](../../tests/sbom/test_enrich_data/tinyllama_owasp_cdx.json)
```
"modelCard": {
        "modelParameters": {
          "architectureFamily": "llama",
          "inputs": [
            {
              "format": "text"
            }
          ],
          "modelArchitecture": "TinyLlama-1.1B-Chat-v1.0ForCausalLM",
          "outputs": [
            {
              "format": "generated-text"
            }
          ],
          "task": "text-generation"
        },
        "properties": [
          {
            "name": "bomFormat",
            "value": "CycloneDX"
          },
          {
            "name": "specVersion",
            "value": "1.6"
          },
          {
            "name": "serialNumber",
            "value": "urn:uuid:TinyLlama-TinyLlama-1.1B-Chat-v1.0"
          },
          {
            "name": "version",
            "value": "1.0.0"
          },
          {
            "name": "primaryPurpose",
            "value": "text-generation"
          },
          {
            "name": "suppliedBy",
            "value": "TinyLlama"
          },
          {
            "name": "licenses",
            "value": "apache-2.0"
          },
          {
            "name": "typeOfModel",
            "value": "llama"
          },
          {
            "name": "downloadLocation",
            "value": "https://huggingface.co/TinyLlama/TinyLlama-1.1B-Chat-v1.0/tree/main"
          },
          {
            "name": "external_references",
            "value": "[{\"type\": \"website\", \"url\": \"https://huggingface.co/TinyLlama/TinyLlama-1.1B-Chat-v1.0\", \"comment\": \"Model repository\"}, {\"type\": \"distribution\", \"url\": \"https://huggingface.co/TinyLlama/TinyLlama-1.1B-Chat-v1.0/tree/main\", \"comment\": \"Model files\"}]"
          }
        ],
        "quantitativeAnalysis": {
          "graphics": {}
        }
      }
```
Expected Output: [Enriched SBOM](../../tests/sbom/test_enrich_data/enriched_sbom_spdx.json)
```
{
      "SPDXID": "SPDXRef-Package-TinyLlama-TinyLlama-1.1B-Chat-v1.0-fe8a4ea1ffedaf415f4da2f062534de366a451e6-73b429a44483c2784ea71c729a66a7af241da4feec573255c760b7f94dc49c6f",
      "annotations": [
        {
          "annotationDate": "2025-10-29T14:26:43Z",
          "annotationType": "OTHER",
          "annotator": "Tool: cachi2:jsonencoded",
          "comment": "{\"name\": \"cachi2:found_by\", \"value\": \"cachi2\"}"
        },
        {
          "annotationDate": "2025-12-18T15:15:13Z",
          "annotationType": "OTHER",
          "annotator": "Tool: OWASP AIBOM Generator",
          "comment": "ai_intendedUse : text-generation"
        },
        {
          "annotationDate": "2025-12-18T15:15:13Z",
          "annotationType": "OTHER",
          "annotator": "Tool: OWASP AIBOM Generator",
          "comment": "ai_typeOfModel : llama"
        }
      ],
      "downloadLocation": "NOASSERTION",
      "externalRefs": [
        {
          "referenceCategory": "PACKAGE_MANAGER",
          "referenceLocator": "pkg:huggingface/TinyLlama/TinyLlama-1.1B-Chat-v1.0@fe8a4ea1ffedaf415f4da2f062534de366a451e6",
          "referenceType": "purl"
        }
      ],
      "filesAnalyzed": true,
      "name": "TinyLlama/TinyLlama-1.1B-Chat-v1.0",
      "versionInfo": "fe8a4ea1ffedaf415f4da2f062534de366a451e6",
      "supplier": "TinyLlama",
      "licenseConcluded": "apache-2.0"
    }
```
# Case 2: Original SBOM (A) is in CDX format
Use Case: Mobster can produce SBOMs in CycloneDX format
Steps:
1. Matches the PURL from A to a PURL in B. Will only enrich the component for which the PURLs match (ignores the version number)
2. Adds OWASP AIBOM generator to tools (accounts for version 1.5 and 1.6)
     {
        "name": "OWASP AIBOM Generator",
        "version": "1.0.0"
    }
3. Enriches the modelCard in the component in A
    a) If the modelCard field does not exist, just copies the whole modelCard over from SBOM B into SBOM A
    b) If the modelCard field does exist, performs a complete merge of model cards (preferring fields in A to B)

Example:
SBOM A: [LLM Compress CDX](../../tests/sbom/test_enrich_data/enriched_sbom_cdx.json)
SBOM B: [Tiny Llama SBOM](../../tests/sbom/test_enrich_data/tinyllama_owasp_cdx.json)
Expected Output: [Enriched SBOM](../../tests/sbom/test_enrich_data/enriched_sbom_cdx.json)
(just adds the whole modelCard from B into A)



# How fields are extracted from the SBOM B for an SPDX SBOM
The relevant AI fields live in the Components.ModelCard section of SBOM B.

Documentation for CycloneDX lives here: https://cyclonedx.org/docs/1.7/json/#metadata_tools_oneOf_i0_components_items_modelCard

ModelCard.Properties is the field that the extraction targets. In CycloneDX, the fields in properties can have any (name,value) pair. However, the OWASP Hugging Face tool has provided a spec for which (name,value) pairs in properties correspond to SPDX 3.0 AI fields. Since Mobster does not support AI fields, these fields must be added as annotations. However, to remain consistent with SPDX the names are changed to their SPDX 3.0 equivalency (even though it just an annotation). This is done with the goal that, when Mobster does support SPDX 3.0, the names will already be in SPDX convention (as SPDX 3.0 does have a prescriptive list of fields that it allows)
OWASP AIBOM mappings: https://github.com/GenAI-Security-Project/aibom-generator/tree/main/docs/aibom-field-mapping

The other parts of SBOM B are ignored. As far as I can tell, they are there more for structure (to make it a complete CycloneDX SBOM) and do not provide any more relevant information.

Currently, besides Properties, the other fields in ModelCard are ignored for an SPDX 2.3 SBOM. This is done because there are no direct mappings for other fields, and also as to not overcrowd with too many annotations.

