import hashlib
import json
import random as rand
from collections.abc import Generator
from typing import Any

import pytest

from mobster import get_mobster_version


@pytest.fixture()
def random() -> None:
    rand.seed(42)


async def awaitable(obj: Any) -> Any:
    return obj


def assert_spdx_sbom(actual: Any, expected: Any) -> None:
    """
    Compare and assert result SPDX SBOM with the expected SBOM, handling
    dynamic fields.

    Args:
        actual (Any): actual generated SBOM dictionary
        expected (Any): expected SBOM dictionary
    """
    actual["creationInfo"]["created"] = expected["creationInfo"]["created"]
    actual["documentNamespace"] = expected["documentNamespace"]

    assert (
        f"Tool: Mobster-{get_mobster_version()}" in actual["creationInfo"]["creators"]
    )
    # Remove the Tool: Mobster entry from creators, as it's not in the expected result
    actual["creationInfo"]["creators"] = [
        creator
        for creator in actual["creationInfo"]["creators"]
        if "Mobster" not in creator
    ]

    assert actual == expected


def assert_cdx_sbom(actual: Any, expected: Any) -> None:
    """
    Compare and assert a result CDX SBOM with the expected SBOM, handling
    dynamic fields.

    Args:
        actual (Any): actual generated SBOM dictionary
        expected (Any): expected SBOM dictionary
    """
    actual["serialNumber"] = expected["serialNumber"]
    actual["metadata"]["timestamp"] = expected["metadata"]["timestamp"]

    assert {
        "type": "application",
        "name": "Mobster",
        "version": get_mobster_version(),
    } in actual["metadata"]["tools"]["components"]

    root_bom_ref = actual["metadata"]["component"]["bom-ref"]
    patch_bom_ref(
        actual,
        root_bom_ref,
        expected["metadata"]["component"]["bom-ref"],
    )
    ignored_keys = {"metadata"}

    for key in {*actual.keys(), *expected.keys()}:
        if key in ignored_keys:
            continue

        assert actual.get(key) == expected.get(key)


def patch_bom_ref(document: Any, old: str, new: str) -> Any:
    document["metadata"]["component"]["bom-ref"] = new
    for component in document["components"]:
        if component["bom-ref"] == old:
            component["bom-ref"] = new
    for dependency in document["dependencies"]:
        if dependency["ref"] == old:
            dependency["ref"] = new
    return document


def random_digest() -> str:
    """
    Generate a random SHA256 digest.

    Returns:
        str: A properly formatted SHA256 digest string (e.g., 'sha256:abc123...')
    """
    random_bytes = rand.randbytes(32)
    digest_hash = hashlib.sha256(random_bytes).hexdigest()
    return f"sha256:{digest_hash}"


@pytest.fixture(scope="session")
def sample1_parsed_dockerfile() -> dict[str, Any]:
    with open("tests/data/dockerfiles/sample1/parsed.json") as json_file:
        return json.load(json_file)  # type: ignore[no-any-return]


@pytest.fixture(scope="session")
def sample2_parsed_dockerfile() -> dict[str, Any]:
    with open("tests/data/dockerfiles/sample2/parsed.json") as json_file:
        return json.load(json_file)  # type: ignore[no-any-return]


@pytest.fixture(scope="session")
def spdx_sbom_skeleton() -> Generator[dict[str, Any], Any, Any]:
    yield {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "foo",
        "documentNamespace": "https://foo.example.com/bar",
        "creationInfo": {
            "created": "1970-01-01T00:00:00Z",
            "creators": ["Tool: Konflux"],
        },
    }
