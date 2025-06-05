from typing import Any

from mobster import get_mobster_version


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
    del actual["metadata"]["tools"]

    root_bom_ref = actual["metadata"]["component"]["bom-ref"]
    patch_bom_ref(
        actual,
        root_bom_ref,
        expected["metadata"]["component"]["bom-ref"],
    )

    assert actual == expected


def patch_bom_ref(document: Any, old: str, new: str) -> Any:
    document["metadata"]["component"]["bom-ref"] = new
    for component in document["components"]:
        if component["bom-ref"] == old:
            component["bom-ref"] = new
    for dependency in document["dependencies"]:
        if dependency["ref"] == old:
            dependency["ref"] = new
    return document
