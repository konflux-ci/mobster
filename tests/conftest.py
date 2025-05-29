from typing import Any

from mobster import get_mobster_version


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

    assert actual == expected
