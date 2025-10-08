import contextlib
import hashlib
import json
import random as rand
from collections.abc import Callable, Generator
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest
from spdx_tools.spdx.model.actor import Actor, ActorType
from spdx_tools.spdx.model.annotation import Annotation, AnnotationType
from spdx_tools.spdx.model.document import Document
from spdx_tools.spdx.model.package import Package
from spdx_tools.spdx.model.relationship import Relationship, RelationshipType
from spdx_tools.spdx.model.spdx_no_assertion import SpdxNoAssertion
from spdx_tools.spdx.parser.parse_anything import parse_file

from mobster import get_mobster_version
from mobster.cmd.upload.tpa import TPAClient
from mobster.sbom.spdx import get_mobster_tool_string


@pytest.fixture
def tpa_env_vars(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Set up environment variables needed for TPA commands.
    """
    monkeypatch.setenv("MOBSTER_TPA_SSO_TOKEN_URL", "https://test.token.url")
    monkeypatch.setenv("MOBSTER_TPA_SSO_ACCOUNT", "test-account")
    monkeypatch.setenv("MOBSTER_TPA_SSO_TOKEN", "test-token")


@pytest.fixture
def mock_tpa_client() -> AsyncMock:
    """
    Create a mock TPA client that returns success for uploads.
    """
    mock = AsyncMock(spec=TPAClient)
    mock.upload_sbom = AsyncMock(
        return_value="urn:uuid:12345678-1234-5678-9012-123456789012"
    )
    mock.__aenter__ = AsyncMock(return_value=mock)
    mock.__aexit__ = AsyncMock(return_value=None)
    return mock


@pytest.fixture
def mock_tpa_client_with_http_response() -> AsyncMock:
    """
    Create a mock TPA client that returns HTTP response for delete/download operations.
    """
    mock = AsyncMock(spec=TPAClient)
    mock.upload_sbom = AsyncMock(
        return_value=httpx.Response(
            200, request=httpx.Request("POST", "https://example.com")
        )
    )
    mock.__aenter__ = AsyncMock(return_value=mock)
    mock.__aexit__ = AsyncMock(return_value=None)
    return mock


@pytest.fixture
def mock_sbom_factory() -> Callable[[str, str], MagicMock]:
    """
    Factory for creating mock SBOM objects with consistent structure.
    """

    def create_mock_sbom(sbom_id: str, name: str) -> MagicMock:
        sbom = MagicMock()
        sbom.id = sbom_id
        sbom.name = name
        return sbom

    return create_mock_sbom


def setup_mock_tpa_client_with_context_manager(
    mock_get_client: MagicMock,
    mock_tpa_client: AsyncMock,
) -> None:
    """
    Utility function to setup TPA client mock with async context manager support.
    This eliminates duplication in test setup code.

    Args:
        mock_get_client: The mock for get_tpa_default_client
        mock_tpa_client: The mock TPA client instance
    """
    mock_tpa_client.__aenter__ = AsyncMock(return_value=mock_tpa_client)
    mock_tpa_client.__aexit__ = AsyncMock(return_value=None)

    @contextlib.asynccontextmanager
    async def mock_client_ctx(base_url: str) -> Any:
        yield mock_tpa_client

    mock_get_client.side_effect = mock_client_ctx


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

    assert get_mobster_tool_string() in actual["creationInfo"]["creators"]
    # Remove the Tool: Mobster entry from creators, as it's not in the expected result
    actual["creationInfo"]["creators"] = [
        creator
        for creator in actual["creationInfo"]["creators"]
        if "Mobster" not in creator
    ]
    patch_annotation_date(actual, "2025-07-21T08:37:50Z")
    patch_annotation_date(expected, "2025-07-21T08:37:50Z")

    # Verify annotations only if it's expected.
    if "annotations" in expected:
        for annotation in actual["annotations"]:
            if "release_id=" in annotation["comment"]:
                assert annotation["annotator"] == get_mobster_tool_string()
                check_timestamp_isoformat(annotation["annotationDate"])
                break
        else:
            raise AssertionError("release_id not found in annotations.")

        # Remove annotations, which is already verified
        actual.pop("annotations")
        expected.pop("annotations")

    assert actual == expected


def patch_annotation_date(sbom: Any, value: str) -> None:
    """
    Patch the dynamicaly generated annotation date in the SBOM with a fixed value.

    Args:
        sbom (Any): An SBOM dictionary to patch.
        value (str): A fixed date value to set in the SBOM.
    """
    for package in sbom["packages"]:
        for annotation in package.get("annotations", []):
            if "annotationDate" in annotation:
                annotation["annotationDate"] = value


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


def check_timestamp_isoformat(timestamp: str) -> None:
    """
    Check that the timestamp is ISO8601 compliant (YYYY-MM-DDThh:mm:ssZ).
    Args:
        timestamp (str): timestamp to validate

    Returns:
        Converted datetime object, otherwise ValueError is raised.
    """
    datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%SZ")


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


@dataclass
class GenerateOciImageCommandArgs:
    from_syft: list[Path]
    from_hermeto: Path | None
    image_pullspec: str
    image_digest: str
    parsed_dockerfile_path: Path | None
    dockerfile_target: str | None
    additional_base_image: list[str]
    base_image_digest_file: Path | None = None
    output: Path | None = None
    contextualize: bool = False


@dataclass
class GenerateOciImageTestCase:
    args: GenerateOciImageCommandArgs
    expected_sbom_path: Path


@pytest.fixture()
def test_case_spdx_with_hermeto_and_additional() -> GenerateOciImageTestCase:
    """Test case with SPDX format, hermeto BOM, and additional base images."""
    return GenerateOciImageTestCase(
        args=GenerateOciImageCommandArgs(
            from_syft=[
                Path("tests/sbom/test_merge_data/spdx/syft-sboms/pip-e2e-test.bom.json")
            ],
            from_hermeto=Path("tests/sbom/test_merge_data/spdx/cachi2.bom.json"),
            image_pullspec="quay.io/foobar/examplecontainer:v10",
            image_digest="sha256:11111111111111111111111111111111",
            parsed_dockerfile_path=Path(
                "tests/data/dockerfiles/somewhat_believable_sample/parsed.json"
            ),
            dockerfile_target="runtime",
            additional_base_image=[
                "quay.io/ubi9:latest@sha256:123456789012345678901234567789012"
            ],
            base_image_digest_file=Path("dummy_path"),  # Will be mocked
        ),
        expected_sbom_path=Path(
            "tests/sbom/test_oci_generate_data/generated.spdx.json"
        ),
    )


@pytest.fixture()
def test_case_spdx_without_hermeto_without_additional() -> GenerateOciImageTestCase:
    """Test case with SPDX format, no hermeto BOM, and no additional base images."""
    return GenerateOciImageTestCase(
        args=GenerateOciImageCommandArgs(
            from_syft=[
                Path("tests/sbom/test_merge_data/spdx/syft-sboms/pip-e2e-test.bom.json")
            ],
            from_hermeto=None,
            image_pullspec="quay.io/foobar/examplecontainer:v10",
            image_digest="sha256:11111111111111111111111111111111",
            parsed_dockerfile_path=Path(
                "tests/data/dockerfiles/somewhat_believable_sample/parsed.json"
            ),
            dockerfile_target="builder",
            additional_base_image=[],
            base_image_digest_file=Path("dummy_path"),  # Will be mocked
        ),
        expected_sbom_path=Path(
            "tests/sbom/test_oci_generate_data/generated_without_hermet_without_additional.spdx.json"
        ),
    )


@pytest.fixture()
def test_case_spdx_multiple_syft() -> GenerateOciImageTestCase:
    """
    Test case with SPDX format, multiple syft BOMs, and no base image digest
    content.
    """
    return GenerateOciImageTestCase(
        args=GenerateOciImageCommandArgs(
            from_syft=[
                Path(
                    "tests/sbom/test_merge_data/spdx/syft-sboms/pip-e2e-test.bom.json"
                ),
                Path("tests/sbom/test_merge_data/spdx/syft-sboms/ubi-micro.bom.json"),
            ],
            from_hermeto=None,
            image_pullspec="quay.io/foobar/examplecontainer:v10",
            image_digest="sha256:11111111111111111111111111111111",
            parsed_dockerfile_path=Path(
                "tests/data/dockerfiles/somewhat_believable_sample/parsed.json"
            ),
            dockerfile_target="builder",
            additional_base_image=[],
            base_image_digest_file=None,  # No base image digest content for this test
        ),
        expected_sbom_path=Path(
            "tests/sbom/test_oci_generate_data/generated_multiple_syft.spdx.json"
        ),
    )


@pytest.fixture()
def test_case_cyclonedx_with_additional() -> GenerateOciImageTestCase:
    """Test case with CycloneDX format and additional base images."""
    return GenerateOciImageTestCase(
        args=GenerateOciImageCommandArgs(
            from_syft=[
                Path(
                    "tests/sbom/test_merge_data/cyclonedx/syft-sboms/pip-e2e-test.bom.json"
                )
            ],
            from_hermeto=None,
            image_pullspec="quay.io/foobar/examplecontainer:v10",
            image_digest="sha256:11111111111111111111111111111111",
            parsed_dockerfile_path=Path(
                "tests/data/dockerfiles/somewhat_believable_sample/parsed.json"
            ),
            dockerfile_target="builder",
            additional_base_image=[
                "quay.io/ubi9:latest@sha256:123456789012345678901234567789012"
            ],
            base_image_digest_file=Path("dummy_path"),  # Will be mocked
        ),
        expected_sbom_path=Path("tests/sbom/test_oci_generate_data/generated.cdx.json"),
    )


@pytest.fixture(scope="session")
def spdx_parent_sbom_bytes() -> bytes:
    with open(
        "tests/sbom/test_oci_generate_data/contextual/fake_parent_sbom/parent_sbom.spdx.json",
        "rb",
    ) as sbom_file:
        return sbom_file.read()


@pytest.fixture(scope="session")
def inspected_parent_multiarch() -> bytes:
    with open(
        "tests/sbom/test_oci_generate_data/contextual/fake_image_inspect/inspect_multiarch.json",
        "rb",
    ) as inspect_file:
        return inspect_file.read()


@pytest.fixture(scope="session")
def inspected_parent_singlearch() -> bytes:
    with open(
        "tests/sbom/test_oci_generate_data/contextual/fake_image_inspect/inspect_singlearch.json",
        "rb",
    ) as inspect_file:
        return inspect_file.read()


@pytest.fixture(scope="session")
def spdx_parent_sbom() -> Document:
    return parse_file(  # type: ignore[no-any-return]
        "tests/sbom/test_oci_generate_data/contextual/fake_parent_sbom/parent_sbom_legacy_with_builder.spdx.json"
    )


@pytest.fixture(scope="session")
def spdx_parent_sbom_builder_removed() -> Document:
    return parse_file(  # type: ignore[no-any-return]
        "tests/sbom/test_oci_generate_data/contextual/fake_parent_sbom/parent_sbom_legacy_builder_removed.spdx.json"
    )


def create_annotation_with_spdx_id(spdx_id: str) -> Annotation:
    """Create an annotation with a specific SPDX ID."""
    return Annotation(
        spdx_id,
        AnnotationType.OTHER,
        Actor(ActorType.TOOL, "test"),
        datetime.now(),
        "test comment",
    )


def get_base_image_items(
    spdx_element_id: str,
    related_spdx_element_id: str,
    legacy: bool,
    grandparent: bool = False,
) -> tuple[Package, Annotation, Relationship]:
    """
    Helper function to generate image package with DESCENDANT_OF
    or BUILD_TOOL_OF relationship and appropriate annotation.
    """
    if legacy and grandparent:
        raise ValueError("Legacy SBOMs do not bear grandparents.")

    # Relationship
    if legacy:
        rel = RelationshipType.BUILD_TOOL_OF
        rel_args = (spdx_element_id, rel, related_spdx_element_id)
    else:
        rel = RelationshipType.DESCENDANT_OF
        rel_args = (related_spdx_element_id, rel, spdx_element_id)
    relationship = Relationship(*rel_args)

    # Annotation
    suffix = "is_ancestor_image" if grandparent else "is_base_image"
    annotation_comment = f'{{"name": "konflux:container:{suffix}",   "value": "true" }}'

    annotation = Annotation(
        spdx_element_id,
        AnnotationType.OTHER,
        Actor(ActorType.TOOL, "ham"),
        datetime.now(),
        annotation_comment,
    )

    # Package
    package = Package(spdx_element_id, "name", SpdxNoAssertion())

    return package, annotation, relationship


def get_root_package_items(spdx_id: str) -> tuple[Package, Relationship]:
    """Helper function to generate root package and relationship items."""
    return Package(spdx_id, "name", SpdxNoAssertion()), Relationship(
        "SPDXRef-DOCUMENT",
        RelationshipType.DESCRIBES,
        spdx_id,
    )
