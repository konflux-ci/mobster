import json
import tempfile
from collections import namedtuple
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from io import StringIO
from pathlib import Path
from typing import Any

import pytest
from packageurl import PackageURL
from spdx_tools.spdx.model.actor import Actor, ActorType
from spdx_tools.spdx.model.document import CreationInfo, Document
from spdx_tools.spdx.model.package import Package
from spdx_tools.spdx.model.relationship import Relationship, RelationshipType
from spdx_tools.spdx.model.spdx_no_assertion import SpdxNoAssertion
from spdx_tools.spdx.writer.json.json_writer import write_document_to_stream

from mobster.cmd.generate.product import (
    GenerateProductCommand,
    ReleaseNotes,
    parse_release_notes,
)
from mobster.image import Image, IndexImage
from mobster.release import Component, Snapshot
from mobster.sbom.spdx import get_mobster_tool_string
from tests.conftest import awaitable, check_timestamp_isoformat

Digests = namedtuple("Digests", ["single_arch", "multi_arch"])
DIGESTS = Digests(
    single_arch="sha256:8f2e5e7f92d8e8d2e9b3e9c1a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0",
    multi_arch="sha256:e4d2f37a563fcfa4d3a1ab476ded714c56f75f916d30c3a33815d64d41f78534",
)


@dataclass
class Args:
    snapshot: Path
    release_data: Path
    output: Path
    release_id: str


@pytest.fixture(
    params=[(Path("product.json"), "release-id-1"), (None, None)],
    ids=["file", "stdout"],
)
def generate_product_command_args(request: Any) -> Args:
    return Args(
        snapshot=Path("snapshot"),
        release_data=Path("data.json"),
        output=request.param[0],
        release_id=request.param[1],
    )


@pytest.fixture()
def generate_product_command(
    generate_product_command_args: Args,
) -> GenerateProductCommand:
    return GenerateProductCommand(cli_args=generate_product_command_args)


@pytest.fixture()
def patch_make_snapshot(monkeypatch: pytest.MonkeyPatch) -> Any:
    def _patch_make_snapshot(snapshot: Snapshot) -> None:
        monkeypatch.setattr(
            "mobster.cmd.generate.product.make_snapshot", lambda *_: awaitable(snapshot)
        )

    return _patch_make_snapshot


@pytest.fixture()
def minimal_spdx_document() -> Document:
    spdx_id = "SPDXRef-DOCUMENT"
    creation_info = CreationInfo(
        spdx_version="SPDX-2.3",
        spdx_id=spdx_id,
        name="document name",
        data_license="CC0-1.0",
        document_namespace="https://some.namespace",
        creators=[Actor(ActorType.PERSON, "Jane Doe", "jane.doe@example.com")],
        created=datetime(2022, 1, 1),
    )

    package = Package(
        spdx_id="SPDXRef-package",
        name="software",
        download_location=SpdxNoAssertion(),
        version="1.0.0",
    )

    relationship = Relationship(
        spdx_element_id="SPDXRef-DOCUMENT",
        relationship_type=RelationshipType.DESCRIBES,
        related_spdx_element_id="SPDXRef-package",
    )

    return Document(
        creation_info=creation_info, packages=[package], relationships=[relationship]
    )


@pytest.fixture()
def minimal_spdx_document_json(minimal_spdx_document: Document) -> str:
    io = StringIO()
    write_document_to_stream(document=minimal_spdx_document, stream=io)
    return io.getvalue()


class TestGenerateProductCommand:
    @pytest.mark.parametrize(
        "cpe",
        [
            pytest.param("cpe:/a:redhat:discovery:1.0::el9", id="cpe-single"),
            pytest.param(
                [
                    "cpe:/a:redhat:discovery:1.0::el9",
                    "cpe:/a:redhat:discovery:1.0::el10",
                ],
                id="cpe-list",
            ),
        ],
    )
    @pytest.mark.parametrize(
        ["snapshot", "purls"],
        [
            pytest.param(
                Snapshot(
                    components=[
                        Component(
                            name="component",
                            image=Image(
                                repository="quay.io/repo", digest=DIGESTS.single_arch
                            ),
                            tags=["1.0", "latest"],
                            repository="registry.redhat.io/repo",
                        )
                    ]
                ),
                [
                    f"pkg:oci/repo@{DIGESTS.single_arch}?repository_url=registry.redhat.io/repo&tag=1.0",
                    f"pkg:oci/repo@{DIGESTS.single_arch}?repository_url=registry.redhat.io/repo&tag=latest",
                ],
                id="single-component-single-arch",
            ),
            pytest.param(
                Snapshot(
                    components=[
                        Component(
                            name="component",
                            image=IndexImage(
                                digest=DIGESTS.multi_arch,
                                children=[
                                    Image(
                                        repository="quay.io/repo", digest="sha256:aaa"
                                    ),
                                    Image(
                                        repository="quay.io/repo", digest="sha256:bbb"
                                    ),
                                ],
                                repository="quay.io/repo",
                            ),
                            tags=["1.0", "latest"],
                            repository="registry.redhat.io/repo",
                        )
                    ]
                ),
                [
                    f"pkg:oci/repo@{DIGESTS.multi_arch}?repository_url=registry.redhat.io/repo&tag=1.0",
                    f"pkg:oci/repo@{DIGESTS.multi_arch}?repository_url=registry.redhat.io/repo&tag=latest",
                ],
                id="single-component-multi-arch",
            ),
            pytest.param(
                Snapshot(
                    components=[
                        Component(
                            name="multiarch-component",
                            image=IndexImage(
                                repository="quay.io/repo",
                                digest=DIGESTS.multi_arch,
                                children=[
                                    Image(
                                        repository="quay.io/repo", digest="sha256:aaa"
                                    ),
                                    Image(
                                        repository="quay.io/repo", digest="sha256:bbb"
                                    ),
                                ],
                            ),
                            tags=["1.0", "latest"],
                            repository="registry.redhat.io/repo",
                        ),
                        Component(
                            name="singlearch-component",
                            image=Image(
                                repository="quay.io/another-repo",
                                digest=DIGESTS.single_arch,
                            ),
                            tags=["2.0", "production"],
                            repository="registry.redhat.io/another-repo",
                        ),
                    ]
                ),
                [
                    f"pkg:oci/repo@{DIGESTS.multi_arch}?repository_url=registry.redhat.io/repo&tag=1.0",
                    f"pkg:oci/repo@{DIGESTS.multi_arch}?repository_url=registry.redhat.io/repo&tag=latest",
                    f"pkg:oci/another-repo@{DIGESTS.single_arch}"
                    "?repository_url=registry.redhat.io/another-repo&tag=2.0",
                    f"pkg:oci/another-repo@{DIGESTS.single_arch}"
                    "?repository_url=registry.redhat.io/another-repo&tag=production",
                ],
                id="multi-component-mixed-arch",
            ),
        ],
    )
    @pytest.mark.asyncio
    async def test_execute(
        self,
        generate_product_command_args: Args,
        generate_product_command: GenerateProductCommand,
        patch_make_snapshot: Callable[[Snapshot], None],
        cpe: str | list[str],
        snapshot: Snapshot,
        purls: list[str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        patch_make_snapshot(snapshot)

        release_notes = ReleaseNotes(
            product_name="Product",
            product_version="1.0",
            cpe=cpe,
        )
        monkeypatch.setattr(
            "mobster.cmd.generate.product.parse_release_notes", lambda *_: release_notes
        )

        await generate_product_command.execute()

        assert generate_product_command.document is not None
        assert generate_product_command.release_notes is not None

        output = StringIO()
        write_document_to_stream(generate_product_command.document, output)
        output.seek(0)

        sbom_dict = json.load(output)
        verify_product_sbom(
            sbom_dict,
            [component.name for component in snapshot.components],
            release_notes,
            purls,
        )

    @pytest.mark.asyncio
    async def test_save(
        self,
        generate_product_command_args: Args,
        generate_product_command: GenerateProductCommand,
        minimal_spdx_document: Document,
        minimal_spdx_document_json: str,
        capsys: Any,
    ) -> None:
        release_notes = ReleaseNotes(
            product_name="Product",
            product_version="1.0",
            cpe="cpe:/a:redhat:discovery:1.0::el10",
        )
        generate_product_command.release_notes = release_notes
        generate_product_command.document = minimal_spdx_document

        # check both file and stdout output functionality
        if generate_product_command_args.output is not None:
            with tempfile.TemporaryDirectory() as dir:
                file_name = generate_product_command_args.output
                out = Path(dir).joinpath(file_name)
                generate_product_command.cli_args.output = out
                await generate_product_command.save()
                with open(out, encoding="utf-8") as fp:
                    assert json.load(fp) == json.loads(minimal_spdx_document_json)
        else:
            # stdout
            await generate_product_command.save()
            out, _ = capsys.readouterr()
            assert json.loads(out) == json.loads(minimal_spdx_document_json)


@pytest.mark.parametrize(
    ["data", "expected_rn"],
    [
        pytest.param(
            {
                "unrelated": "field",
                "releaseNotes": {
                    "product_name": "Product",
                    "product_version": "1.0",
                    "cpe": "cpe",
                },
            },
            ReleaseNotes(
                product_name="Product",
                product_version="1.0",
                cpe="cpe",
            ),
            id="cpe-single",
        ),
        pytest.param(
            {
                "unrelated": "field",
                "releaseNotes": {
                    "product_name": "Product",
                    "product_version": "1.0",
                    "cpe": ["cpe1", "cpe2"],
                },
            },
            ReleaseNotes(
                product_name="Product",
                product_version="1.0",
                cpe=["cpe1", "cpe2"],
            ),
            id="cpe-list",
        ),
    ],
)
def test_parse_release_notes(data: dict[str, Any], expected_rn: ReleaseNotes) -> None:
    with tempfile.NamedTemporaryFile(mode="w") as tmpf:
        tmpf.write(json.dumps(data))
        tmpf.flush()
        actual = parse_release_notes(Path(tmpf.name))

    assert expected_rn == actual


def verify_product_sbom(
    sbom_dict: Any,
    component_names: list[str],
    release_notes: ReleaseNotes,
    purls: list[str],
) -> None:
    verify_creation_info(
        sbom_dict, f"{release_notes.product_name} {release_notes.product_version}"
    )
    verify_cpe(sbom_dict, release_notes.cpe)
    verify_purls(sbom_dict, purls)
    verify_relationships(sbom_dict, component_names)
    verify_checksums(sbom_dict)
    verify_supplier(sbom_dict)
    verify_package_licenses(sbom_dict)

    assert sbom_dict["dataLicense"] == "CC0-1.0"


def verify_creation_info(sbom: Any, expected_name: str) -> None:
    """
    Verify that creationInfo fields match the expected values.
    """
    assert get_mobster_tool_string() in sbom["creationInfo"]["creators"]
    assert sbom["name"] == expected_name


def verify_cpe(sbom: Any, expected_cpe: str | list[str]) -> None:
    """
    Verify that all CPE externalRefs are in the first package.
    """
    all_cpes = expected_cpe if isinstance(expected_cpe, list) else [expected_cpe]
    for cpe in all_cpes:
        assert {
            "referenceCategory": "SECURITY",
            "referenceLocator": cpe,
            "referenceType": "cpe22Type",
        } in sbom["packages"][0]["externalRefs"]


def verify_release_id(sbom: Any, expected_release_id: str | None) -> None:
    """
    Verify that release_id annotation match the expected values.
    """
    if expected_release_id:
        for annotation in sbom["annotations"]:
            if "release_id=" in annotation["comment"]:
                check_timestamp_isoformat(annotation["annotationDate"])
                break
        else:
            raise AssertionError("release_id not found in annotations.")
    else:
        assert "annotations" not in sbom


def verify_purls(sbom: Any, expected: list[str]) -> None:
    """
    Verify that the actual purls in the SBOM match the expected purls.
    """
    actual_purls = []
    for package in sbom["packages"]:
        refs = package["externalRefs"]
        actual_purls.extend(
            [ref["referenceLocator"] for ref in refs if ref["referenceType"] == "purl"]
        )

    assert sorted(actual_purls) == sorted(expected), print(
        f"Actual: {actual_purls}, Expected: {expected}"
    )


def verify_checksums(sbom: Any) -> None:
    """
    Verify that if there is an OCI purl in a package, the version can also be
    found in the checksums of the package.
    """
    for package in sbom["packages"]:
        refs = package["externalRefs"]
        purls = {
            PackageURL.from_string(ref["referenceLocator"])
            for ref in refs
            if ref["referenceType"] == "purl"
        }

        expected_checksums = {
            f"sha256:{checksum['checksumValue']}"
            for checksum in package.get("checksums", [])
            if checksum["algorithm"] == "SHA256"
        }

        actual_checksums = {purl.version or "" for purl in purls if purl.type == "oci"}

        assert actual_checksums == expected_checksums


def verify_relationships(sbom: Any, component_names: list[str]) -> None:
    """
    Verify that the correct relationships exist for each component and the product.
    """
    for name in component_names:
        assert {
            "spdxElementId": f"SPDXRef-component-{name}",
            "relatedSpdxElement": "SPDXRef-product",
            "relationshipType": "PACKAGE_OF",
        } in sbom["relationships"]

    # verify the relationship for the product
    assert {
        "spdxElementId": "SPDXRef-DOCUMENT",
        "relatedSpdxElement": "SPDXRef-product",
        "relationshipType": "DESCRIBES",
    } in sbom["relationships"]


def verify_supplier(sbom: Any) -> None:
    # verify suppliers are set
    for package in sbom["packages"]:
        assert package["supplier"] == "Organization: Red Hat"


def verify_package_licenses(sbom: Any) -> None:
    for package in sbom["packages"]:
        assert package["licenseDeclared"] == "NOASSERTION"
