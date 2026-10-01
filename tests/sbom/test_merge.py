# ruff: noqa: E501
import json
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest
from cyclonedx.model.component import Component
from cyclonedx.model.tool import Tool
from packageurl import PackageURL
from spdx_tools.spdx.jsonschema.document_converter import DocumentConverter
from spdx_tools.spdx.model.document import Document
from spdx_tools.spdx.model.package import (
    ExternalPackageRef,
    ExternalPackageRefCategory,
    Package,
)
from spdx_tools.spdx.model.spdx_no_assertion import SpdxNoAssertion
from spdx_tools.spdx.writer.write_utils import convert

from mobster.sbom.cyclonedx_wrapper import CycloneDX1BomWrapper
from mobster.sbom.load import load_file_to_dict
from mobster.sbom.merge import (
    CDXComponent,
    CycloneDXMerger,
    MergeIndex,
    SBOMItem,
    SBOMSource,
    SPDXPackage,
    _detect_sbom_type,
    _subpath_is_version,
    fallback_key,
    merge_sboms,
    try_parse_purl,
    wrap_as_cdx,
    wrap_as_spdx,
)

INDIVIDUAL_SYFT_SBOMS = [
    Path("syft-sboms/gomod-pandemonium.bom.json"),
    Path("syft-sboms/npm-cachi2-smoketest.bom.json"),
    Path("syft-sboms/pip-e2e-test.bom.json"),
    Path("syft-sboms/ubi-micro.bom.json"),
]


@pytest.fixture
def data_dir() -> Path:
    """Path to the directory for storing SBOM sample test data."""
    return Path(__file__).parent / "test_merge_data"


def sbom_to_dict(sbom: Document | CycloneDX1BomWrapper) -> dict[str, Any]:
    """Serialize a merged SBOM object back to a JSON-compatible dict."""
    if isinstance(sbom, Document):
        return convert(sbom, DocumentConverter())  # type: ignore[no-untyped-call]
    return sbom.to_dict()


def make_cdx_component(
    name: str,
    version: str = "1.0.0",
    purl: str | None = None,
    bom_ref: str | None = None,
    source: SBOMSource = SBOMSource.SYFT,
) -> CDXComponent:
    return CDXComponent(
        source=source,
        data=Component(
            name=name,
            version=version,
            bom_ref=bom_ref or f"{name}-{version}",
            purl=PackageURL.from_string(purl) if purl else None,
        ),
    )


def make_spdx_package(
    name: str,
    version: str = "1.0.0",
    purl: str | None = None,
    source: SBOMSource = SBOMSource.SYFT,
    spdx_id: str | None = None,
) -> SPDXPackage:
    external_refs = []
    if purl:
        external_refs.append(
            ExternalPackageRef(
                category=ExternalPackageRefCategory.PACKAGE_MANAGER,
                reference_type="purl",
                locator=purl,
            )
        )
    return SPDXPackage(
        source=source,
        data=Package(
            spdx_id=spdx_id or f"SPDXRef-{name}-{version}",
            name=name,
            version=version,
            download_location=SpdxNoAssertion(),
            external_references=external_refs,
        ),
    )


def test_try_parse_purl() -> None:
    purl = try_parse_purl("pkg:valid/package_name@1.1.1")
    assert isinstance(purl, PackageURL)
    assert purl.type == "valid"
    assert purl.name == "package_name"
    assert purl.version == "1.1.1"

    assert try_parse_purl("invalid_purl") is None
    assert try_parse_purl(None) is None


def test_fallback_key() -> None:
    cdx = make_cdx_component("cdx_package", "1.0.0", bom_ref="cdxID")
    spdx = make_spdx_package("spdx_package", "2.0.0")
    assert fallback_key(cdx) == "cdx_package@1.0.0"
    assert fallback_key(spdx) == "spdx_package@2.0.0"

    cdx_local = make_cdx_component("./local_package", "1.0.0", bom_ref="cdxID")
    spdx_local = make_spdx_package("./local_package", "2.0.0")
    assert fallback_key(cdx_local) == "cdxID"
    assert fallback_key(spdx_local) == "SPDXRef-./local_package-2.0.0"


def test_CDXComponent() -> None:
    component = make_cdx_component(
        "cdx_package",
        "1.0.0",
        purl="pkg:valid/package_name@1.1.1",
        bom_ref="cdxID",
    )
    assert component.id() == "cdxID"
    assert component.name() == "cdx_package"
    assert component.version() == "1.0.0"
    assert component.purl() == PackageURL.from_string("pkg:valid/package_name@1.1.1")
    assert component.unwrap() is component.data

    assert make_cdx_component("cdx_package", "1.0.0", bom_ref="cdxID").purl() is None


def test_wrap_as_cdx() -> None:
    components = [
        Component(
            name="cdx_package",
            version="1.0.0",
            bom_ref="cdxID",
            purl=PackageURL.from_string("pkg:valid/package_name@1.1.1"),
        ),
        Component(
            name="cdx_package2",
            version="2.0.0",
            bom_ref="cdxID2",
            purl=PackageURL.from_string("pkg:valid/package_name2@2.0.0"),
        ),
    ]
    wrapped = wrap_as_cdx(components, SBOMSource.SYFT)
    assert len(wrapped) == 2
    assert all(isinstance(item, CDXComponent) for item in wrapped)
    assert all(item.source is SBOMSource.SYFT for item in wrapped)


@pytest.mark.parametrize(
    ["purl", "expected"],
    [
        pytest.param(None, None, id="no-purl"),
        pytest.param(
            PackageURL.from_string("pkg:pypi/FooBar@1.0.0"),
            "pkg:pypi/foobar@1.0.0",
            id="pypi-name-lowercased",
        ),
        pytest.param(
            PackageURL.from_string(
                "pkg:pypi/Foo@1.0.0?arch=noarch&vcs_url=http://example.com"
            ),
            "pkg:pypi/foo@1.0.0",
            id="drop-noarch-and-non-identity-quals",
        ),
        pytest.param(
            PackageURL.from_string("pkg:pypi/Foo@1.0.0?arch=x86_64"),
            "pkg:pypi/foo@1.0.0?arch=x86_64",
            id="keep-meaningful-arch",
        ),
        pytest.param(
            PackageURL.from_string("pkg:golang/example.com/mod@v1.0.0#v2"),
            "pkg:golang/example.com/mod/v2@v1.0.0",
            id="golang-version-subpath-folded-into-name",
        ),
        pytest.param(
            PackageURL.from_string("pkg:golang/example.com/mod@v1.0.0#cmd/tool"),
            "pkg:golang/example.com/mod@v1.0.0#cmd/tool",
            id="golang-non-version-subpath-kept",
        ),
        pytest.param(
            PackageURL.from_string("pkg:golang/example.com/mod@v1.0.0?type=module"),
            "pkg:golang/example.com/mod@v1.0.0",
            id="golang-drop-type-module",
        ),
        pytest.param(
            PackageURL.from_string("pkg:golang/example.com/mod@v1.0.0?type=package"),
            "pkg:golang/example.com/mod@v1.0.0?type=package",
            id="golang-keep-type-package",
        ),
        pytest.param(
            PackageURL.from_string(
                "pkg:rpm/foo@1.0.0?arch=x86_64&os=linux&epoch=1&classifier=c"
                "&type=t&extra=drop"
            ),
            "pkg:rpm/foo@1.0.0?arch=x86_64&classifier=c&epoch=1&os=linux&type=t",
            id="keep-identity-quals-drop-others",
        ),
        pytest.param(
            PackageURL.from_string("pkg:npm/foo@1.0.0"),
            "pkg:npm/foo@1.0.0",
            id="passthrough-other-ecosystem",
        ),
        pytest.param(
            MagicMock(
                type="pypi",
                name="Foo",
                namespace=None,
                version="1.0.0",
                subpath=None,
                qualifiers="not-a-dict",
            ),
            None,
            id="non-dict-qualifiers",
        ),
    ],
)
def test_sbom_item_normalized_purl(
    purl: PackageURL | MagicMock | None, expected: str | None
) -> None:
    item = MagicMock()
    item.purl.return_value = purl
    assert SBOMItem.normalized_purl(item) == expected

    package = make_spdx_package(
        "spdx_package", "2.0.0", purl="pkg:valid/package_name@1.1.1"
    )
    assert package.id() == "SPDXRef-spdx_package-2.0.0"
    assert package.name() == "spdx_package"
    assert package.version() == "2.0.0"
    assert package.purl() == PackageURL.from_string("pkg:valid/package_name@1.1.1")
    assert package.unwrap() is package.data

    multi_purl = SPDXPackage(
        source=SBOMSource.SYFT,
        data=Package(
            spdx_id="SPDXRef-multi",
            name="spdx_package",
            version="2.0.0",
            download_location=SpdxNoAssertion(),
            external_references=[
                ExternalPackageRef(
                    category=ExternalPackageRefCategory.PACKAGE_MANAGER,
                    reference_type="purl",
                    locator="pkg:valid/package_name@1.1.1",
                ),
                ExternalPackageRef(
                    category=ExternalPackageRefCategory.PACKAGE_MANAGER,
                    reference_type="purl",
                    locator="pkg:valid/package_name2@2.0.0",
                ),
            ],
        ),
    )
    with pytest.raises(ValueError, match="multiple purls"):
        multi_purl.purl()


def test_wrap_as_spdx() -> None:
    packages = [
        Package(
            spdx_id="SPDXRef-spdxID",
            name="spdx_package",
            version="2.0.0",
            download_location=SpdxNoAssertion(),
        ),
        Package(
            spdx_id="SPDXRef-spdxID2",
            name="spdx_package2",
            version="3.0.0",
            download_location=SpdxNoAssertion(),
        ),
    ]
    wrapped = wrap_as_spdx(packages, SBOMSource.HERMETO)
    assert len(wrapped) == 2
    assert all(isinstance(item, SPDXPackage) for item in wrapped)
    assert all(item.source is SBOMSource.HERMETO for item in wrapped)


def test__subpath_is_version() -> None:
    assert _subpath_is_version("v2") is True
    assert _subpath_is_version("v10noversion") is False
    assert _subpath_is_version("noversion") is False


def test_merge_index_matches_golang_version_subpath() -> None:
    index = MergeIndex[Component]()
    hermeto = make_cdx_component(
        "mod",
        "v1.0.0",
        "pkg:golang/example.com/mod/v2@v1.0.0",
        bom_ref="hermeto-mod",
        source=SBOMSource.HERMETO,
    )
    syft = make_cdx_component(
        "mod",
        "v1.0.0",
        "pkg:golang/example.com/mod@v1.0.0#v2",
        bom_ref="syft-mod",
        source=SBOMSource.SYFT,
    )
    assert index.add(hermeto) is True
    assert index.add(syft) is False
    assert [item.id() for item in index.get_items()] == [hermeto.id()]
    assert index.id_mapping[syft.id()] == hermeto.id()


@pytest.mark.parametrize(
    "sbom, expected_type",
    [
        (
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.4",
                "components": [],
            },
            "cyclonedx",
        ),
        (
            {
                "SPDXID": "DocumentRef-SPDXRef-DOCUMENT",
                "name": "example",
                "spdxVersion": "SPDX-2.4",
                "versionInfo": "1.0.0",
                "dataLicense": "CC0-1.0",
                "documentNamespace": "http://spdx.org/spdxdocs/example-1.0.0",
                "creationInfo": {},
            },
            "spdx",
        ),
    ],
)
def test__detect_sbom_type(sbom: dict[str, Any], expected_type: str) -> None:
    assert _detect_sbom_type(sbom) == expected_type


def test__detect_sbom_type_invalid() -> None:
    with pytest.raises(ValueError):
        _detect_sbom_type({"no_format_mentioned": "fail"})


def test_merge_index_drops_duplicate_by_key() -> None:
    index = MergeIndex[Component]()
    hermeto = make_cdx_component(
        "foo",
        "1.0.0",
        "pkg:pypi/foo@1.0.0",
        bom_ref="hermeto-foo",
        source=SBOMSource.HERMETO,
    )
    syft = make_cdx_component(
        "foo",
        "1.0.0",
        "pkg:pypi/foo@1.0.0",
        bom_ref="syft-foo",
        source=SBOMSource.SYFT,
    )

    assert index.add(hermeto) is True
    assert index.add(syft) is False
    assert [item.id() for item in index.get_items()] == [hermeto.id()]
    assert index.id_mapping[syft.id()] == hermeto.id()
    assert index.id_mapping[hermeto.id()] == hermeto.id()


def test_merge_index_drops_syft_duplicate_of_hermeto_non_registry() -> None:
    index = MergeIndex[Package]()
    hermeto = make_spdx_package(
        "bar",
        "2.0.0",
        "pkg:pypi/bar@2.0.0?vcs_url=https://github.com/example/bar",
        source=SBOMSource.HERMETO,
        spdx_id="SPDXRef-hermeto-bar",
    )
    syft = make_spdx_package(
        "bar",
        "2.0.0",
        "pkg:pypi/bar@2.0.0",
        source=SBOMSource.SYFT,
        spdx_id="SPDXRef-syft-bar",
    )

    assert index.add(hermeto) is True
    assert index.add(syft) is False
    assert [item.id() for item in index.get_items()] == [hermeto.id()]
    assert index.id_mapping[syft.id()] == hermeto.id()


def test_merge_index_drops_syft_npm_matching_hermeto_subpath() -> None:
    index = MergeIndex[Component]()
    # Hermeto reports a local path via purl subpath; Syft reports the same
    # dependency as a namespaced npm package whose namespace/name equals that path.
    hermeto = make_cdx_component(
        "baz",
        "3.0.0",
        "pkg:npm/baz@3.0.0#foo/eggs",
        bom_ref="hermeto-baz",
        source=SBOMSource.HERMETO,
    )
    syft = make_cdx_component(
        "eggs",
        "3.0.0",
        "pkg:npm/foo/eggs@3.0.0",
        bom_ref="syft-eggs",
        source=SBOMSource.SYFT,
    )

    assert index.add(hermeto) is True
    assert index.add(syft) is False
    assert [item.id() for item in index.get_items()] == [hermeto.id()]
    assert index.id_mapping[syft.id()] == hermeto.id()


def test_merge_index_drops_syft_local_golang_replacement() -> None:
    # Without Hermeto, Syft-only merges keep local Golang replacements.
    syft_only_index = MergeIndex[Package]()
    local_mod = make_spdx_package(
        ".localmod", "(devel)", "pkg:golang/.localmod@(devel)"
    )
    local_subpath = make_spdx_package(
        ".local", "(devel)", "pkg:golang/.local@(devel)#subdir"
    )
    assert syft_only_index.add(local_mod) is True
    assert syft_only_index.add(local_subpath) is True
    assert len(syft_only_index.get_items()) == 2

    # With Hermeto present, those same Syft reports are filtered out.
    index = MergeIndex[Package]()
    hermeto = make_spdx_package(
        "real", "1.0.0", "pkg:golang/example@v1.0.0", source=SBOMSource.HERMETO
    )
    assert index.add(hermeto) is True
    assert index.add(local_mod) is False
    assert index.add(local_subpath) is False
    assert [item.id() for item in index.get_items()] == [hermeto.id()]


def test_merge_index_keeps_distinct_syft_component() -> None:
    index = MergeIndex[Component]()
    hermeto = make_cdx_component(
        "foo", "1.0.0", "pkg:pypi/foo@1.0.0", source=SBOMSource.HERMETO
    )
    syft = make_cdx_component(
        "bar", "2.0.0", "pkg:pypi/bar@2.0.0", source=SBOMSource.SYFT
    )

    assert index.add(hermeto) is True
    assert index.add(syft) is True
    assert {item.id() for item in index.get_items()} == {hermeto.id(), syft.id()}


@pytest.mark.parametrize(
    "example",
    [
        "remap-relationships",
        "multi-syft",
        "alt-purl-match",
        "golang",
    ],
)
def test_spdx_merge_examples(example: str, data_dir: Path) -> None:
    """Small SPDX fixtures under examples/spdx/<case>/ with fully visible data."""
    case_dir = data_dir / "examples" / "spdx" / example
    expected = json.loads((case_dir / "expected.bom.json").read_text(encoding="utf-8"))

    if example == "multi-syft":
        syft_paths = [case_dir / "syft-a.bom.json", case_dir / "syft-b.bom.json"]
        hermeto_path = None
    else:
        syft_paths = [case_dir / "syft.bom.json"]
        hermeto_path = case_dir / "hermeto.bom.json"

    syft_sboms = [load_file_to_dict(path) for path in syft_paths]
    hermeto_sbom = load_file_to_dict(hermeto_path) if hermeto_path else None
    result = sbom_to_dict(merge_sboms(syft_sboms, hermeto_sbom))

    assert {p["SPDXID"] for p in result["packages"]} == {
        p["SPDXID"] for p in expected["packages"]
    }
    result_rels = {
        (r["spdxElementId"], r["relationshipType"], r["relatedSpdxElement"])
        for r in result["relationships"]
    }
    expected_rels = {
        (r["spdxElementId"], r["relationshipType"], r["relatedSpdxElement"])
        for r in expected["relationships"]
    }
    assert result_rels == expected_rels


def test_cyclonedx_merge_tools_metadata() -> None:
    syft_tool = Tool(vendor="anchore", name="syft", version="1.4.1")
    hermeto_tool = Tool(vendor="red hat", name="hermeto", version="1.0.0")
    other_tool = Tool(vendor="example", name="scanner", version="2.0.0")

    def sbom_with_tools(*tools: Tool) -> MagicMock:
        wrapper = MagicMock()
        wrapper.sbom.metadata.tools.tools = list(tools)
        return wrapper

    # Three SBOMs: syft appears twice, hermeto appears twice, other once.
    result = CycloneDXMerger()._merge_tools_metadata(
        [
            sbom_with_tools(syft_tool, hermeto_tool),
            sbom_with_tools(
                syft_tool,
                other_tool,
            ),
            sbom_with_tools(hermeto_tool),
        ]
    )

    assert len(result) == 3
    assert set(result) == {syft_tool, hermeto_tool, other_tool}


def test_cyclonedx_prefer_and_remap_example(data_dir: Path) -> None:
    """Hermeto wins on shared foo; Syft-only bar kept; deps remapped to hermeto-foo."""
    case_dir = data_dir / "examples" / "cyclonedx" / "prefer-and-remap"
    expected = json.loads((case_dir / "expected.bom.json").read_text(encoding="utf-8"))

    merged = merge_sboms(
        [load_file_to_dict(case_dir / "syft.bom.json")],
        load_file_to_dict(case_dir / "hermeto.bom.json"),
    )
    assert isinstance(merged, CycloneDX1BomWrapper)
    result = sbom_to_dict(merged)

    result_purls = {c.get("purl") for c in result["components"]}
    expected_purls = {c.get("purl") for c in expected["components"]}
    assert result_purls == expected_purls
    foo = next(c for c in result["components"] if c.get("purl") == "pkg:pypi/foo@1.0.0")
    assert foo["bom-ref"] == "hermeto-foo"

    graph = _dependency_graph(merged)
    assert None not in graph
    assert all(None not in deps for deps in graph.values())
    assert "syft-foo" not in graph
    assert graph["hermeto-foo"] == {"syft-bar"}
    assert graph["syft-bar"] == set()


def _dependency_graph(
    sbom: CycloneDX1BomWrapper,
) -> dict[str | None, set[str | None]]:
    """Map each dependency ref value to the set of dependsOn ref values."""
    graph: dict[str | None, set[str | None]] = {}
    for dependency in sbom.sbom.dependencies:
        graph[dependency.ref.value] = {
            child.ref.value for child in dependency.dependencies
        }
    return graph


@pytest.mark.parametrize(
    "syft_sboms, hermeto_sbom",
    [
        ([], {"some": "hermeto_sbom"}),
        ([{"some": "syft_sbom"}], None),
    ],
)
def test_merge_sboms_invalid(
    syft_sboms: list[dict[str, Any]],
    hermeto_sbom: dict[str, Any] | None,
) -> None:
    with pytest.raises(ValueError):
        merge_sboms(syft_sboms, hermeto_sbom)


def test_merge_sboms_mismatched_formats() -> None:
    syft = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": [],
    }
    hermeto = {
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "example",
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "documentNamespace": "http://spdx.org/spdxdocs/example",
        "creationInfo": {
            "created": "2024-01-01T00:00:00Z",
            "creators": ["Tool: test"],
        },
        "packages": [],
    }
    with pytest.raises(ValueError, match="same SBOM format"):
        merge_sboms([syft, syft], hermeto)
