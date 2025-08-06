# ruff: noqa: E501
import json
from collections import Counter
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any
from unittest.mock import Mock, patch

import pytest
from packageurl import PackageURL

from mobster.sbom.merge import (
    CDXComponent,
    CycloneDXMerger,
    SBOMItem,
    SPDXMerger,
    SPDXPackage,
    _create_merger,
    _detect_sbom_type,
    _get_syft_component_filter,
    _subpath_is_version,
    fallback_key,
    merge_by_apparent_sameness,
    merge_by_prefering_hermeto,
    merge_sboms,
    try_parse_purl,
    wrap_as_cdx,
    wrap_as_spdx,
)

TOOLS_METADATA = {
    "syft-cyclonedx-1.4": {
        "name": "syft",
        "vendor": "anchore",
        "version": "0.47.0",
    },
    "syft-cyclonedx-1.5": {
        "type": "application",
        "author": "anchore",
        "name": "syft",
        "version": "0.100.0",
    },
    "hermeto-cyclonedx-1.4": {
        "name": "hermeto",
        "vendor": "red hat",
    },
    "hermeto-cyclonedx-1.5": {
        "type": "application",
        "author": "red hat",
        "name": "hermeto",
    },
}

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


def count_components(sbom: dict[str, Any]) -> Counter[str]:
    def key(component: SBOMItem) -> str:
        purl = component.purl()
        if purl:
            return purl.to_string()
        return fallback_key(component)

    components: Sequence[CDXComponent | SPDXPackage]

    if _detect_sbom_type(sbom) == "cyclonedx":
        components = wrap_as_cdx(sbom["components"])
    else:
        components = wrap_as_spdx(sbom["packages"])

    return Counter(map(key, components))


def count_relationships(spdx_sbom: dict[str, Any]) -> Counter[str]:
    package_spdxids = {p["SPDXID"] for p in spdx_sbom["packages"]}

    def relationship_key(r: dict[str, Any]) -> str | None:
        element = r["spdxElementId"]
        relationship = r["relationshipType"]
        related_element = r["relatedSpdxElement"]

        if related_element not in package_spdxids:
            # The Syft SBOM also contains relationships referencing elements
            # of the .files array, for which we have no handling. As well
            # as relationships referencing non-existent SPDXIDs.
            # Exclude those from the comparison, keep only those we care about.
            return None

        if relationship == "DESCRIBES":
            return f"{element} {relationship} {related_element}"
        else:
            return f"{element} {relationship} *"

    return Counter(filter(None, map(relationship_key, spdx_sbom["relationships"])))


def diff_counts(a: Counter[str], b: Counter[str]) -> dict[str, int]:
    a = a.copy()
    a.subtract(b)
    return {key: count for key, count in a.items() if count != 0}


def test_try_parse_purl() -> None:
    # Test with a valid PURL
    purl_str = "pkg:valid/package_name@1.1.1"
    purl = try_parse_purl(purl_str)
    assert isinstance(purl, PackageURL)
    assert purl.type == "valid"
    assert purl.name == "package_name"
    assert purl.version == "1.1.1"

    # Test with an invalid PURL
    invalid_purl_str = "invalid_purl"
    purl = try_parse_purl(invalid_purl_str)
    assert purl is None


def test_fallback_key() -> None:
    cdx_component = CDXComponent(
        {"bom-ref": "cdxID", "name": "cdx_package", "version": "1.0.0"}
    )
    spdx_component = SPDXPackage(
        {"SPDXID": "spdxID", "name": "spdx_package", "versionInfo": "2.0.0"}
    )

    assert fallback_key(cdx_component) == "cdx_package@1.0.0"
    assert fallback_key(spdx_component) == "spdx_package@2.0.0"

    # Test with a local package
    cdx_local_package = CDXComponent(
        {"bom-ref": "cdxID", "name": "./local_package", "version": "1.0.0"}
    )
    spdx_local_package = SPDXPackage(
        {"SPDXID": "spdxID", "name": "./local_package", "versionInfo": "2.0.0"}
    )

    assert fallback_key(cdx_local_package) == "cdxID"
    assert fallback_key(spdx_local_package) == "spdxID"


def test_CDXComponent() -> None:
    component_data = {
        "bom-ref": "cdxID",
        "name": "cdx_package",
        "version": "1.0.0",
        "purl": "pkg:valid/package_name@1.1.1",
    }
    cdx_component = CDXComponent(component_data)
    assert cdx_component.id() == "cdxID"
    assert cdx_component.name() == "cdx_package"
    assert cdx_component.version() == "1.0.0"
    assert cdx_component.purl() == PackageURL.from_string(
        "pkg:valid/package_name@1.1.1"
    )

    component_data_no_purl = {
        "bom-ref": "cdxID",
        "name": "cdx_package",
        "version": "1.0.0",
    }
    cdx_component_no_purl = CDXComponent(component_data_no_purl)
    assert cdx_component_no_purl.purl() is None


def test_wrap_as_cdx() -> None:
    data = [
        {
            "bom-ref": "cdxID",
            "name": "cdx_package",
            "version": "1.0.0",
            "purl": "pkg:valid/package_name@1.1.1",
        },
        {
            "bom-ref": "cdxID2",
            "name": "cdx_package2",
            "version": "2.0.0",
            "purl": "pkg:valid/package_name2@2.0.0",
        },
    ]

    wrapped_data = wrap_as_cdx(data)
    assert len(wrapped_data) == 2

    for item in wrapped_data:
        assert isinstance(item, CDXComponent)


def test_SPDXPackage() -> None:
    package_data = {
        "SPDXID": "spdxID",
        "name": "spdx_package",
        "versionInfo": "2.0.0",
        "externalRefs": [
            {
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceLocator": "pkg:valid/package_name@1.1.1",
                "referenceType": "purl",
            }
        ],
    }
    spdx_package = SPDXPackage(package_data)
    assert spdx_package.id() == "spdxID"
    assert spdx_package.name() == "spdx_package"
    assert spdx_package.version() == "2.0.0"
    assert spdx_package.purl() == PackageURL.from_string("pkg:valid/package_name@1.1.1")

    package_data_multiple_refs = {
        "SPDXID": "spdxID",
        "name": "spdx_package",
        "versionInfo": "2.0.0",
        "externalRefs": [
            {
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceLocator": "pkg:valid/package_name@1.1.1",
                "referenceType": "purl",
            },
            {
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceLocator": "pkg:valid/package_name2@2.0.0",
                "referenceType": "purl",
            },
        ],
    }

    spdx_package_multiple_refs = SPDXPackage(package_data_multiple_refs)
    with pytest.raises(ValueError):
        spdx_package_multiple_refs.purl()


def test_wrap_as_spdx() -> None:
    data = [
        {
            "SPDXID": "spdxID",
            "name": "spdx_package",
            "versionInfo": "2.0.0",
        },
        {
            "SPDXID": "spdxID2",
            "name": "spdx_package2",
            "versionInfo": "3.0.0",
        },
    ]

    wrapped_data = wrap_as_spdx(data)
    assert len(wrapped_data) == 2

    for item in wrapped_data:
        assert isinstance(item, SPDXPackage)


def test__subpath_is_version() -> None:
    assert _subpath_is_version("v2") is True
    assert _subpath_is_version("v10noversion") is False
    assert _subpath_is_version("noversion") is False


@pytest.mark.parametrize(
    "syft_tools_metadata, hermeto_tools_metadata, expected_result",
    [
        (
            [TOOLS_METADATA["syft-cyclonedx-1.4"]],
            [TOOLS_METADATA["hermeto-cyclonedx-1.4"]],
            [
                TOOLS_METADATA["syft-cyclonedx-1.4"],
                TOOLS_METADATA["hermeto-cyclonedx-1.4"],
            ],
        ),
        (
            [TOOLS_METADATA["syft-cyclonedx-1.4"]],
            {
                "components": [TOOLS_METADATA["hermeto-cyclonedx-1.5"]],
            },
            [
                TOOLS_METADATA["syft-cyclonedx-1.4"],
                TOOLS_METADATA["hermeto-cyclonedx-1.4"],
            ],
        ),
        (
            {
                "components": [TOOLS_METADATA["syft-cyclonedx-1.5"]],
            },
            {
                "components": [TOOLS_METADATA["hermeto-cyclonedx-1.5"]],
            },
            {
                "components": [
                    TOOLS_METADATA["syft-cyclonedx-1.5"],
                    TOOLS_METADATA["hermeto-cyclonedx-1.5"],
                ],
            },
        ),
        (
            {
                "components": [TOOLS_METADATA["syft-cyclonedx-1.5"]],
            },
            [TOOLS_METADATA["hermeto-cyclonedx-1.4"]],
            {
                "components": [
                    TOOLS_METADATA["syft-cyclonedx-1.5"],
                    TOOLS_METADATA["hermeto-cyclonedx-1.5"],
                ],
            },
        ),
    ],
)
def test__merge_tools_metadata(
    syft_tools_metadata: Any, hermeto_tools_metadata: Any, expected_result: Any
) -> None:
    syft_sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "metadata": {
            "tools": syft_tools_metadata,
        },
        "components": [],
    }

    hermeto_sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "metadata": {
            "tools": hermeto_tools_metadata,
        },
        "components": [],
    }

    merger = CycloneDXMerger(merge_by_apparent_sameness)
    merger2 = CycloneDXMerger(merge_by_prefering_hermeto)
    result = merger.merge(syft_sbom, hermeto_sbom)
    result2 = merger2.merge(syft_sbom, hermeto_sbom)

    assert result["metadata"]["tools"] == expected_result
    assert result2["metadata"]["tools"] == expected_result


def test__merge_tools_metadata_invalid() -> None:
    syft_sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "metadata": {
            "tools": "invalid_metadata",
        },
        "components": [],
    }

    hermeto_sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "metadata": {
            "tools": [TOOLS_METADATA["hermeto-cyclonedx-1.4"]],
        },
        "components": [],
    }

    merger = CycloneDXMerger(merge_by_apparent_sameness)
    with pytest.raises(RuntimeError):
        merger.merge(syft_sbom, hermeto_sbom)


def make_spdx_package(
    name: str,
    version: str = "1.0.0",
    purl: str | None = None,
    externalRefs: list[dict[str, Any]] | None = None,
) -> SPDXPackage:
    data: dict[str, Any] = {
        "SPDXID": f"SPDXRef-{name}-{version}",
        "name": name,
        "versionInfo": version,
    }
    if purl:
        data["externalRefs"] = [
            {
                "referenceCategory": "PACKAGE_MANAGER",
                "referenceLocator": purl,
                "referenceType": "purl",
            }
        ]
    if externalRefs:
        data["externalRefs"] = externalRefs
    return SPDXPackage(data)


def make_cdx_component(
    name: str,
    version: str = "1.0.0",
    purl: str | None = None,
    bom_ref: str | None = None,
) -> CDXComponent:
    data = {
        "bom-ref": bom_ref or f"{name}-{version}",
        "name": name,
        "version": version,
    }
    if purl:
        data["purl"] = purl
    return CDXComponent(data)


def test__get_syft_component_filter_duplicate_by_key() -> None:
    hermeto_spdx = [make_spdx_package("foo", "1.0.0", "pkg:pypi/foo@1.0.0")]
    syft_spdx = [make_spdx_package("foo", "1.0.0", "pkg:pypi/foo@1.0.0")]
    component_is_removable_spdx = _get_syft_component_filter(hermeto_spdx)

    assert component_is_removable_spdx(syft_spdx[0]) is True

    hermeto_cdx = [make_cdx_component("foo", "1.0.0", "pkg:pypi/foo@1.0.0")]
    syft_cdx = [make_cdx_component("foo", "1.0.0", "pkg:pypi/foo@1.0.0")]
    component_is_removable_cdx = _get_syft_component_filter(hermeto_cdx)
    assert component_is_removable_cdx(syft_cdx[0]) is True


def test__get_syft_component_filter_duplicate_non_registry() -> None:
    hermeto_spdx = [
        make_spdx_package(
            "bar", "2.0.0", "pkg:pypi/bar@2.0.0?vcs_url=https://github.com/example/bar"
        )
    ]
    syft_spdx = [make_spdx_package("bar", "2.0.0", "pkg:pypi/bar@2.0.0")]
    component_is_removable_spdx = _get_syft_component_filter(hermeto_spdx)
    assert component_is_removable_spdx(syft_spdx[0]) is True

    hermeto_cdx = [
        make_cdx_component(
            "bar", "2.0.0", "pkg:pypi/bar@2.0.0?vcs_url=https://github.com/example/bar"
        )
    ]
    syft_cdx = [make_cdx_component("bar", "2.0.0", "pkg:pypi/bar@2.0.0")]
    component_is_removable_cdx = _get_syft_component_filter(hermeto_cdx)
    assert component_is_removable_cdx(syft_cdx[0]) is True


def test__get_syft_component_filter_duplicate_npm_localpath() -> None:
    hermeto_spdx = [make_spdx_package("baz", "3.0.0", "pkg:npm/baz@3.0.0#subdir")]
    syft_spdx = [make_spdx_package("subdir", "3.0.0", "pkg:npm/subdir@3.0.0")]
    component_is_removable_spdx = _get_syft_component_filter(hermeto_spdx)

    assert component_is_removable_spdx(syft_spdx[0]) is True

    hermeto_cdx = [make_cdx_component("baz", "3.0.0", "pkg:npm/baz@3.0.0#subdir")]

    syft_cdx = [make_cdx_component("subdir", "3.0.0", "pkg:npm/subdir@3.0.0")]
    component_is_removable_cdx = _get_syft_component_filter(hermeto_cdx)
    assert component_is_removable_cdx(syft_cdx[0]) is True


def test__get_syft_component_filter_local_golang_replacement() -> None:
    hermeto: list[Any] = []
    syft = [
        make_spdx_package(".localmod", "(devel)", "pkg:golang/.localmod@(devel)"),
        make_spdx_package(".local", "(devel)", "pkg:golang/.local@@(devel)#subdir"),
    ]
    component_is_removable = _get_syft_component_filter(hermeto)
    assert component_is_removable(syft[0]) is True
    assert component_is_removable(syft[1]) is True


def test__get_syft_component_filter_not_duplicate() -> None:
    hermeto = [make_cdx_component("foo", "1.0.0", "pkg:pypi/foo@1.0.0")]
    syft = [make_cdx_component("bar", "2.0.0", "pkg:pypi/bar@2.0.0")]
    component_is_removable = _get_syft_component_filter(hermeto)
    assert component_is_removable(syft[0]) is False


MockFunction = Callable[[Sequence[SBOMItem], Sequence[SBOMItem]], list[dict[str, Any]]]


@patch("mobster.sbom.merge._detect_sbom_type")
def test__create_merger(mock_detect_sbom_type: Mock) -> None:
    mock_detect_sbom_type.return_value = "cyclonedx"

    mock_function: MockFunction = Mock(spec=MockFunction)

    merger = _create_merger({}, {}, mock_function)
    assert isinstance(merger, CycloneDXMerger)

    mock_detect_sbom_type.return_value = "spdx"
    merger = _create_merger({}, {}, mock_function)
    assert isinstance(merger, SPDXMerger)


def test__create_merger_invalid() -> None:
    cycloneDX_sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "components": [],
    }
    spdx_sbom = {
        "SPDXID": "DocumentRef-SPDXRef-DOCUMENT",
        "name": "example",
        "spdxVersion": "SPDX-2.4",
        "versionInfo": "1.0.0",
        "dataLicense": "CC0-1.0",
        "documentNamespace": "http://spdx.org/spdxdocs/example-1.0.0",
        "creationInfo": {},
    }

    mock_function: MockFunction = Mock(spec=MockFunction)

    with pytest.raises(ValueError):
        _create_merger(spdx_sbom, cycloneDX_sbom, mock_function)


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
    invalid_sbom = {
        "no_format_mentioned": "fail",
    }

    with pytest.raises(ValueError):
        _detect_sbom_type(invalid_sbom)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "syft_sboms, hermeto_sbom",
    [
        ([Path("syft.merged-by-us.bom.json")], Path("cachi2.bom.json")),
        (
            INDIVIDUAL_SYFT_SBOMS,
            # merging these 4 should result in syft.merged-by-us.bom.json
            Path("cachi2.bom.json"),
            # merging the result with the cachi2.bom.json should be the same as the cases above
        ),
    ],
)
@pytest.mark.parametrize(
    "sbom_type, should_take_from_syft",
    [
        (
            "cyclonedx",
            {
                # The operating system component appears only in CycloneDX Syft SBOMs, not SPDX
                "rhel@9.5": 1,
                # vvv Identical between CycloneDX and SPDX
                "pkg:golang/github.com/release-engineering/retrodep@v2.1.0#v2": 1,
                "pkg:rpm/rhel/basesystem@11-13.el9?arch=noarch&distro=rhel-9.5&upstream=basesystem-11-13.el9.src.rpm": 1,
                "pkg:rpm/rhel/bash@5.1.8-9.el9?arch=x86_64&distro=rhel-9.5&upstream=bash-5.1.8-9.el9.src.rpm": 1,
                "pkg:rpm/rhel/coreutils-single@8.32-36.el9?arch=x86_64&distro=rhel-9.5&upstream=coreutils-8.32-36.el9.src.rpm": 1,
                "pkg:rpm/rhel/filesystem@3.16-5.el9?arch=x86_64&distro=rhel-9.5&upstream=filesystem-3.16-5.el9.src.rpm": 1,
                "pkg:rpm/rhel/glibc@2.34-125.el9_5.1?arch=x86_64&distro=rhel-9.5&upstream=glibc-2.34-125.el9_5.1.src.rpm": 1,
                "pkg:rpm/rhel/glibc-common@2.34-125.el9_5.1?arch=x86_64&distro=rhel-9.5&upstream=glibc-2.34-125.el9_5.1.src.rpm": 1,
                "pkg:rpm/rhel/glibc-minimal-langpack@2.34-125.el9_5.1?arch=x86_64&distro=rhel-9.5&upstream=glibc-2.34-125.el9_5.1.src.rpm": 1,
                "pkg:rpm/rhel/gpg-pubkey@5a6340b3-6229229e?distro=rhel-9.5": 1,
                "pkg:rpm/rhel/gpg-pubkey@fd431d51-4ae0493b?distro=rhel-9.5": 1,
                "pkg:rpm/rhel/libacl@2.3.1-4.el9?arch=x86_64&distro=rhel-9.5&upstream=acl-2.3.1-4.el9.src.rpm": 1,
                "pkg:rpm/rhel/libattr@2.5.1-3.el9?arch=x86_64&distro=rhel-9.5&upstream=attr-2.5.1-3.el9.src.rpm": 1,
                "pkg:rpm/rhel/libcap@2.48-9.el9_2?arch=x86_64&distro=rhel-9.5&upstream=libcap-2.48-9.el9_2.src.rpm": 1,
                "pkg:rpm/rhel/libgcc@11.5.0-2.el9?arch=x86_64&distro=rhel-9.5&upstream=gcc-11.5.0-2.el9.src.rpm": 1,
                "pkg:rpm/rhel/libselinux@3.6-1.el9?arch=x86_64&distro=rhel-9.5&upstream=libselinux-3.6-1.el9.src.rpm": 1,
                "pkg:rpm/rhel/libsepol@3.6-1.el9?arch=x86_64&distro=rhel-9.5&upstream=libsepol-3.6-1.el9.src.rpm": 1,
                "pkg:rpm/rhel/ncurses-base@6.2-10.20210508.el9?arch=noarch&distro=rhel-9.5&upstream=ncurses-6.2-10.20210508.el9.src.rpm": 1,
                "pkg:rpm/rhel/ncurses-libs@6.2-10.20210508.el9?arch=x86_64&distro=rhel-9.5&upstream=ncurses-6.2-10.20210508.el9.src.rpm": 1,
                "pkg:rpm/rhel/pcre2@10.40-6.el9?arch=x86_64&distro=rhel-9.5&upstream=pcre2-10.40-6.el9.src.rpm": 1,
                "pkg:rpm/rhel/pcre2-syntax@10.40-6.el9?arch=noarch&distro=rhel-9.5&upstream=pcre2-10.40-6.el9.src.rpm": 1,
                "pkg:rpm/rhel/redhat-release@9.5-0.6.el9?arch=x86_64&distro=rhel-9.5&upstream=redhat-release-9.5-0.6.el9.src.rpm": 1,
                "pkg:rpm/rhel/setup@2.13.7-10.el9?arch=noarch&distro=rhel-9.5&upstream=setup-2.13.7-10.el9.src.rpm": 1,
                "pkg:rpm/rhel/tzdata@2024b-2.el9?arch=noarch&distro=rhel-9.5&upstream=tzdata-2024b-2.el9.src.rpm": 1,
            },
        ),
        (
            "spdx",
            {
                # These root packages appear only in SPDX Syft SBOMs, not CycloneDX
                "SPDXRef-DocumentRoot-Directory-.": 1,
                "pkg:oci/registry.access.redhat.com/ubi9/ubi-micro@sha256:71c7ec827876417693bd3feb615a5c70753b78667cb27c17cb3a5346a6955da5?arch=amd64&tag=9.5": 1,
                # vvv Identical between CycloneDX and SPDX
                "pkg:golang/github.com/release-engineering/retrodep@v2.1.0#v2": 1,
                "pkg:rpm/rhel/basesystem@11-13.el9?arch=noarch&distro=rhel-9.5&upstream=basesystem-11-13.el9.src.rpm": 1,
                "pkg:rpm/rhel/bash@5.1.8-9.el9?arch=x86_64&distro=rhel-9.5&upstream=bash-5.1.8-9.el9.src.rpm": 1,
                "pkg:rpm/rhel/coreutils-single@8.32-36.el9?arch=x86_64&distro=rhel-9.5&upstream=coreutils-8.32-36.el9.src.rpm": 1,
                "pkg:rpm/rhel/filesystem@3.16-5.el9?arch=x86_64&distro=rhel-9.5&upstream=filesystem-3.16-5.el9.src.rpm": 1,
                "pkg:rpm/rhel/glibc@2.34-125.el9_5.1?arch=x86_64&distro=rhel-9.5&upstream=glibc-2.34-125.el9_5.1.src.rpm": 1,
                "pkg:rpm/rhel/glibc-common@2.34-125.el9_5.1?arch=x86_64&distro=rhel-9.5&upstream=glibc-2.34-125.el9_5.1.src.rpm": 1,
                "pkg:rpm/rhel/glibc-minimal-langpack@2.34-125.el9_5.1?arch=x86_64&distro=rhel-9.5&upstream=glibc-2.34-125.el9_5.1.src.rpm": 1,
                "pkg:rpm/rhel/gpg-pubkey@5a6340b3-6229229e?distro=rhel-9.5": 1,
                "pkg:rpm/rhel/gpg-pubkey@fd431d51-4ae0493b?distro=rhel-9.5": 1,
                "pkg:rpm/rhel/libacl@2.3.1-4.el9?arch=x86_64&distro=rhel-9.5&upstream=acl-2.3.1-4.el9.src.rpm": 1,
                "pkg:rpm/rhel/libattr@2.5.1-3.el9?arch=x86_64&distro=rhel-9.5&upstream=attr-2.5.1-3.el9.src.rpm": 1,
                "pkg:rpm/rhel/libcap@2.48-9.el9_2?arch=x86_64&distro=rhel-9.5&upstream=libcap-2.48-9.el9_2.src.rpm": 1,
                "pkg:rpm/rhel/libgcc@11.5.0-2.el9?arch=x86_64&distro=rhel-9.5&upstream=gcc-11.5.0-2.el9.src.rpm": 1,
                "pkg:rpm/rhel/libselinux@3.6-1.el9?arch=x86_64&distro=rhel-9.5&upstream=libselinux-3.6-1.el9.src.rpm": 1,
                "pkg:rpm/rhel/libsepol@3.6-1.el9?arch=x86_64&distro=rhel-9.5&upstream=libsepol-3.6-1.el9.src.rpm": 1,
                "pkg:rpm/rhel/ncurses-base@6.2-10.20210508.el9?arch=noarch&distro=rhel-9.5&upstream=ncurses-6.2-10.20210508.el9.src.rpm": 1,
                "pkg:rpm/rhel/ncurses-libs@6.2-10.20210508.el9?arch=x86_64&distro=rhel-9.5&upstream=ncurses-6.2-10.20210508.el9.src.rpm": 1,
                "pkg:rpm/rhel/pcre2@10.40-6.el9?arch=x86_64&distro=rhel-9.5&upstream=pcre2-10.40-6.el9.src.rpm": 1,
                "pkg:rpm/rhel/pcre2-syntax@10.40-6.el9?arch=noarch&distro=rhel-9.5&upstream=pcre2-10.40-6.el9.src.rpm": 1,
                "pkg:rpm/rhel/redhat-release@9.5-0.6.el9?arch=x86_64&distro=rhel-9.5&upstream=redhat-release-9.5-0.6.el9.src.rpm": 1,
                "pkg:rpm/rhel/setup@2.13.7-10.el9?arch=noarch&distro=rhel-9.5&upstream=setup-2.13.7-10.el9.src.rpm": 1,
                "pkg:rpm/rhel/tzdata@2024b-2.el9?arch=noarch&distro=rhel-9.5&upstream=tzdata-2024b-2.el9.src.rpm": 1,
            },
        ),
    ],
)
async def test_merge_syft_and_hermeto_sboms(
    syft_sboms: list[Path],
    hermeto_sbom: Path,
    sbom_type: str,
    should_take_from_syft: dict[str, int],
    data_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(data_dir / sbom_type)
    result = await merge_sboms(syft_sboms, hermeto_sbom)

    with open("merged.bom.json", encoding="utf-8") as file:
        expected_sbom = json.load(file)

    assert result == expected_sbom

    with open("cachi2.bom.json", encoding="utf-8") as f:
        cachi2_sbom = json.load(f)

    taken_from_syft = diff_counts(
        count_components(expected_sbom), count_components(cachi2_sbom)
    )
    assert taken_from_syft == should_take_from_syft

    if sbom_type == "spdx":
        relationships_from_syft = diff_counts(
            count_relationships(expected_sbom), count_relationships(cachi2_sbom)
        )
        assert relationships_from_syft == {
            "SPDXRef-DOCUMENT DESCRIBES SPDXRef-DocumentRoot-Directory-.": 1,
            "SPDXRef-DOCUMENT DESCRIBES SPDXRef-DocumentRoot-Image-registry.access.redhat.com-ubi9-ubi-micro": 1,
            # The one pkg:golang package
            "SPDXRef-DocumentRoot-Directory-. CONTAINS *": 1,
            # All the pkg:rpm packages
            "SPDXRef-DocumentRoot-Image-registry.access.redhat.com-ubi9-ubi-micro CONTAINS *": 22,
        }


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "sbom_type, expect_diff",
    [
        (
            "cyclonedx",
            {
                # All of these golang purls appear twice in the SBOM merged by syft
                # (they already appear twice in the individual gomod SBOM).
                # They only appear once in the SBOM merged by us, which seems better.
                "pkg:golang/github.com/Azure/go-ansiterm@v0.0.0-20210617225240-d185dfc1b5a1": -1,
                "pkg:golang/github.com/moby/term@v0.0.0-20221205130635-1aeaba878587": -1,
                "pkg:golang/golang.org/x/sys@v0.6.0": -1,
                # The rhel@9.5 component doesn't have a purl. Syft drops it when merging, we keep it.
                "rhel@9.5": 1,
            },
        ),
        (
            "spdx",
            {
                # This is the "made-up root" that Syft uses for the merged SBOM
                "SPDXRef-DocumentRoot-Directory-.-syft-sboms": -1,
                # We instead keep the original "made-up root", as well as the root of the
                # ubi-micro.bom.json document (which has an actual root, not a made-up one,
                # because it comes from scanning a container image, not a directory).
                "SPDXRef-DocumentRoot-Directory-.": 1,
                "pkg:oci/registry.access.redhat.com/ubi9/ubi-micro@sha256:71c7ec827876417693bd3feb615a5c70753b78667cb27c17cb3a5346a6955da5?arch=amd64&tag=9.5": 1,
                # For some reason, Syft lowercases the purls when merging. We do not.
                "pkg:golang/github.com/masterminds/semver@v1.4.2": -1,
                "pkg:golang/github.com/Masterminds/semver@v1.4.2": 1,
                "pkg:golang/github.com/microsoft/go-winio@v0.6.0": -1,
                "pkg:golang/github.com/Microsoft/go-winio@v0.6.0": 1,
                "pkg:golang/github.com/azure/go-ansiterm@v0.0.0-20210617225240-d185dfc1b5a1": -1,
                "pkg:golang/github.com/Azure/go-ansiterm@v0.0.0-20210617225240-d185dfc1b5a1": 1,
            },
        ),
    ],
)
async def test_merge_multiple_syft_sboms(
    sbom_type: str,
    expect_diff: dict[str, int],
    data_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(data_dir / sbom_type)

    result = await merge_sboms(
        INDIVIDUAL_SYFT_SBOMS,
    )

    with open("syft.merged-by-us.bom.json", encoding="utf-8") as f:
        merged_by_us = json.load(f)

    assert result == merged_by_us

    with open("syft.merged-by-syft.bom.json", encoding="utf-8") as f:
        merged_by_syft = json.load(f)

    compared_to_syft = diff_counts(
        count_components(merged_by_us), count_components(merged_by_syft)
    )
    assert compared_to_syft == expect_diff

    if sbom_type == "spdx":
        relationships_diff = diff_counts(
            count_relationships(merged_by_us), count_relationships(merged_by_syft)
        )
        assert relationships_diff == {
            "SPDXRef-DOCUMENT DESCRIBES SPDXRef-DocumentRoot-Directory-.-syft-sboms": -1,
            "SPDXRef-DOCUMENT DESCRIBES SPDXRef-DocumentRoot-Image-registry.access.redhat.com-ubi9-ubi-micro": 1,
            "SPDXRef-DOCUMENT DESCRIBES SPDXRef-DocumentRoot-Directory-.": 1,
            # In the Syft-merged SBOM, the ./syft-sboms element contains everything
            # In our merged SBOM, the same set of packages is split between two roots
            "SPDXRef-DocumentRoot-Directory-.-syft-sboms CONTAINS *": -139,
            "SPDXRef-DocumentRoot-Directory-. CONTAINS *": 117,
            "SPDXRef-DocumentRoot-Image-registry.access.redhat.com-ubi9-ubi-micro CONTAINS *": 22,
        }


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "syft_sboms, hermeto_sbom",
    [
        ([], Path("hermeto-bom.json")),
        ([Path("only-one-syft.bom.json")], None),
    ],
)
async def test_merge_sboms_invalid(
    syft_sboms: list[Path],
    hermeto_sbom: Path | None,
) -> None:
    """Test the merge_sboms function."""
    with pytest.raises(ValueError):
        await merge_sboms(syft_sboms, hermeto_sbom)
