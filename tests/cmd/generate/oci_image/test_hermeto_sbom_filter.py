"""Unit tests for hermeto_sbom_filter module."""

import json
from pathlib import Path
from typing import Any

import pytest

from mobster.cmd.generate.oci_image.hermeto_sbom_filter import (
    filter_hermeto_sbom_by_arch,
)


@pytest.fixture
def spdx_sbom() -> Any:
    """
    Return a minimal SPDX SBOM for testing architecture filtering.

    This SBOM contains:
    - 1 root package without purl (should always be kept)
    - 1 non-RPM package (should always be kept)
    - 2 noarch packages with identical checksums (only one should be kept)
    - 1 package with x86_64 architecture
    - 1 package with aarch64 architecture
    """
    path = Path(__file__).parent / "test_hermeto_sbom_filter_data" / "spdx.bom.json"

    with open(path) as file:
        return json.load(file)


@pytest.fixture
def cyclonedx_sbom() -> Any:
    """
    Return a minimal SPDX SBOM for testing architecture filtering.

    This SBOM contains:
    - 1 non-RPM package (should always be kept)
    - 2 noarch packages with identical checksums (only one should be kept)
    - 1 package with x86_64 architecture
    - 1 package with aarch64 architecture
    """
    path = (
        Path(__file__).parent / "test_hermeto_sbom_filter_data" / "cyclonedx.bom.json"
    )

    with open(path) as file:
        return json.load(file)


ALWAYS_KEPT_SPDX_PACKAGES = {
    "SPDXRef-DocumentRoot",
    "SPDXRef-Package-jq-noarch-1",
    "SPDXRef-Package-npm-package",
}

ALWAYS_KEPT_CYCLONEDX_COMPONENTS = {
    "pkg:rpm/redhat/jq@1.6-19.el9?arch=noarch&checksum=sha256:ghi789&repository_id=repo-for-x86",
    "pkg:npm/lodash@4.17.21",
}


class TestFilterHermetoSbomByArchValidations:
    """Tests the validations performed by the filter_hermeto_sbom_by_arch function."""

    def test_unknow_sbom_format_raises_value_error(self) -> None:
        """Test that SBOM that is neither SPDX or CycloneDX raises ValueError."""
        sbom_dict = {
            "creationInfo": {"creators": ["Tool: hermeto"]},
        }
        with pytest.raises(ValueError, match="Unknown SBOM format"):
            filter_hermeto_sbom_by_arch(sbom_dict, "aarch64")


class TestFilterHermetoSPDXSbomByArch:
    """Tests the filter_hermeto_sbom_by_arch function on SPDX SBOMs."""

    @pytest.mark.parametrize(
        "target_arch, expected_ids",
        [
            pytest.param(
                "x86_64",
                ALWAYS_KEPT_SPDX_PACKAGES | {"SPDXRef-Package-gzip-x86_64"},
                id="x86_64",
            ),
            pytest.param(
                "aarch64",
                ALWAYS_KEPT_SPDX_PACKAGES | {"SPDXRef-Package-gzip-aarch64"},
                id="aarch64",
            ),
            pytest.param(
                "randomarch",
                ALWAYS_KEPT_SPDX_PACKAGES,
                id="randomarch",
            ),
        ],
    )
    def test_filter_spdx_sbom(
        self, target_arch: str, spdx_sbom: dict[str, Any], expected_ids: set[str]
    ) -> None:
        """Test filtering SBOM for a target architecture."""

        result = filter_hermeto_sbom_by_arch(spdx_sbom, target_arch)

        package_ids = {pkg["SPDXID"] for pkg in result["packages"]}
        assert package_ids == expected_ids

        relationship_ids = {
            pkg["relatedSpdxElement"] for pkg in result["relationships"]
        }
        assert relationship_ids == expected_ids

    def test_filter_sbom_empty_packages(self) -> None:
        """Test filtering SBOM with empty packages list."""
        sbom_dict = {
            "spdxVersion": "SPDX-2.3",
            "creationInfo": {"creators": ["Tool: hermeto", "Organization: red hat"]},
            "packages": [],
            "relationships": [],
        }

        result = filter_hermeto_sbom_by_arch(sbom_dict, "x86_64")

        assert len(result["packages"]) == 0
        assert len(result["relationships"]) == 0

    def test_filter_sbom_preserves_other_fields(
        self, spdx_sbom: dict[str, Any]
    ) -> None:
        """Test that filtering preserves other SBOM fields."""
        original_name = spdx_sbom["name"]
        original_namespace = spdx_sbom["documentNamespace"]

        result = filter_hermeto_sbom_by_arch(spdx_sbom, "x86_64")

        assert result["name"] == original_name
        assert result["documentNamespace"] == original_namespace
        assert result["spdxVersion"] == "SPDX-2.3"


class TestFilterHermetoCycloneDXSbomByArch:
    """Tests the filter_hermeto_sbom_by_arch function on CycloneDX SBOMs."""

    @pytest.mark.parametrize(
        "target_arch, expected_purls",
        [
            pytest.param(
                "x86_64",
                ALWAYS_KEPT_CYCLONEDX_COMPONENTS
                | {"pkg:rpm/redhat/gzip@1.12-1.el9?arch=x86_64&checksum=sha256:abc123"},
                id="x86_64",
            ),
            pytest.param(
                "aarch64",
                ALWAYS_KEPT_CYCLONEDX_COMPONENTS
                | {
                    "pkg:rpm/redhat/gzip@1.12-1.el9?arch=aarch64&checksum=sha256:def456"
                },
                id="aarch64",
            ),
            pytest.param(
                "randomarch",
                ALWAYS_KEPT_CYCLONEDX_COMPONENTS,
                id="randomarch",
            ),
        ],
    )
    def test_filter_cyclonedx_sbom(
        self, target_arch: str, cyclonedx_sbom: dict[str, Any], expected_purls: set[str]
    ) -> None:
        """Test filtering SBOM for a target architecture."""

        result = filter_hermeto_sbom_by_arch(cyclonedx_sbom, target_arch)

        kept_purls = {component["purl"] for component in result["components"]}
        assert kept_purls == expected_purls

    def test_filter_sbom_empty_components(self) -> None:
        """Test filtering SBOM with empty packages list."""
        sbom_dict = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "version": 1,
            "metadata": {"tools": [{"vendor": "red hat", "name": "hermeto"}]},
            "components": [],
        }

        result = filter_hermeto_sbom_by_arch(sbom_dict, "x86_64")

        assert len(result["components"]) == 0

    def test_filter_sbom_preserves_other_fields(
        self, cyclonedx_sbom: dict[str, Any]
    ) -> None:
        """Test that filtering preserves other SBOM fields."""
        original_bom_format = cyclonedx_sbom["bomFormat"]
        original_spec_version = cyclonedx_sbom["specVersion"]
        original_version = cyclonedx_sbom["version"]

        result = filter_hermeto_sbom_by_arch(cyclonedx_sbom, "x86_64")

        assert result["bomFormat"] == original_bom_format
        assert result["specVersion"] == original_spec_version
        assert result["version"] == original_version
