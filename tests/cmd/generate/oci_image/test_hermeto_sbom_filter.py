"""Unit tests for hermeto_sbom_filter module."""

import pytest

from mobster.cmd.generate.oci_image.hermeto_sbom_filter import (
    filter_hermeto_sbom_by_arch,
)


class TestFilterHermetoSbomByArch:
    """Tests for the filter_hermeto_sbom_by_arch function."""

    def test_empty_target_arch_raises_value_error(self) -> None:
        """Test that an empty target_arch raises ValueError."""
        with pytest.raises(
            ValueError, match="No target architecture specified for filtering"
        ):
            filter_hermeto_sbom_by_arch({}, "")

    def test_unknow_sbom_format_raises_value_error(self) -> None:
        """Test that SBOM that is neither SPDX or CycloneDX raises ValueError."""
        sbom_dict = {
            "creationInfo": {"creators": ["Tool: hermeto"]},
        }
        with pytest.raises(ValueError, match="Unknown SBOM format"):
            filter_hermeto_sbom_by_arch(sbom_dict, "aarch64")
