"""Logging utilities for contextual SBOM matching statistics."""

import json
import logging
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from spdx_tools.spdx.model.package import Package
from spdx_tools.spdx.model.relationship import Relationship

from mobster.cmd.generate.oci_image.contextual_sbom.constants import (
    MatchBy,
    PackageMatchInfo,
    PackageProducer,
)

LOGGER = logging.getLogger(__name__)


@dataclass
class PackageStats:
    """
    Statistics for a single SBOM (parent or component).

    Tracks all packages, which were matched, and which lack unique identifiers.
    """

    all_packages: set[str] = field(default_factory=set)
    matched_packages: set[str] = field(default_factory=set)
    packages_without_unique_id: set[str] = field(default_factory=set)

    @property
    def unmatched_packages(self) -> set[str]:
        """All packages that were not matched."""
        return self.all_packages - self.matched_packages

    @property
    def unmatched_with_unique_id(self) -> set[str]:
        """
        Packages with unique ID that were not matched.
        In component SBOM those are component-only content (installed in final layer).
        In parent SBOM those are removed at build time.
        """
        return self.unmatched_packages - self.packages_without_unique_id


@dataclass
class MatchIdentifierStats:
    """
    Statistics about match identifiers used for match.

    Tracks how many matches were made by checksums, verification codes, or PURLs.
    """

    by_checksum: int = 0
    by_verification_code: int = 0
    by_purl: int = 0

    @property
    def total(self) -> int:
        """Total number of matches across all methods."""
        return self.by_checksum + self.by_verification_code + self.by_purl


@dataclass
class ProducerMatchStats:
    """
    Statistics about producer combinations in matches.

    Tracks matches between different producer combinations (SYFT/HERMETO).
    """

    syft_to_syft: int = 0
    hermeto_to_syft: int = 0
    # Those two should be always 0 - parent content
    # (either syft or hermeto-produced) shouldn't be
    # matched to component-only (installed) content
    # represented by hermeto packages in component SBOM
    syft_to_hermeto: int = 0
    hermeto_to_hermeto: int = 0


@dataclass
class DuplicateTracker:
    """
    Tracks duplicate identifiers across matches.

    Maps identifier values to sets of (parent_spdx_id, component_spdx_id) tuples
    that matched using that identifier.
    """

    checksums: dict[str, set[tuple[str, str]]] = field(
        default_factory=lambda: defaultdict(set)
    )
    verification_codes: dict[str, set[tuple[str, str]]] = field(
        default_factory=lambda: defaultdict(set)
    )
    purls: dict[str, set[tuple[str, str]]] = field(
        default_factory=lambda: defaultdict(set)
    )

    @property
    def duplicate_checksums(self) -> dict[str, set[tuple[str, str]]]:
        """Checksums that matched multiple package pairs."""
        return {k: v for k, v in self.checksums.items() if len(v) > 1}

    @property
    def duplicate_verification_codes(self) -> dict[str, set[tuple[str, str]]]:
        """Verification codes that matched multiple package pairs."""
        return {k: v for k, v in self.verification_codes.items() if len(v) > 1}

    @property
    def duplicate_purls(self) -> dict[str, set[tuple[str, str]]]:
        """PURLs that matched multiple package pairs."""
        return {k: v for k, v in self.purls.items() if len(v) > 1}


@dataclass
class MatchingStatistics:
    """
    Statistics about package matching between parent and component SBOMs.

    Organized into logical groups for better maintainability and clarity.
    """

    component: PackageStats = field(default_factory=PackageStats)
    parent: PackageStats = field(default_factory=PackageStats)
    match_methods: MatchIdentifierStats = field(default_factory=MatchIdentifierStats)
    producer_matches: ProducerMatchStats = field(default_factory=ProducerMatchStats)
    duplicates: DuplicateTracker = field(default_factory=DuplicateTracker)

    def record_component_packages(
        self, component_packages: list[tuple[Package, Relationship]]
    ) -> None:
        """Record all component packages."""
        self.component.all_packages = {c.spdx_id for c, r in component_packages}

    def record_parent_packages(
        self, parent_packages: list[tuple[Package, Relationship]]
    ) -> None:
        """Record all parent packages."""
        self.parent.all_packages = {p.spdx_id for p, r in parent_packages}

    def record_parent_package_match(self, parent_spdx_id: str) -> None:
        """
        Record that this parent package has been matched.
        This can be higher number than self.component.matched_packages,
        because of the possibility of the duplicates in parent
        (caused by Hermeto bug).
        """
        self.parent.matched_packages.add(parent_spdx_id)

    def record_component_package_match(
        self,
        match_info: PackageMatchInfo,
    ) -> None:
        """
        Record a successful match in component with parent package.
        Store match for later duplicates analysis.
        Store producer combination.

        Args:
            match_info: PackageMatchInfo containing all match details
        """
        self.component.matched_packages.add(match_info.component_info.spdx_id)

        # Track match method
        if match_info.match_by == MatchBy.CHECKSUM:
            self.match_methods.by_checksum += 1
            if match_info.identifier_value:
                self.duplicates.checksums[match_info.identifier_value].add(
                    (match_info.parent_info.spdx_id, match_info.component_info.spdx_id)
                )
        elif match_info.match_by == MatchBy.PACKAGE_VERIFICATION_CODE:
            self.match_methods.by_verification_code += 1
            if match_info.identifier_value:
                self.duplicates.verification_codes[match_info.identifier_value].add(
                    (match_info.parent_info.spdx_id, match_info.component_info.spdx_id)
                )
        elif match_info.match_by == MatchBy.PURL:
            self.match_methods.by_purl += 1
            if match_info.identifier_value:
                self.duplicates.purls[match_info.identifier_value].add(
                    (match_info.parent_info.spdx_id, match_info.component_info.spdx_id)
                )

        # Track match by producer combination
        if (
            match_info.parent_info.producer == PackageProducer.SYFT
            and match_info.component_info.producer == PackageProducer.SYFT
        ):
            self.producer_matches.syft_to_syft += 1
        elif (
            match_info.parent_info.producer == PackageProducer.HERMETO
            and match_info.component_info.producer == PackageProducer.SYFT
        ):
            self.producer_matches.hermeto_to_syft += 1
        # Should be always 0
        elif (
            match_info.parent_info.producer == PackageProducer.SYFT
            and match_info.component_info.producer == PackageProducer.HERMETO
        ):
            self.producer_matches.syft_to_hermeto += 1
        # Should be always 0
        elif (
            match_info.parent_info.producer == PackageProducer.HERMETO
            and match_info.component_info.producer == PackageProducer.HERMETO
        ):
            self.producer_matches.hermeto_to_hermeto += 1

    def record_component_package_without_unique_id(self, spdx_id: str) -> None:
        """
        Record component package without unique identifier.
        Stores the information only once per package.
        """
        self.component.packages_without_unique_id.add(spdx_id)

    def record_parent_package_without_unique_id(self, spdx_id: str) -> None:
        """
        Record parent package without unique identifier.
        Stores the information only once per package.
        """
        self.parent.packages_without_unique_id.add(spdx_id)

    @property
    def duplicate_checksums(self) -> dict[str, set[tuple[str, str]]]:
        """Checksums that matched multiple package pairs."""
        return self.duplicates.duplicate_checksums

    @property
    def duplicate_verification_codes(self) -> dict[str, set[tuple[str, str]]]:
        """Verification codes that matched multiple package pairs."""
        return self.duplicates.duplicate_verification_codes

    @property
    def duplicate_purls(self) -> dict[str, set[tuple[str, str]]]:
        """PURLs that matched multiple package pairs."""
        return self.duplicates.duplicate_purls

    def _prepare_duplicate_identifier_data(
        self,
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
        """
        Prepare duplicate identifier data for structured logging.
        This serves for inspection of duplicate "unique" identifiers.
        Limits duplicate research only to matched content between parent and component.

        This function transforms duplicate identifier mappings into structured data
        suitable for JSON logging and analysis. Each duplicate identifier
        (checksum, verification code, or PURL) that matched multiple package
        pairs is converted into a dictionary containing:
        - identifier: The actual identifier value (checksum string,
            verification code, or PURL)
        - match_count: How many different package pairs were matched between
            parent and component using this identifier
        - spdx_id_pairs: List of all (parent, component) SPDX ID pairs that
            matched

        Returns:
            Tuple of three lists: (checksums_data, verification_codes_data,
            purls_data). Each list contains dictionaries with 'identifier',
            'match_count', and 'spdx_id_pairs' keys.
        """
        duplicate_checksums_data = []
        for checksum, matches in self.duplicate_checksums.items():
            duplicate_checksums_data.append(
                {
                    "identifier": checksum,
                    "match_count": len(matches),
                    "spdx_id_pairs": [
                        {"parent": p, "component": c} for p, c in matches
                    ],
                }
            )

        duplicate_verification_codes_data = []
        for code, matches in self.duplicate_verification_codes.items():
            duplicate_verification_codes_data.append(
                {
                    "identifier": code,
                    "match_count": len(matches),
                    "spdx_id_pairs": [
                        {"parent": p, "component": c} for p, c in matches
                    ],
                }
            )

        duplicate_purls_data = []
        for purl, matches in self.duplicate_purls.items():
            duplicate_purls_data.append(
                {
                    "identifier": purl,
                    "match_count": len(matches),
                    "spdx_id_pairs": [
                        {"parent": p, "component": c} for p, c in matches
                    ],
                }
            )

        return (
            duplicate_checksums_data,
            duplicate_verification_codes_data,
            duplicate_purls_data,
        )

    def log_summary_structured(self) -> None:
        """
        Log structured statistics as JSON for Splunk ingestion.
        """
        # Prepare duplicate identifier data for structured logging
        (
            duplicate_checksums_data,
            duplicate_verification_codes_data,
            duplicate_purls_data,
        ) = self._prepare_duplicate_identifier_data()

        stats_data = {
            "event_type": "contextual_sbom_matching_statistics",
            "component_packages": {
                "total": len(self.component.all_packages),
                "matched": len(self.component.matched_packages),
                "unmatched_all": len(self.component.unmatched_packages),
                "unmatched_component_only": len(
                    self.component.unmatched_with_unique_id
                ),
                "unmatched_without_unique_id": len(
                    self.component.packages_without_unique_id
                ),
            },
            "parent_packages": {
                "total": len(self.parent.all_packages),
                "matched": len(self.parent.matched_packages),
                "unmatched_all": len(self.parent.unmatched_packages),
                "unmatched_removed_at_build": len(self.parent.unmatched_with_unique_id),
                "unmatched_without_unique_id": len(
                    self.parent.packages_without_unique_id
                ),
            },
            "match_methods": {
                "by_checksum": self.match_methods.by_checksum,
                "by_verification_code": self.match_methods.by_verification_code,
                "by_purl": self.match_methods.by_purl,
                "total": self.match_methods.total,
            },
            "match_origins": {
                "syft_to_syft": self.producer_matches.syft_to_syft,
                "syft_to_hermeto": self.producer_matches.syft_to_hermeto,
                "hermeto_to_syft": self.producer_matches.hermeto_to_syft,
                "hermeto_to_hermeto": self.producer_matches.hermeto_to_hermeto,
            },
            "duplicate_identifiers": {
                "checksums": {
                    "count": len(duplicate_checksums_data),
                    "details": duplicate_checksums_data,
                },
                "verification_codes": {
                    "count": len(duplicate_verification_codes_data),
                    "details": duplicate_verification_codes_data,
                },
                "purls": {
                    "count": len(duplicate_purls_data),
                    "details": duplicate_purls_data,
                },
            },
        }

        # Log as JSON for Splunk/structured logging
        LOGGER.info(json.dumps(stats_data))

    def _log_package_counts(self) -> None:
        """Log basic package count statistics."""
        LOGGER.debug("=== Contextual SBOM: Package Matching Statistics ===")
        LOGGER.debug("Total component packages: %d", len(self.component.all_packages))
        LOGGER.debug("Total parent packages: %d", len(self.parent.all_packages))
        LOGGER.debug(
            "Component packages matched: %d", len(self.component.matched_packages)
        )
        # This number may differ from previous one due to the bug in hermeto
        # including packages with multiple architectures into SBOM.
        LOGGER.debug("Parent packages matched: %d", len(self.parent.matched_packages))

    def _log_match_method_breakdown(self) -> None:
        """
        Log statistics about match methods (checksum,
        verification code, purl). Includes duplicate matches.
        """
        total_matches = self.match_methods.total

        if total_matches == 0:
            LOGGER.debug("--- Match Method Breakdown ---")
            LOGGER.debug("  No matches found")
            return

        LOGGER.debug("--- Match Method Breakdown ---")
        LOGGER.debug(
            "  Matched by checksum: %d (%.1f%%)",
            self.match_methods.by_checksum,
            100 * self.match_methods.by_checksum / total_matches,
        )
        LOGGER.debug(
            "  Matched by package verification code: %d (%.1f%%)",
            self.match_methods.by_verification_code,
            100 * self.match_methods.by_verification_code / total_matches,
        )
        LOGGER.debug(
            "  Matched by purl: %d (%.1f%%)",
            self.match_methods.by_purl,
            100 * self.match_methods.by_purl / total_matches,
        )

    def _log_match_producer_breakdown(self) -> None:
        """
        Log statistics about match producer combinations (SYFT/HERMETO combinations).
        """
        total_matches = self.match_methods.total
        if total_matches == 0:
            return

        LOGGER.debug("--- Match Producer Breakdown ---")
        LOGGER.debug(
            "  SYFT (parent) -> SYFT (component): %d (%.1f%%)",
            self.producer_matches.syft_to_syft,
            100 * self.producer_matches.syft_to_syft / total_matches,
        )
        LOGGER.debug(
            "  HERMETO (parent) -> SYFT (component): %d (%.1f%%)",
            self.producer_matches.hermeto_to_syft,
            100 * self.producer_matches.hermeto_to_syft / total_matches,
        )

        # Both of these should be always 0 - HERMETO component packages represent
        # component-only content and should not match with any parent content
        if self.producer_matches.syft_to_hermeto > 0:
            LOGGER.warning(
                "  SYFT (parent) -> HERMETO (component): %d (%.1f%%) "
                "[UNEXPECTED: Parent content should not match component-only content]",
                self.producer_matches.syft_to_hermeto,
                100 * self.producer_matches.syft_to_hermeto / total_matches,
            )
        else:
            LOGGER.debug(
                "  SYFT (parent) -> HERMETO (component): %d (%.1f%%)",
                self.producer_matches.syft_to_hermeto,
                100 * self.producer_matches.syft_to_hermeto / total_matches,
            )

        if self.producer_matches.hermeto_to_hermeto > 0:
            LOGGER.warning(
                "  HERMETO (parent) -> HERMETO (component): %d (%.1f%%) "
                "[UNEXPECTED: Parent content should not match component-only content]",
                self.producer_matches.hermeto_to_hermeto,
                100 * self.producer_matches.hermeto_to_hermeto / total_matches,
            )
        else:
            LOGGER.debug(
                "  HERMETO (parent) -> HERMETO (component): %d (%.1f%%)",
                self.producer_matches.hermeto_to_hermeto,
                100 * self.producer_matches.hermeto_to_hermeto / total_matches,
            )

    def _log_unmatched_packages(self) -> None:
        """
        Log statistics about unmatched packages (component-only and removed at build).
        """
        # non-matchable - missing unique ID
        LOGGER.debug(
            "Component packages without unique ID: %d",
            len(self.component.packages_without_unique_id),
        )
        if self.component.packages_without_unique_id:
            LOGGER.debug(
                "Component packages without unique ID SPDX IDs: %s \n ",
                "\n".join(self.component.packages_without_unique_id),
            )
        LOGGER.debug(
            "Parent packages without unique ID: %d",
            len(self.parent.packages_without_unique_id),
        )
        if self.parent.packages_without_unique_id:
            LOGGER.debug(
                "Parent packages without unique ID SPDX IDs: %s \n ",
                ("\n".join(self.parent.packages_without_unique_id),),
            )

        # has unique ID but has not been matched
        LOGGER.debug(
            "Component-only packages (unique ID, but unmatched with parent): %d",
            len(self.component.unmatched_with_unique_id),
        )
        LOGGER.debug(
            "Parent packages removed from parent at build time (unique ID, "
            "but unmatched with component): %d",
            len(self.parent.unmatched_with_unique_id),
        )
        if self.parent.unmatched_with_unique_id:
            LOGGER.debug(
                "Parent packages removed from parent at build time (unique "
                "ID, but unmatched with component) SPDX IDs: %s \n ",
                "\n".join(self.parent.unmatched_with_unique_id),
            )

    def _log_duplicate_identifiers(self) -> None:
        """
        Log statistics about duplicate identifiers.
        Includes checksums, verification codes, and purls.
        """
        total_duplicates = (
            len(self.duplicate_checksums)
            + len(self.duplicate_verification_codes)
            + len(self.duplicate_purls)
        )
        if total_duplicates == 0:
            return

        LOGGER.debug("--- Duplicate Identifiers Detected ---")
        LOGGER.debug(
            "Duplicate checksums: %d",
            len(self.duplicate_checksums),
        )
        LOGGER.debug(
            "Duplicate package verification codes: %d",
            len(self.duplicate_verification_codes),
        )
        LOGGER.debug(
            "Duplicate purls: %d",
            len(self.duplicate_purls),
        )

        if self.duplicate_checksums:
            for checksum, matches in self.duplicate_checksums.items():
                spdx_pairs = "\n    ".join(
                    [f"(parent: {p} | component: {c})" for p, c in matches]
                )
                LOGGER.debug(
                    "  Duplicate checksum: %s | matched %d pairs:\n    %s",
                    checksum,
                    len(matches),
                    spdx_pairs,
                )

        if self.duplicate_verification_codes:
            for code, matches in self.duplicate_verification_codes.items():
                spdx_pairs = "\n    ".join(
                    [f"(parent: {p} | component: {c})" for p, c in matches]
                )
                LOGGER.debug(
                    "  Duplicate verification_code: %s | matched %d pairs:\n    %s",
                    code,
                    len(matches),
                    spdx_pairs,
                )

        if self.duplicate_purls:
            for purl, matches in self.duplicate_purls.items():
                spdx_pairs = "\n    ".join(
                    [f"(parent: {p} | component: {c})" for p, c in matches]
                )
                LOGGER.debug(
                    "  Duplicate purl: %s | matched %d pairs:\n    %s",
                    purl,
                    len(matches),
                    spdx_pairs,
                )

    def log_summary_debug(self) -> None:
        """Log a comprehensive summary of matching statistics."""
        # Log structured JSON for Splunk/centralized logging
        self.log_summary_structured()

        # Log all statistics sections for debug mode
        self._log_package_counts()
        self._log_match_method_breakdown()
        self._log_match_producer_breakdown()
        self._log_unmatched_packages()
        self._log_duplicate_identifiers()
