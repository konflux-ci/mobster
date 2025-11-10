"""Tests for contextual SBOM logging utilities."""

import json

import pytest
from _pytest.logging import LogCaptureFixture
from spdx_tools.spdx.model.package import Package
from spdx_tools.spdx.model.relationship import Relationship, RelationshipType
from spdx_tools.spdx.model.spdx_no_assertion import SpdxNoAssertion

from mobster.cmd.generate.oci_image.contextual_sbom.constants import (
    MatchBy,
    PackageInfo,
    PackageMatchInfo,
    PackageProducer,
)
from mobster.cmd.generate.oci_image.contextual_sbom.logging import (
    DuplicateTracker,
    MatchingStatistics,
    PackageStats,
)


def test_unmatched_packages() -> None:
    """Test that unmatched_packages property returns correct set."""
    stats = PackageStats()
    stats.all_packages = {"pkg1", "pkg2", "pkg3"}
    stats.matched_packages = {"pkg1"}

    assert stats.unmatched_packages == {"pkg2", "pkg3"}


def test_unmatched_with_unique_id() -> None:
    """Test that unmatched_with_unique_id excludes packages without unique ID."""
    stats = PackageStats()
    stats.all_packages = {"pkg1", "pkg2", "pkg3", "pkg4"}
    stats.matched_packages = {"pkg1"}
    stats.packages_without_unique_id = {"pkg3"}

    # pkg2 and pkg3 are unmatched, but pkg3 has no unique ID
    assert stats.unmatched_with_unique_id == {"pkg2", "pkg4"}


def test_duplicate_checksums_property() -> None:
    """Test that duplicate_checksums returns only duplicates."""
    tracker = DuplicateTracker()
    tracker.checksums["checksum1"].add(("parent1", "component1"))
    tracker.checksums["checksum1"].add(("parent2", "component2"))
    tracker.checksums["checksum2"].add(("parent3", "component3"))
    tracker.verification_codes["vc1"].add(("parent4", "component4"))
    tracker.verification_codes["vc1"].add(("parent5", "component5"))
    tracker.verification_codes["vc2"].add(("parent6", "component6"))
    tracker.purls["pkg:npm/pkg@1.0.0"].add(("parent7", "component7"))
    tracker.purls["pkg:npm/pkg@1.0.0"].add(("parent8", "component8"))
    tracker.purls["pkg:npm/other@2.0.0"].add(("parent9", "component9"))

    duplicates_ch = tracker.duplicate_checksums
    duplicates_vc = tracker.duplicate_verification_codes
    duplicates_purl = tracker.duplicate_purls

    assert len(duplicates_ch) == 1
    assert "checksum1" in duplicates_ch
    assert len(duplicates_ch["checksum1"]) == 2

    assert len(duplicates_vc) == 1
    assert "vc1" in duplicates_vc

    assert len(duplicates_purl) == 1
    assert "pkg:npm/pkg@1.0.0" in duplicates_purl


def test_no_duplicates() -> None:
    """Test that properties return empty dict when no duplicates exist."""
    tracker = DuplicateTracker()
    tracker.checksums["checksum1"].add(("parent1", "component1"))
    tracker.checksums["checksum2"].add(("parent2", "component2"))
    tracker.verification_codes["vc1"].add(("parent4", "component4"))
    tracker.verification_codes["vc2"].add(("parent5", "component5"))
    tracker.purls["pkg:npm/pkg@1.0.0"].add(("parent6", "component6"))
    tracker.purls["pkg:npm/other@2.0.0"].add(("parent7", "component7"))

    assert tracker.duplicate_checksums == {}
    assert tracker.duplicate_verification_codes == {}
    assert tracker.duplicate_purls == {}


@pytest.mark.parametrize(
    ["package_type", "spdx_refs", "record_method", "stats_attr"],
    [
        pytest.param(
            "component",
            ["SPDXRef-c1", "SPDXRef-c2"],
            "record_component_packages",
            "component",
            id="component_packages",
        ),
        pytest.param(
            "parent",
            ["SPDXRef-p1", "SPDXRef-p2"],
            "record_parent_packages",
            "parent",
            id="parent_packages",
        ),
    ],
)
def test_record_packages(
    package_type: str,
    spdx_refs: list[str],
    record_method: str,
    stats_attr: str,
) -> None:
    """Test recording component and parent packages."""
    stats = MatchingStatistics()
    packages = [
        (
            Package(spdx_ref, f"pkg{i + 1}", SpdxNoAssertion()),
            Relationship("SPDXRef-root", RelationshipType.CONTAINS, spdx_ref),
        )
        for i, spdx_ref in enumerate(spdx_refs)
    ]

    getattr(stats, record_method)(packages)

    assert getattr(stats, stats_attr).all_packages == set(spdx_refs)


def test_record_parent_package_match() -> None:
    """Test recording parent package match."""
    stats = MatchingStatistics()

    stats.record_parent_package_match("SPDXRef-p1")
    stats.record_parent_package_match("SPDXRef-p2")

    assert stats.parent.matched_packages == {"SPDXRef-p1", "SPDXRef-p2"}


@pytest.mark.parametrize(
    ["match_by", "parent_producer", "component_producer", "identifier_value"],
    [
        pytest.param(
            MatchBy.CHECKSUM,
            PackageProducer.SYFT,
            PackageProducer.SYFT,
            "SHA256:abc123",
            id="checksum-syft_to_syft",
        ),
        pytest.param(
            MatchBy.CHECKSUM,
            PackageProducer.HERMETO,
            PackageProducer.SYFT,
            "SHA256:abc123",
            id="checksum-hermeto_to_syft",
        ),
        pytest.param(
            MatchBy.PACKAGE_VERIFICATION_CODE,
            PackageProducer.SYFT,
            PackageProducer.SYFT,
            "vc123",
            id="verification_code-syft_to_syft",
        ),
        pytest.param(
            MatchBy.PACKAGE_VERIFICATION_CODE,
            PackageProducer.HERMETO,
            PackageProducer.SYFT,
            "vc123",
            id="verification_code-hermeto_to_syft",
        ),
        pytest.param(
            MatchBy.PURL,
            PackageProducer.SYFT,
            PackageProducer.SYFT,
            "pkg:npm/package@1.0.0",
            id="purl-syft_to_syft",
        ),
        pytest.param(
            MatchBy.PURL,
            PackageProducer.HERMETO,
            PackageProducer.SYFT,
            "pkg:npm/package@1.0.0",
            id="purl-hermeto_to_syft",
        ),
    ],
)
def test_record_component_package_match(
    match_by: MatchBy,
    parent_producer: PackageProducer,
    component_producer: PackageProducer,
    identifier_value: str,
) -> None:
    """
    Test recording component package match by
    different identifiers and producer combinations.
    """
    stats = MatchingStatistics()
    match_info = PackageMatchInfo(
        matched=True,
        match_by=match_by,
        parent_info=PackageInfo("SPDXRef-p1", parent_producer),
        component_info=PackageInfo("SPDXRef-c1", component_producer),
        identifier_value=identifier_value,
    )

    stats.record_component_package_match(match_info)

    # Component package should be marked as matched
    assert stats.component.matched_packages == {"SPDXRef-c1"}

    # Check that appropriate match method counter was incremented
    if match_by == MatchBy.CHECKSUM:
        assert stats.match_methods.by_checksum == 1
        assert stats.match_methods.by_verification_code == 0
        assert stats.match_methods.by_purl == 0
    elif match_by == MatchBy.PACKAGE_VERIFICATION_CODE:
        assert stats.match_methods.by_verification_code == 1
        assert stats.match_methods.by_checksum == 0
        assert stats.match_methods.by_purl == 0
        assert identifier_value in stats.duplicates.verification_codes
    elif match_by == MatchBy.PURL:
        assert stats.match_methods.by_purl == 1
        assert stats.match_methods.by_checksum == 0
        assert stats.match_methods.by_verification_code == 0

    # Check producer match tracking
    if (
        parent_producer == PackageProducer.SYFT
        and component_producer == PackageProducer.SYFT
    ):
        assert stats.producer_matches.syft_to_syft == 1
    elif (
        parent_producer == PackageProducer.HERMETO
        and component_producer == PackageProducer.SYFT
    ):
        assert stats.producer_matches.hermeto_to_syft == 1


@pytest.mark.parametrize(
    ["parent_producer", "component_producer", "expected_match_attr"],
    [
        pytest.param(
            PackageProducer.SYFT,
            PackageProducer.HERMETO,
            "syft_to_hermeto",
            id="syft_to_hermeto",
        ),
        pytest.param(
            PackageProducer.HERMETO,
            PackageProducer.HERMETO,
            "hermeto_to_hermeto",
            id="hermeto_to_hermeto",
        ),
    ],
)
def test_record_component_package_match_unexpected_producers(
    parent_producer: PackageProducer,
    component_producer: PackageProducer,
    expected_match_attr: str,
) -> None:
    """Test recording unexpected producer combinations."""
    stats = MatchingStatistics()
    match_info = PackageMatchInfo(
        matched=True,
        match_by=MatchBy.CHECKSUM,
        parent_info=PackageInfo("SPDXRef-p1", parent_producer),
        component_info=PackageInfo("SPDXRef-c1", component_producer),
        identifier_value="checksum",
    )

    stats.record_component_package_match(match_info)

    # This should be tracked even though it's unexpected
    assert getattr(stats.producer_matches, expected_match_attr) == 1


def test_duplicate_identifier_tracking() -> None:
    """Test that duplicate identifiers are tracked correctly."""
    stats = MatchingStatistics()

    # Record two matches with same checksum
    match_info1 = PackageMatchInfo(
        matched=True,
        match_by=MatchBy.CHECKSUM,
        parent_info=PackageInfo("SPDXRef-p1", PackageProducer.SYFT),
        component_info=PackageInfo("SPDXRef-c1", PackageProducer.SYFT),
        identifier_value="SHA256:duplicate",
    )
    match_info2 = PackageMatchInfo(
        matched=True,
        match_by=MatchBy.CHECKSUM,
        parent_info=PackageInfo("SPDXRef-p2", PackageProducer.SYFT),
        component_info=PackageInfo("SPDXRef-c2", PackageProducer.SYFT),
        identifier_value="SHA256:duplicate",
    )
    match_info3 = PackageMatchInfo(
        matched=True,
        match_by=MatchBy.CHECKSUM,
        parent_info=PackageInfo("SPDXRef-p2", PackageProducer.SYFT),
        component_info=PackageInfo("SPDXRef-c2", PackageProducer.SYFT),
        identifier_value="SHA256:unique",
    )

    stats.record_component_package_match(match_info1)
    stats.record_component_package_match(match_info2)
    stats.record_component_package_match(match_info3)

    assert len(stats.duplicates.duplicate_checksums) == 1
    assert "SHA256:duplicate" in stats.duplicates.duplicate_checksums
    assert "SHA256:unique" not in stats.duplicates.duplicate_checksums
    assert len(stats.duplicates.duplicate_checksums["SHA256:duplicate"]) == 2


def test_log_summary_structured(caplog: LogCaptureFixture) -> None:
    """Test that structured logging outputs valid JSON."""
    stats = MatchingStatistics()

    # Setup some test data
    stats.component.all_packages = {"c1", "c2", "c3"}
    stats.component.matched_packages = {"c1"}
    stats.parent.all_packages = {"p1", "p2"}
    stats.parent.matched_packages = {"p1"}
    stats.match_methods.by_checksum = 1

    with caplog.at_level("INFO"):
        stats.log_summary_structured()

    assert len(caplog.records) == 1
    log_message = caplog.records[0].message

    data = json.loads(log_message)
    assert data["event_type"] == "contextual_sbom_matching_statistics"
    assert data["component_packages"]["total"] == 3
    assert data["component_packages"]["matched"] == 1
    assert data["parent_packages"]["total"] == 2
    assert data["parent_packages"]["matched"] == 1
    assert data["match_methods"]["by_checksum"] == 1


def test_log_summary_debug_with_matches(caplog: LogCaptureFixture) -> None:
    """Test debug logging with matches."""
    stats = MatchingStatistics()

    stats.component.all_packages = {"c1", "c2"}
    stats.parent.all_packages = {"p1", "p2"}
    stats.component.matched_packages = {"c1"}
    stats.parent.matched_packages = {"p1"}
    stats.match_methods.by_checksum = 1

    with caplog.at_level("DEBUG"):
        stats.log_summary_debug()

    # Check that debug logs contain expected content with specific values
    log_text = "\n".join(record.message for record in caplog.records)
    assert "Package Matching Statistics" in log_text
    assert "Total component packages: 2" in log_text
    assert "Component packages matched: 1" in log_text
    assert "Total parent packages: 2" in log_text
    assert "Parent packages matched: 1" in log_text
    assert "Matched by checksum: 1" in log_text


def test_log_summary_debug_with_no_matches(caplog: LogCaptureFixture) -> None:
    """Test debug logging when no matches occurred."""
    stats = MatchingStatistics()

    stats.component.all_packages = {"c1", "c2"}
    stats.parent.all_packages = {"p1", "p2"}

    with caplog.at_level("DEBUG"):
        stats.log_summary_debug()

    log_text = "\n".join(record.message for record in caplog.records)
    assert "Package Matching Statistics" in log_text
    assert "No matches found" in log_text
    assert "Total component packages: 2" in log_text
    assert "Total parent packages: 2" in log_text


def test_log_summary_debug_with_duplicates(caplog: LogCaptureFixture) -> None:
    """Test debug logging with duplicate identifiers."""
    stats = MatchingStatistics()

    # Add duplicate checksum
    stats.duplicates.checksums["SHA256:dup"].add(("p1", "c1"))
    stats.duplicates.checksums["SHA256:dup"].add(("p2", "c2"))

    stats.component.all_packages = {"c1", "c2"}
    stats.parent.all_packages = {"p1", "p2"}
    stats.component.matched_packages = {"c1", "c2"}
    stats.parent.matched_packages = {"p1", "p2"}
    stats.match_methods.by_checksum = 2

    with caplog.at_level("DEBUG"):
        stats.log_summary_debug()

    log_text = "\n".join(record.message for record in caplog.records)
    assert "Package Matching Statistics" in log_text
    assert "Duplicate Identifiers Detected" in log_text
    assert "Duplicate checksum: SHA256:dup" in log_text
    assert "Total component packages: 2" in log_text
    assert "Component packages matched: 2" in log_text


def test_log_summary_debug_with_unexpected_producer_matches(
    caplog: LogCaptureFixture,
) -> None:
    """Test that unexpected producer matches are logged as warnings."""
    stats = MatchingStatistics()

    stats.component.all_packages = {"c1"}
    stats.parent.all_packages = {"p1"}
    stats.component.matched_packages = {"c1"}
    stats.match_methods.by_checksum = 1
    stats.producer_matches.syft_to_hermeto = 1  # Unexpected!

    with caplog.at_level("DEBUG"):
        stats.log_summary_debug()

    # Check for warning about unexpected match with specific producer combination
    warning_text = "\n".join(
        record.message for record in caplog.records if record.levelname == "WARNING"
    )
    assert warning_text, "Expected at least one WARNING message"
    assert "SYFT (parent) -> HERMETO (component): 1" in warning_text


def test_prepare_duplicate_identifier_data() -> None:
    """Test that duplicate identifier data is prepared correctly."""
    stats = MatchingStatistics()

    # Add duplicates
    stats.duplicates.checksums["cksum1"].add(("p1", "c1"))
    stats.duplicates.checksums["cksum1"].add(("p2", "c2"))
    stats.duplicates.verification_codes["vc1"].add(("p3", "c3"))
    stats.duplicates.verification_codes["vc1"].add(("p4", "c4"))
    stats.duplicates.purls["purl1"].add(("p5", "c5"))
    stats.duplicates.purls["purl1"].add(("p6", "c6"))

    checksums, vcs, purls = stats._prepare_duplicate_identifier_data()

    assert len(checksums) == 1
    assert checksums[0]["identifier"] == "cksum1"
    assert checksums[0]["match_count"] == 2

    assert len(vcs) == 1
    assert vcs[0]["identifier"] == "vc1"

    assert len(purls) == 1
    assert purls[0]["identifier"] == "purl1"
