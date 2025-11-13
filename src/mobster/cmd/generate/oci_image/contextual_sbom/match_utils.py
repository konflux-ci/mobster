"""Utilities for matching packages between parent and component SBOMs."""

import logging
from collections.abc import Generator

from packageurl import PackageURL
from spdx_tools.spdx.model.actor import ActorType
from spdx_tools.spdx.model.annotation import Annotation
from spdx_tools.spdx.model.checksum import Checksum
from spdx_tools.spdx.model.document import Document
from spdx_tools.spdx.model.package import Package
from spdx_tools.spdx.model.relationship import Relationship

from mobster.cmd.generate.oci_image.contextual_sbom.constants import (
    HERMETO_ANNOTATION_COMMENTS,
    MatchBy,
    PackageInfo,
    PackageMatchInfo,
    PackageProducer,
)
from mobster.cmd.generate.oci_image.contextual_sbom.logging import MatchingStatistics
from mobster.cmd.generate.oci_image.spdx_utils import (
    get_annotations_by_spdx_id,
    get_package_purl,
)

LOGGER = logging.getLogger(__name__)


# pylint: disable=too-many-instance-attributes
class ComponentRelationshipResolver:
    """
    Resolves and modifies component SBOM relationships based on parent package
    matches.

    This class provides a multi-index structure for fast component package
    lookups and handles the complete workflow of:
    1. Indexing component packages by checksums, verification codes, and PURLs
    2. Finding matching packages between parent and component SBOMs
    3. Resolving and modifying component relationships to point to
       parent/grandparent packages
    4. Tracking already matched packages to avoid duplicate matching
    """

    def __init__(
        self,
        component_packages: list[tuple[Package, Relationship]],
        parent_sbom_doc: Document,
        component_sbom_doc: Document,
        stats: MatchingStatistics,
    ):
        """
        Initialize and build all indexes.

        Args:
            component_packages: List of (component Package, component
                Relationship) tuples to index
            parent_sbom_doc: Parent SBOM document
            component_sbom_doc: Component SBOM document
            stats: Statistics tracker for recording packages without
                unique IDs
        """
        self.checksum_index: dict[str, list[tuple[Package, Relationship]]] = {}
        self.verification_code_index: dict[str, list[tuple[Package, Relationship]]] = {}
        self.purl_index: dict[str, list[tuple[Package, Relationship]]] = {}
        self.component_packages = component_packages
        self.parent_sbom_doc = parent_sbom_doc
        self.component_sbom_doc = component_sbom_doc
        self.matched_packages: set[str] = set()
        self.stats = stats

        self._build_indexes()

    def _build_indexes(self) -> None:
        """
        Build indexes for all identifiers. Index considers possibility
        of multiple packages under same unique id in component SBOM
        (multiple packages with same identifier).

        Also records component packages without any unique identifier.
        """
        for pkg, rel in self.component_packages:
            has_unique_id = False

            if pkg.checksums:
                checksum_key = self._create_checksum_key(pkg.checksums)
                self.checksum_index.setdefault(checksum_key, []).append((pkg, rel))
                has_unique_id = True

            if pkg.verification_code and pkg.verification_code.value:
                vc_key = pkg.verification_code.value
                self.verification_code_index.setdefault(vc_key, []).append((pkg, rel))
                has_unique_id = True

            purl = get_package_purl(pkg)
            # Packages with missing or malformed purl, or
            # purl without version are not indexed
            if purl:
                try:
                    purl_obj = PackageURL.from_string(purl)
                    if purl_obj.version:
                        purl_key = self._create_purl_key(purl_obj)
                        self.purl_index.setdefault(purl_key, []).append((pkg, rel))
                        has_unique_id = True
                except ValueError:
                    LOGGER.warning(
                        "Could not parse component's SBOM package URL %s", purl
                    )

            # Record component packages without any unique identifier
            if not has_unique_id:
                self.stats.record_component_package_without_unique_id(pkg.spdx_id)

    @staticmethod
    def _create_checksum_key(checksums: list[Checksum]) -> str:
        """Create unique key from checksums list."""
        checksum_strs = [f"{c.algorithm}:{c.value}" for c in checksums]
        return "|".join(sorted(checksum_strs))

    @staticmethod
    def _create_purl_key(purl: PackageURL) -> str:
        """Create unique key from PURL object."""
        return f"{purl.type}/{purl.namespace or ''}/{purl.name}@{purl.version}"

    def find_candidates(
        self, parent_package: Package
    ) -> list[tuple[Package, Relationship]]:
        """
        Find candidate component packages that may match the given parent package
        using prioritized identifier-based lookup strategy.

        Priority: checksums -> verification_code -> purl

        Also records parent packages without any unique identifier.

        Args:
            parent_package: Parent package to find matching candidates for
                in the indexed component SBOM

        Returns:
            List of candidate (Package, Relationship) tuples
        """
        if parent_package.checksums:
            checksum_key = self._create_checksum_key(parent_package.checksums)
            if checksum_key in self.checksum_index:
                return self.checksum_index[checksum_key]

        if parent_package.verification_code and parent_package.verification_code.value:
            vc_key = parent_package.verification_code.value
            if vc_key in self.verification_code_index:
                return self.verification_code_index[vc_key]

        purl = get_package_purl(parent_package)
        has_valid_purl = False
        # Parent packages with absent checksum, pkg verification code,
        # missing or malformed purl, or purl without version are not
        # eligible for matching against component packages.
        # The resolver cannot match such parent packages with component packages.
        if purl:
            try:
                purl_obj = PackageURL.from_string(purl)
                if purl_obj.version:
                    has_valid_purl = True
                    purl_key = self._create_purl_key(purl_obj)
                    if purl_key in self.purl_index:
                        return self.purl_index[purl_key]
            except ValueError:
                LOGGER.warning("Could not parse parent's SBOM package URL %s", purl)

        # Record parent packages without any unique identifier
        # (no checksums, no verification_code, and no valid purl with version)
        if (
            not parent_package.checksums
            and not parent_package.verification_code
            and not has_valid_purl
        ):
            self.stats.record_parent_package_without_unique_id(parent_package.spdx_id)

        return []

    def mark_as_matched(self, spdx_id: str) -> None:
        """Mark component package as matched."""
        self.matched_packages.add(spdx_id)

    def is_matched(self, spdx_id: str) -> bool:
        """Check if component package was already matched."""
        return spdx_id in self.matched_packages

    def get_match(
        self,
        parent_package: Package,
    ) -> Generator[tuple[Package, Relationship, PackageMatchInfo], None, None]:
        """
        Find matching component packages for given parent package.

        This method encapsulates the matching logic by:
        1. Finding candidates using the index
        2. Filtering out already matched packages
        3. Validating the match using package_matched()
        4. Yielding all valid matches

        Args:
            parent_package: Parent package to find match for

        Yields:
            Tuple of (component Package, component Relationship,
                PackageMatchInfo) for each match
        """
        candidates = self.find_candidates(parent_package)

        if not candidates:
            return

        self.stats.record_parent_package_match(parent_package.spdx_id)

        for component_package, component_relationship in candidates:
            # Skip if already matched (avoid matching duplicates multiple times)
            if self.is_matched(component_package.spdx_id):
                continue

            match_info = package_matched(
                parent_package=parent_package,
                component_sbom_doc=self.component_sbom_doc,
                component_package=component_package,
                parent_sbom_doc=self.parent_sbom_doc,
            )

            if match_info.matched:
                yield component_package, component_relationship, match_info

    def resolve_component_relationships(
        self,
        parent_packages: list[tuple[Package, Relationship]],
        parent_spdx_id_from_component: str,
        parent_root_packages: list[str],
    ) -> None:
        """
        Resolve and modify component relationships based on parent package matches.

        For each parent package that has a matching component package:
        1. Find the match using get_match()
        2. Modify the component relationship to point to parent or grandparent
        3. Mark the component package as matched
        """
        for parent_package, parent_relationship in parent_packages:
            for component_package, component_relationship, match_info in self.get_match(
                parent_package
            ):
                if match_info:
                    self._modify_relationship_in_component(
                        component_relationship,
                        parent_relationship,
                        parent_spdx_id_from_component,
                        parent_root_packages,
                    )
                    self.mark_as_matched(component_package.spdx_id)
                    # Record component package matched against parent
                    self.stats.record_component_package_match(match_info)

    def supply_ancestors(
        self,
        descendant_of_items_from_used_parent: list[
            tuple[Package, Relationship, Annotation]
        ],
    ) -> None:
        """
        Supply all DESCENDANT_OF relationships (and related packages and annotations)
        from parent SBOM to component SBOM.

        This method adds ancestor packages (grandparents of the component) to the
        component SBOM. It modifies annotation comments from "is_base_image" to
        "is_ancestor_image" to ensure proper functioning when this component is used
        as a base image for another component.

        Note: This method expects that component package relationships already point
        to the correct parent/grandparent packages (modified by
        resolve_component_relationships).

        Args:
            descendant_of_items_from_used_parent: All DESCENDANT_OF relationships,
                associated packages and their annotations from parent SBOM
        """
        for pkg, rel, annot in descendant_of_items_from_used_parent:
            self.component_sbom_doc.relationships.append(rel)
            self.component_sbom_doc.packages.append(pkg)
            if annot:
                if annot.annotation_comment:
                    annot.annotation_comment = annot.annotation_comment.replace(
                        "is_base_image", "is_ancestor_image"
                    )
                self.component_sbom_doc.annotations.append(annot)

    @staticmethod
    def _modify_relationship_in_component(
        component_relationship: Relationship,
        parent_relationship: Relationship,
        parent_spdx_id_from_component: str,
        parent_root_packages: list[str],
    ) -> None:
        """
        Function modifies relationship in component SBOM.
        If package from parent image content was found in
        component content by package_matched function,
        relationship of the package in component content
        is swapped to parent or grandparents
        (if parent is contextualized)

        Args:
            component_relationship: Component relationship to-be-modified.

            parent_relationship: Parent relationship.
                A) If parent has been contextualized there are two options of the
                component's relationship modification after packages match,
                depending on the information in used parent SBOM:
                1. component CONTAINS package -> grandparent CONTAINS package
                2. component CONTAINS package ->
                parent (parent_spdx_id_from_component) CONTAINS package
                B) If downloaded used parent is not contextualized there is only
                one option for the component's relationship modification:
                component CONTAINS package ->
                1. parent (parent_spdx_id_from_component) CONTAINS package

            parent_spdx_id_from_component: The name of the used parent that
                is determined at component SBOM generation.

            parent_root_packages: This decides if CONTAINS relationship is copied
                (grandparent) or modified (every package in non-contextualized parent
                OR every other package in contextualized parent that is not bound to
                its parent (component's grandparent)).

        Returns: None. Component SBOM is modified in-place.
        """
        # Contextualized parent: matched package is bound to parent itself
        # (not to any of the grandparents),
        # and when we want to point relationship from component to parent
        # we need to use parent name from generated component
        # Non-contextualized parent: all the packages are bound to the
        # parent, we need to use parent name from generated component
        if parent_relationship.spdx_element_id in parent_root_packages:
            component_relationship.spdx_element_id = parent_spdx_id_from_component

        # Contextualized parent: matched package is not bound to the root package(s) but
        # bound to some grandparent of the parent by previous contextualization - we
        # need to preserve this relationship
        # Non-contextualized parent or parent without another parent (no grandparent for
        # component): should never reach this branch, because all
        # the packages will always be bound to parent itself - all relationships will
        # refer to root packages, no grandparents are present by contextualization or
        # in reality
        else:
            component_relationship.spdx_element_id = parent_relationship.spdx_element_id


def validate_and_compare_purls(
    parent_purl: str | None,
    component_purl: str | None,
) -> bool:
    """
    Validate that the purls contains the required fields (type, name and version). Then
    compare the purls based on the required fields and the namespace.

    Args:
        parent_purl: The parent purl to validate and compare with the component purl.
        component_purl: The component purl to validate and compare with the parent purl.

    Returns:
        True if the purls match after validation, False if either purl is invalid, or
        the validated purls don't match.
    """
    if not parent_purl or not component_purl:
        return False

    # ValueError is thrown if a purl is None, or missing type or name.
    try:
        parent_purl_obj = PackageURL.from_string(parent_purl)
        component_purl_obj = PackageURL.from_string(component_purl)
    except ValueError:
        return False

    if not parent_purl_obj.version or not component_purl_obj.version:
        return False

    return (
        parent_purl_obj.type == component_purl_obj.type
        and parent_purl_obj.name == component_purl_obj.name
        and parent_purl_obj.version == component_purl_obj.version
        and parent_purl_obj.namespace == component_purl_obj.namespace
    )


def format_checksums_identifier(checksums: list[Checksum]) -> list[str]:
    """
    Format checksums as sorted, pipe-separated identifier string.
    The Checksum objects are not hashable and do not have to_string()
    method, and we have to convert them to strings in a custom way

    Args:
        checksums: List of Checksum objects.

    Returns:
        Sorted, pipe-separated string of checksums.
    """
    return [f"{checksum.algorithm}:{checksum.value}" for checksum in checksums]


def checksums_match(
    parent_checksums: list[Checksum], component_checksums: list[Checksum]
) -> bool:
    """
    Compare two lists of Package Checksum objects. All checksums must match.

    Args:
        parent_checksums: List of Checksum objects from parent package.
        component_checksums: List of Checksum objects from component package.

    Returns:
        True if all the checksums match, False otherwise.
    """
    parent_checksums_str = format_checksums_identifier(parent_checksums)
    component_checksums_str = format_checksums_identifier(component_checksums)
    return set(parent_checksums_str) == set(component_checksums_str)


def generated_by_hermeto(annotations: list[Annotation]) -> bool:
    """
    Will determine if the package was generated by hermeto/cachi2 based on its
    annotation.

    Args:
        annotations: list of annotations of the package.

    Returns:
        True if the annotation indicates that the package was generated by
        hermeto/cachi2, False otherwise.
    """
    if not annotations:
        return False

    return any(
        annot.annotator.actor_type == ActorType.TOOL
        and annot.annotation_comment in HERMETO_ANNOTATION_COMMENTS
        for annot in annotations
    )


def package_matched(
    parent_sbom_doc: Document,
    component_sbom_doc: Document,
    parent_package: Package,
    component_package: Package,
) -> PackageMatchInfo:
    """
    Determine if a component package matches a parent package for SBOM
    contextualization. The matching strategy depends on the tool that generated the
    packages:

    **Hermeto-to-Syft matching:**
    - Parent packages generated by Hermeto are compared to component packages generated
      by Syft.
    - Matching is done by comparing validated purls (type, name, version, and optionally
      namespace). If either purl fails validation, the packages are considered not
      matched.

    **Syft-to-Syft matching:**
    - Both parent and component packages are generated by Syft.
    - Uses prioritized matching with identifiers checked from most to least specific:
      1. Package checksums (all items in the lists must match)
      2. Package verification codes
      3. Validated purls (type, name, version, and optionally namespace). If either purl
         fails validation, the packages are considered not matched.

    There is no Hermeto-to-Hermeto matching because Hermeto produces component-only
    content that was added during build. Therefore, a Hermeto-generated component
    package should never be matched with any parent content. On the other hand, Syft
    scans the entire image including parent content, so Syft-generated components can
    potentially be matched with parent packages generated by either tool.

    Args:
        parent_sbom_doc: The parent SBOM document.
        component_sbom_doc: The component SBOM document.
        parent_package: The parent package.
        component_package: The component package.

    Returns:
        PackageMatchInfo containing match result and metadata about both packages
    """
    parent_purl = get_package_purl(parent_package)
    component_purl = get_package_purl(component_package)

    parent_producer = (
        PackageProducer.HERMETO
        if generated_by_hermeto(
            get_annotations_by_spdx_id(parent_sbom_doc, parent_package.spdx_id)
        )
        else PackageProducer.SYFT
    )

    component_producer = (
        PackageProducer.HERMETO
        if generated_by_hermeto(
            get_annotations_by_spdx_id(component_sbom_doc, component_package.spdx_id)
        )
        else PackageProducer.SYFT
    )

    # Create package info objects
    parent_info = PackageInfo(parent_package.spdx_id, parent_producer)
    component_info = PackageInfo(component_package.spdx_id, component_producer)

    # Hermeto-to-syft matching
    if parent_producer == PackageProducer.HERMETO:
        matched = validate_and_compare_purls(parent_purl, component_purl)
        return PackageMatchInfo(
            matched=matched,
            match_by=MatchBy.PURL,
            parent_info=parent_info,
            component_info=component_info,
            identifier_value=parent_purl if matched else None,
        )

    # Syft-to-syft matching: Check identifiers from most specific to the least specific
    if parent_package.checksums and component_package.checksums:
        matched = checksums_match(parent_package.checksums, component_package.checksums)
        identifier_value = (
            "|".join(sorted(format_checksums_identifier(parent_package.checksums)))
            if matched
            else None
        )
        return PackageMatchInfo(
            matched=matched,
            match_by=MatchBy.CHECKSUM,
            parent_info=parent_info,
            component_info=component_info,
            identifier_value=identifier_value,
        )

    if (
        parent_package.verification_code
        and parent_package.verification_code.value
        and component_package.verification_code
        and component_package.verification_code.value
    ):
        matched = (
            parent_package.verification_code == component_package.verification_code
        )
        return PackageMatchInfo(
            matched=matched,
            match_by=MatchBy.PACKAGE_VERIFICATION_CODE,
            parent_info=parent_info,
            component_info=component_info,
            identifier_value=parent_package.verification_code.value
            if matched
            else None,
        )

    matched = validate_and_compare_purls(parent_purl, component_purl)
    return PackageMatchInfo(
        matched=matched,
        match_by=MatchBy.PURL,
        parent_info=parent_info,
        component_info=component_info,
        identifier_value=parent_purl if matched else None,
    )
