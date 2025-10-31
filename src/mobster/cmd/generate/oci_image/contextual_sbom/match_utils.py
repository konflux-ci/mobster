"""Utilities for matching packages between parent and component SBOMs."""

from packageurl import PackageURL
from spdx_tools.spdx.model.actor import ActorType
from spdx_tools.spdx.model.annotation import Annotation
from spdx_tools.spdx.model.checksum import Checksum
from spdx_tools.spdx.model.document import Document
from spdx_tools.spdx.model.package import Package
from spdx_tools.spdx.model.relationship import Relationship, RelationshipType

from mobster.cmd.generate.oci_image.constants import HERMETO_ANNOTATION_COMMENTS
from mobster.cmd.generate.oci_image.spdx_utils import (
    get_annotations_by_spdx_id,
    get_package_purl,
)


class ComponentPackageIndex:
    """
    Multi-index structure for fast component package lookups.

    Builds indexes based on checksums, verification codes, and PURLs
    """

    def __init__(self, component_packages: list[tuple[Package, Relationship]]):
        """
        Initialize and build all indexes.

        Args:
            component_packages: List of (Package, Relationship) tuples to index
        """
        self.checksum_index: dict[str, list[tuple[Package, Relationship]]] = {}
        self.verification_code_index: dict[str, list[tuple[Package, Relationship]]] = {}
        self.purl_index: dict[str, list[tuple[Package, Relationship]]] = {}
        self.component_packages = component_packages
        self.matched_packages: set[str] = set()

        self._build_indexes()

    def _build_indexes(self) -> None:
        """
        Build indexes for all identifiers. Index considers possibility
        of multiple packages under same unique id in component SBOM
        (multiple packages with same identifier).
        """
        for pkg, rel in self.component_packages:
            if pkg.checksums:
                checksum_key = self._create_checksum_key(pkg.checksums)
                self.checksum_index.setdefault(checksum_key, []).append((pkg, rel))

            if pkg.verification_code:
                vc_key = pkg.verification_code.value
                self.verification_code_index.setdefault(vc_key, []).append((pkg, rel))

            purl = get_package_purl(pkg)
            # Packages with missing or malformed purl, or
            # purl without version are not indexed
            if purl:
                try:
                    purl_obj = PackageURL.from_string(purl)
                    if purl_obj.version:
                        purl_key = self._create_purl_key(purl_obj)
                        self.purl_index.setdefault(purl_key, []).append((pkg, rel))
                except ValueError:
                    pass

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
        Find candidate matches in component index for parent package
        using prioritized strategy.

        Priority: checksums -> verification_code -> purl

        Args:
            parent_package: Parent package to find candidates for
                in component package index

        Returns:
            List of candidate (Package, Relationship) tuples
        """
        if parent_package.checksums:
            checksum_key = self._create_checksum_key(parent_package.checksums)
            if checksum_key in self.checksum_index:
                return self.checksum_index[checksum_key]

        if parent_package.verification_code:
            vc_key = parent_package.verification_code.value
            if vc_key in self.verification_code_index:
                return self.verification_code_index[vc_key]

        purl = get_package_purl(parent_package)
        # Parent packages with absent checksum, pkg verification code,
        # missing or malformed purl, or purl without version are not
        # eligible to be used for searching in component index
        # We cannot match such parent packages with component
        if purl:
            try:
                purl_obj = PackageURL.from_string(purl)
                if purl_obj.version:
                    purl_key = self._create_purl_key(purl_obj)
                    if purl_key in self.purl_index:
                        return self.purl_index[purl_key]
            except ValueError:
                return []
        return []

    def mark_as_matched(self, spdx_id: str) -> None:
        """Mark component package as matched."""
        self.matched_packages.add(spdx_id)

    def is_matched(self, spdx_id: str) -> bool:
        """Check if component package was already matched."""
        return spdx_id in self.matched_packages


def validate_and_compare_purls(
    parent_purl: str | None,
    component_purl: str | None,
) -> bool:
    """
    Validate that the purls contains the required fields (type, name and version). Then
    compare the compare purls based on the required fields and the namespace.

    Args:
        parent_purl: The parent purl to validate and compare with the component purl.
        component_purl: The component purl to validate and compare with the parent purl.

    Returns:
        True if the purls match after validation, False if either purl is invalid, or
        the validated purls don't match.
    """
    # ValueError is thrown if a purl is None, or missing type or name.
    try:
        parent_purl_obj = PackageURL.from_string(parent_purl)  # type: ignore[arg-type]
        component_purl_obj = PackageURL.from_string(component_purl)  # type: ignore[arg-type]
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


def checksums_match(
    parent_checksums: list[Checksum], component_checksums: list[Checksum]
) -> bool:
    """
    Compare two lists of Package Checksum objects. All checksums must match.

    Args:
        parent_checksums: List of Checksum objects from parent package.
        component_checksums: List of Checksum objects from component package.

    Returns:
        True if any ofthe checksums match, False otherwise.
    """
    # The Checksum objects are not hashable and do not have to_string(), convert them to
    # strings in a custom way
    parent_checksums_str = [
        str(checksum.algorithm) + ":" + checksum.value for checksum in parent_checksums
    ]
    component_checksums_str = [
        str(checksum.algorithm) + ":" + checksum.value
        for checksum in component_checksums
    ]
    return set(parent_checksums_str) == set(component_checksums_str)


def package_matched(
    parent_sbom_doc: Document,
    parent_package: Package,
    component_package: Package,
) -> bool:
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
    content that was added during build. Therefore a Hermeto-generated component package
    should never be matched with any parent content. On the other hand, Syft scans the
    entire image including parent content, so Syft-generated components can potentially
    be matched with parent packages generated by either tool.

    Args:
        parent_sbom_doc: The parent SBOM document.
        parent_package: The parent package.
        component_package: The component package.

    Returns:
        True if the packages match based on the criteria above, False otherwise.
    """
    parent_package_annotations = get_annotations_by_spdx_id(
        parent_sbom_doc, parent_package.spdx_id
    )

    parent_purl = get_package_purl(parent_package)
    component_purl = get_package_purl(component_package)

    # Hermeto-to-syft matching
    if generated_by_hermeto(parent_package_annotations):
        return validate_and_compare_purls(parent_purl, component_purl)

    # Syft-to-syft matching: Check identifiers from most specific to least specific
    if parent_package.checksums or component_package.checksums:
        return checksums_match(parent_package.checksums, component_package.checksums)

    if parent_package.verification_code or component_package.verification_code:
        return parent_package.verification_code == component_package.verification_code

    return validate_and_compare_purls(parent_purl, component_purl)


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


def associate_relationships_and_related_packages(
    packages: list[Package],
    relationships: list[Relationship],
    relationship_type: RelationshipType,
) -> list[tuple[Package, Relationship]]:
    """
    Associate relationships (related_spdx_element_id) and related
    packages (spdx_id) together for given relationship type.
    First relationship index is built. Then packages and
    relationships are associated based on index.

    Args:
        packages: List of Package objects.
        relationships: List of Relationship objects.
        relationship_type: Relationship type.

    Returns:
        List of tuples of related package and relationship objects.
    """
    rel_index: dict[str, Relationship] = {}
    for rel in relationships:
        if rel.relationship_type == relationship_type and isinstance(
            rel.related_spdx_element_id, str
        ):
            rel_index[rel.related_spdx_element_id] = rel

    assoc_package_relationship = []
    for pkg in packages:
        if pkg.spdx_id in rel_index:
            assoc_package_relationship.append((pkg, rel_index[pkg.spdx_id]))

    return assoc_package_relationship
