import re
from dataclasses import dataclass, field
from datetime import datetime

from spdx_tools.spdx.model.actor import Actor, ActorType
from spdx_tools.spdx.model.annotation import Annotation
from spdx_tools.spdx.model.checksum import Checksum, ChecksumAlgorithm
from spdx_tools.spdx.model.document import CreationInfo, Document
from spdx_tools.spdx.model.package import (
    ExternalPackageRef,
    ExternalPackageRefCategory,
    Package,
    PackagePurpose,
    PackageVerificationCode,
)
from spdx_tools.spdx.model.relationship import Relationship, RelationshipType
from spdx_tools.spdx.model.spdx_no_assertion import SpdxNoAssertion

from mobster.cmd.generate.oci_image.spdx_utils import KonfluxAnnotationManager


@dataclass
class AnnotatedPackage:
    """
    Convenience wrapper for a package and its annotations to keep them
    together. Needed because the spdx-tools library doesn't support embedding
    annotation objects directly into a Package.
    """

    package: Package
    annotations: list[Annotation] = field(default_factory=list)

    @property
    def spdx_id(self) -> str:
        return self.package.spdx_id


class SPDXPackageBuilder:
    """
    Builder-pattern object to easily create annotated SPDX packages for testing
    purposes.
    """

    def __init__(self) -> None:
        self._version: str | None = None
        self._name: str | None = None
        self._external_references: list[ExternalPackageRef] = []
        self._checksums: list[Checksum] = []
        self._spdx_id: str | None = None
        self._primary_package_purpose: PackagePurpose | None = None
        self._annotations: list[Annotation] = []
        self._verification_code: PackageVerificationCode | None = None

    def version(self, version: str) -> "SPDXPackageBuilder":
        self._version = version
        return self

    def name(self, name: str) -> "SPDXPackageBuilder":
        self._name = name
        return self

    def spdx_id(self, spdx_id: str) -> "SPDXPackageBuilder":
        self._spdx_id = spdx_id
        return self

    def sha256_checksum(self, value: str) -> "SPDXPackageBuilder":
        self._checksums.append(
            Checksum(
                algorithm=ChecksumAlgorithm.SHA256,
                value=value,
            )
        )
        return self

    def is_base_image_annotation(self) -> "SPDXPackageBuilder":
        self._annotations.append(KonfluxAnnotationManager.base_image(""))
        return self

    def is_builder_image_for_stage_annotation(self, stage: int) -> "SPDXPackageBuilder":
        self._annotations.append(KonfluxAnnotationManager.builder_image("", stage))
        return self

    def purl(self, purl: str) -> "SPDXPackageBuilder":
        self._external_references.append(
            ExternalPackageRef(
                category=ExternalPackageRefCategory.PACKAGE_MANAGER,
                reference_type="purl",
                locator=purl,
            )
        )
        return self

    def primary_package_purpose(self, purpose: PackagePurpose) -> "SPDXPackageBuilder":
        self._primary_package_purpose = purpose
        return self

    def spdx_id_from_name(self, name: str) -> str:
        """
        Generate an spdx_id from a package name, while normalizing it to use
        just alphanumeric characters plus '.' and '-'.
        """
        normalized = re.sub(r"[^0-9a-zA-Z\.\-\+]", "-", name)
        return f"SPDXRef-Package-{normalized}"

    def verification_code(self, value: str) -> "SPDXPackageBuilder":
        self._verification_code = PackageVerificationCode(value=value)
        return self

    def build(self) -> AnnotatedPackage:
        if self._name is None:
            raise ValueError("name is a mandatory field for a package")

        if self._version is None:
            raise ValueError("version is a mandatory field for a package")

        spdx_id = self._spdx_id
        if spdx_id is None:
            spdx_id = self.spdx_id_from_name(self._name)

        annotations = []
        for ann in self._annotations:
            ann.spdx_id = spdx_id
            annotations.append(ann)

        package = Package(
            spdx_id=spdx_id,
            name=self._name,
            version=self._version,
            supplier=SpdxNoAssertion(),
            download_location=SpdxNoAssertion(),
            files_analyzed=self._verification_code is not None,
            checksums=self._checksums,
            license_concluded=SpdxNoAssertion(),
            license_declared=SpdxNoAssertion(),
            copyright_text=SpdxNoAssertion(),
            external_references=self._external_references,
            primary_package_purpose=self._primary_package_purpose,
            verification_code=self._verification_code,
        )
        return AnnotatedPackage(package, annotations)


class SPDXSBOMBuilder:
    """
    Builder-pattern object to easily create SPDX documents for testing
    purposes.
    """

    def __init__(self) -> None:
        self._name: str | None = None
        self._root_purl: str | None = None

        # tuple associating parent and child package spdx_ids and the
        # relationship between them to add to the SPDX document
        self._relationships: list[tuple[str | None, RelationshipType, str | None]] = []

        # packages and their associated annotations to be added to the SPDX document
        self._packages: list[AnnotatedPackage] = []

    def __extend_packages(self, packages: list[AnnotatedPackage]) -> None:
        """
        Extend the document's packages if their spdx ids are not already
        included.
        """
        for new_pkg in packages:
            if new_pkg.spdx_id not in {pkg.spdx_id for pkg in self._packages}:
                self._packages.append(new_pkg)

    def name(self, name: str) -> "SPDXSBOMBuilder":
        """
        Set the name of the SPDX document.
        """
        self._name = name
        return self

    def root_contains(self, packages: list[AnnotatedPackage]) -> "SPDXSBOMBuilder":
        """
        Add the passed packages to the SBOM and associate them to the root
        package with a CONTAINS relationship.
        """
        self.__extend_packages(packages)
        for pkg in packages:
            self._relationships.append((None, RelationshipType.CONTAINS, pkg.spdx_id))

        return self

    def root_describes(self, packages: list[AnnotatedPackage]) -> "SPDXSBOMBuilder":
        """
        Add the passed packages to the SBOM and associate them to the root
        package with a DESCRIBES relationship.
        """
        self.__extend_packages(packages)
        for pkg in packages:
            self._relationships.append((None, RelationshipType.DESCRIBES, pkg.spdx_id))
        return self

    def root_build_tool_of(self, packages: list[AnnotatedPackage]) -> "SPDXSBOMBuilder":
        """
        Add the passed packages to the SBOM and associate them to the root
        package with a BUILD_TOOL_OF relationship (package BUILD_TOOL_OF root).
        """
        self.__extend_packages(packages)
        for pkg in packages:
            self._relationships.append(
                (pkg.spdx_id, RelationshipType.BUILD_TOOL_OF, None)
            )
        return self

    def root_dependency_of(self, packages: list[AnnotatedPackage]) -> "SPDXSBOMBuilder":
        """
        Add the passed packages to the SBOM and associate them to the root
        package with a DEPENDENCY_OF relationship.
        """
        self.__extend_packages(packages)
        for pkg in packages:
            self._relationships.append(
                (None, RelationshipType.DEPENDENCY_OF, pkg.spdx_id)
            )

        return self

    def contains(
        self, pkg1: AnnotatedPackage, pkg2: AnnotatedPackage
    ) -> "SPDXSBOMBuilder":
        """
        Add the passed packages to the SBOM and create a CONTAINS relationship
        between them (pkg1 CONTAINS pkg2).
        """
        self.__extend_packages([pkg1, pkg2])
        self._relationships.append(
            (pkg1.spdx_id, RelationshipType.CONTAINS, pkg2.spdx_id)
        )
        return self

    def dependency_of(
        self, pkg1: AnnotatedPackage, pkg2: AnnotatedPackage
    ) -> "SPDXSBOMBuilder":
        """
        Add the passed packages to the SBOM and create a DEPENDENCY_OF relationship
        between them (pkg1 DEPENDENCY_OF pkg2).
        """
        self.__extend_packages([pkg1, pkg2])
        self._relationships.append(
            (pkg1.spdx_id, RelationshipType.DEPENDENCY_OF, pkg2.spdx_id)
        )
        return self

    def root_purl(self, purl: str) -> "SPDXSBOMBuilder":
        """
        Set the root package URL.
        """
        self._root_purl = purl
        return self

    @staticmethod
    def __add_package(
        doc: Document,
        apackage: AnnotatedPackage,
    ) -> None:
        doc.annotations.extend(apackage.annotations)
        doc.packages.append(apackage.package)

    @staticmethod
    def __add_relationship(
        doc: Document,
        spdx_id: str,
        reltype: RelationshipType,
        rel_spdx_id: str,
    ) -> None:
        doc.relationships.append(
            Relationship(
                spdx_element_id=spdx_id,
                related_spdx_element_id=rel_spdx_id,
                relationship_type=reltype,
            )
        )

    def build(self) -> Document:
        if self._name is None:
            raise ValueError("name is a mandatory field for an spdx document")

        if self._root_purl is None:
            raise ValueError("root purl is a mandatory field for an spdx document")

        creation_info = CreationInfo(
            spdx_version="SPDX-2.3",
            spdx_id="SPDXRef-DOCUMENT",
            name=self._name,
            data_license="CC0-1.0",
            document_namespace="https://some.namespace",
            creators=[Actor(ActorType.ORGANIZATION, "Red Hat", "shadowman@redhat.com")],
            created=datetime(2025, 1, 1),
        )

        doc = Document(creation_info)

        root_spdx_id = f"SPDXRef-DocumentRoot-{self._name}"
        root_package = (
            SPDXPackageBuilder()
            .spdx_id(root_spdx_id)
            .name(f"./{self._name}")
            .version("v1.0.0")
            .purl(self._root_purl)
            .primary_package_purpose(PackagePurpose.CONTAINER)
            .build()
        )

        # add the root package and its relationship to the document
        self.__add_package(
            doc,
            root_package,
        )

        self.__add_relationship(
            doc,
            "SPDXRef-DOCUMENT",
            RelationshipType.DESCRIBES,
            root_spdx_id,
        )

        # add the specified packages and relationships
        for pkg in self._packages:
            self.__add_package(doc, pkg)

        for spdx_id1, reltype, spdx_id2 in self._relationships:
            if spdx_id1 is None:
                spdx_id1 = root_spdx_id

            if spdx_id2 is None:
                spdx_id2 = root_spdx_id

            self.__add_relationship(
                doc,
                spdx_id1,
                reltype,
                spdx_id2,
            )

        return doc
