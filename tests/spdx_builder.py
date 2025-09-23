import re
from dataclasses import dataclass, field
from datetime import datetime

from spdx_tools.spdx.model.actor import Actor, ActorType
from spdx_tools.spdx.model.annotation import Annotation, AnnotationType
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

    def _konflux_annotation(self, comment: str) -> "SPDXPackageBuilder":
        # spdx_id will be populated during the build() step when the package
        # spdx_id is finalized
        self._annotations.append(
            Annotation(
                spdx_id="",
                annotation_type=AnnotationType.OTHER,
                annotation_date=datetime(2025, 1, 1),
                annotation_comment=comment,
                annotator=Actor(
                    actor_type=ActorType.TOOL,
                    name="konflux:jsonencoded",
                ),
            )
        )
        return self

    def is_base_image_annotation(self) -> "SPDXPackageBuilder":
        return self._konflux_annotation(
            '{"name":"konflux:container:is_base_image","value":"true"}'
        )

    def is_builder_image_for_stage_annotation(self, stage: int) -> "SPDXPackageBuilder":
        return self._konflux_annotation(
            f'{{"name":"konflux:container:is_builder_image:for_stage","value":"{stage}"}}'
        )

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
        self._contains: list[AnnotatedPackage] = []
        self._build_tool_of: list[AnnotatedPackage] = []
        self._dependency_of: list[AnnotatedPackage] = []
        self._root_purl: str | None = None

    def name(self, name: str) -> "SPDXSBOMBuilder":
        self._name = name
        return self

    def contains_packages(self, packages: list[AnnotatedPackage]) -> "SPDXSBOMBuilder":
        self._contains.extend(packages)
        return self

    def build_tool_of_packages(
        self, packages: list[AnnotatedPackage]
    ) -> "SPDXSBOMBuilder":
        self._build_tool_of.extend(packages)
        return self

    def dependency_of_packages(
        self, packages: list[AnnotatedPackage]
    ) -> "SPDXSBOMBuilder":
        self._dependency_of.extend(packages)
        return self

    def root_purl(self, purl: str) -> "SPDXSBOMBuilder":
        self._root_purl = purl
        return self

    @staticmethod
    def __add_package(
        doc: Document,
        apackage: AnnotatedPackage,
        reltype: RelationshipType,
        spdx_id: str,
        rel_spdx_id: str,
    ) -> None:
        doc.annotations.extend(apackage.annotations)
        doc.packages.append(apackage.package)
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

        self.__add_package(
            doc,
            root_package,
            RelationshipType.DESCRIBES,
            "SPDXRef-DOCUMENT",
            root_spdx_id,
        )

        for apkg in self._contains:
            self.__add_package(
                doc, apkg, RelationshipType.CONTAINS, root_spdx_id, apkg.spdx_id
            )

        for apkg in self._dependency_of:
            self.__add_package(
                doc, apkg, RelationshipType.DEPENDENCY_OF, root_spdx_id, apkg.spdx_id
            )

        for apkg in self._build_tool_of:
            self.__add_package(
                doc, apkg, RelationshipType.BUILD_TOOL_OF, apkg.spdx_id, root_spdx_id
            )

        return doc
