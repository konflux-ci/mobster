"""SBOM merging utilities"""

import uuid
from abc import ABC, abstractmethod
from collections.abc import Iterable
from copy import copy, deepcopy
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Generic, Literal, TypeVar

from cyclonedx.model.bom_ref import BomRef
from cyclonedx.model.component import Component
from cyclonedx.model.dependency import Dependency
from cyclonedx.model.tool import Tool
from packageurl import PackageURL
from spdx_tools.spdx.model.actor import Actor
from spdx_tools.spdx.model.annotation import Annotation
from spdx_tools.spdx.model.document import Document
from spdx_tools.spdx.model.package import Package
from spdx_tools.spdx.model.relationship import Relationship

from mobster.sbom.cyclonedx_wrapper import CycloneDX1BomWrapper
from mobster.sbom.load import load_dict_to_sbom
from mobster.sbom.spdx import deduplicate_relationships

T = TypeVar("T")


class SBOMSource(Enum):
    """
    The source tool of the SBOM.
    """

    SYFT = "syft"
    HERMETO = "hermeto"


def try_parse_purl(s: str | None) -> PackageURL | None:
    """
    Try to parse a Package URL from a string.

    Args:
        s: The string to parse
    Returns:
        PackageURL: The parsed Package URL, or None if parsing failed
    """
    if s is None:
        return None
    try:
        return PackageURL.from_string(s)
    except ValueError:
        return None


@dataclass
class SBOMItem(ABC, Generic[T]):
    """
    Base class for SBOM items.

    Methods are defined to be overridden by subclasses.
    """

    source: SBOMSource
    data: T

    @abstractmethod
    def id(self) -> str:
        """Get the ID of the SBOM item."""

    @abstractmethod
    def name(self) -> str:
        """Get the name of the SBOM item."""

    @abstractmethod
    def version(self) -> str:
        """Get the version of the SBOM item."""

    @abstractmethod
    def purl(self) -> PackageURL | None:
        """Get the Package URL of the SBOM item."""

    @abstractmethod
    def unwrap(self) -> T:
        """Unwrap the SBOM item into an object."""

    def normalized_purl(self) -> str | None:
        """
        The PURL format unified between Syft and Hermeto SBOMs.
        Returns:
            The normalized PURL string if PURL is present. None otherwise.
        """
        if not (purl := self.purl()):
            return None
        name = purl.name
        if purl.type == "pypi":
            name = name.lower()
        subpath = purl.subpath
        if purl.type == "golang":
            if subpath and _subpath_is_version(subpath):
                # put the module version where it belongs (in the module name)
                name = f"{name}/{subpath}"
        subpath = None

        qualifiers = purl.qualifiers
        if not isinstance(qualifiers, dict):
            return None

        # clear redundant qualifiers
        identity_qualifiers = {"arch", "os", "classifier", "type", "epoch"}
        meaningful_quals: dict[str, Any] = {}
        for k, v in qualifiers.items():
            if k not in identity_qualifiers:
                continue
            if k == "arch" and v == "noarch":
                continue
            if purl.type == "golang" and k == "type" and v == "module":
                continue
            meaningful_quals[k] = v

        return PackageURL(
            type=purl.type,
            namespace=purl.namespace,
            name=name,
            version=purl.version,
            qualifiers=meaningful_quals,
            subpath=subpath,
        ).to_string()


def fallback_key(package: SBOMItem[T]) -> str:
    """
    Get the "fallback key" for a package that doesn't have a purl.
    This is used to identify the package in the merged SBOM.
    Args:
        package: The package to get the key for
    Returns:
        str: The fallback key for the package
    """

    name = package.name()
    version = package.version()
    # name starts with "." or "/" -> the package probably represents a local directory
    # that is a useless name, don't use it as the key
    if name and not name.startswith((".", "/")):
        return f"{name}@{version}"
    return package.id()


@dataclass
class CDXComponent(SBOMItem[Component]):
    """
    Class representing a CycloneDX component.
    Creates a bom-ref for this object if not present.
    """

    def id(self) -> str:
        if self.data.bom_ref.value is None:
            self.data.bom_ref.value = uuid.uuid4().hex
        return self.data.bom_ref.value

    def name(self) -> str:
        return self.data.name

    def version(self) -> str:
        return self.data.version or ""

    def purl(self) -> PackageURL | None:
        return self.data.purl

    def unwrap(self) -> Component:
        return self.data


def wrap_as_cdx(items: Iterable[Component], source: SBOMSource) -> list[CDXComponent]:
    """
    Wrap a list of CycloneDX components into CDXComponent objects.
    """
    return [CDXComponent(data=item, source=source) for item in items]


@dataclass
class SPDXPackage(SBOMItem[Package]):
    """
    Class representing an SPDX package.
    """

    def id(self) -> str:
        return self.data.spdx_id

    def name(self) -> str:
        return self.data.name

    def version(self) -> str:
        return self.data.version or ""

    def purl(self) -> PackageURL | None:
        purls = self.all_purls()
        if len(purls) > 1:
            raise ValueError(
                f"multiple purls for SPDX package: {', '.join(map(str, purls))}"
            )
        return purls[0] if purls else None

    def all_purls(self) -> list[PackageURL]:
        """Get all Package URLs for the SPDX package."""
        purls = [
            ref.locator
            for ref in self.data.external_references
            if ref.reference_type == "purl"
        ]
        return list(filter(None, map(try_parse_purl, purls)))

    def unwrap(self) -> Package:
        """
        Transform back into an SPDX package.
        Returns:
            The abstracted SPDX package.
        """
        return self.data


@dataclass
class MergeIndex(Generic[T]):
    """
    Class for tracking unique SBOM Items, keeps track
    of merged SBOMs and helps to add new packages with
    deduplication.

    Attributes:
        hermeto_involved:
            True if this index contains Hermeto content
        hermeto_non_registry_items:
            Hermeto items not pushed to a registry.
            These are matched against Syft items by
            name.
        items_by_path:
            If 2 records share the same path, they
            are equivalent and can be deduplicated.
        items_by_unique_key:
            Contains all deduplicated packages and
            their unique keys.
        id_mapping:
            Mapping of any SBOM Item id present in
            inputs mapped to an SBOM ID present in
            output.
    """

    hermeto_involved: bool = field(default=False)
    hermeto_non_registry_items: dict[str, SBOMItem[T]] = field(default_factory=dict)
    items_by_path: dict[Path, SBOMItem[T]] = field(default_factory=dict)
    items_by_unique_key: dict[str, SBOMItem[T]] = field(default_factory=dict)
    id_mapping: dict[str, str] = field(default_factory=dict)

    def add(self, item: SBOMItem[T]) -> bool:
        """Add an item to the index.

        Returns True if the item was kept in the merged set, False if it was
        dropped as a duplicate or filtered Syft-local Golang component.

        Users should add Hermeto component first.

        Args:
            item: SBOM Item to add.
        """
        purl = item.purl()
        if item.source is SBOMSource.HERMETO:
            self.hermeto_involved = True
            if _is_hermeto_non_registry_dependency(item):
                self.hermeto_non_registry_items[item.name()] = item
            if purl and purl.subpath:
                self.items_by_path[Path(purl.subpath)] = item
            self.items_by_unique_key[_unique_key(item)] = item
            self.id_mapping[item.id()] = item.id()
            return True

        # If item is sourced from Syft:

        # Local Golang replacements are only filtered when Hermeto is present
        if self.hermeto_involved and _is_syft_local_golang_component(item):
            return False
        if item.name() in self.hermeto_non_registry_items:
            self.id_mapping[item.id()] = self.hermeto_non_registry_items[
                item.name()
            ].id()
            return False
        if purl and purl.type == "npm":
            # Syft reports path deps as pkg:npm/<subpath>@version; Hermeto uses
            # pkg:npm/name@version#<subpath>. Match on the full path key.
            path_key = Path(purl.namespace or "", purl.name)
            if path_key in self.items_by_path:
                self.id_mapping[item.id()] = self.items_by_path[path_key].id()
                return False
        syft_key = _unique_key(item)
        if syft_key in self.items_by_unique_key:
            self.id_mapping[item.id()] = self.items_by_unique_key[syft_key].id()
            return False
        self.items_by_unique_key[syft_key] = item
        self.id_mapping[item.id()] = item.id()
        return True

    def add_sbom(self, items: Iterable[SBOMItem[T]]) -> None:
        """
        Add all items from the SBOM to the index.
        Args:
            items: The SBOM Items to add.

        Returns:
            Nothing, mutates the index.
        """
        for item in items:
            self.add(item)

    def get_items(self) -> list[SBOMItem[T]]:
        """
        Get all unique items back from the index.
        Returns:
            The unique merged deduplicated items.
        """
        return list(self.items_by_unique_key.values())


def wrap_as_spdx(items: list[Package], source: SBOMSource) -> list[SPDXPackage]:
    """
    Wrap a list of SPDX packages into SPDXPackage objects.
    """
    return [SPDXPackage(source=source, data=item) for item in items]


def _subpath_is_version(subpath: str) -> bool:
    """
    Determine if a subpath is actually a version identifier.

    This is specific to Golang packages, where sometimes the subpath
    is actually a version (e.g., 'v2' in pkg:golang/example@v1.0.0#v2).

    Args:
        subpath: The subpath string to check

    Returns:
        bool: True if the subpath appears to be a version identifier False otherwise
    """
    # pkg:golang/github.com/cachito-testing/gomod-pandemonium@v0.0.0#terminaltor
    # -> subpath is a subpath

    # pkg:golang/github.com/cachito-testing/retrodep@v2.1.1#v2
    # -> subpath is a version. Thanks, Syft.
    return subpath.startswith("v") and subpath.removeprefix("v").isdecimal()


def _is_syft_local_golang_component(component: SBOMItem[T]) -> bool:
    """
    Check if a Syft Golang reported component is a local replacement.

    Local replacements are reported in a very different way by hermeto,
    which is why the same reports by Syft should be removed.

    Args:
        component: The component to check

    Returns:
        bool: True if the component is a local Golang replacement, False otherwise
    """
    purl = component.purl()
    if not purl or purl.type != "golang":
        return False
    if (subpath := purl.subpath) and not _subpath_is_version(subpath):
        return True
    return component.name().startswith(".") or component.version() == "(devel)"


def _is_hermeto_non_registry_dependency(component: SBOMItem[T]) -> bool:
    """
    Check if hermeto component was fetched from a VCS or a direct file location.

    hermeto reports non-registry components in a different way from Syft,
    so the reports from Syft need to be removed.

    Unfortunately, there's no way to determine which
    components are non-registry by looking at the Syft report alone.
    This function is meant to create a list of non-registry components
    from hermeto's SBOM, then remove the corresponding ones
    reported by Syft for the merged SBOM.

    Note that this function is only applicable for PyPI or NPM components.

    Args:
        component: The component to check

    Returns:
        bool: True if the component is a non-registry dependency, False otherwise
    """
    purl = component.purl()
    if not purl:
        return False

    qualifiers = purl.qualifiers or {}
    return purl.type in ("pypi", "npm") and (
        "vcs_url" in qualifiers or "download_url" in qualifiers
    )


def _unique_key(component: SBOMItem[T]) -> str:
    """
    Create a unique key for Syft reported components.

    This is done by taking a lowercase namespace/name, URL encoding the version,
    removing subpaths and non-identity qualifiers.
    """
    purl = component.normalized_purl()
    if not purl:
        return fallback_key(component)
    return purl


class SBOMMerger(ABC, Generic[T]):  # pylint: disable=too-few-public-methods
    """Base class for merging SBOMs."""

    @abstractmethod
    def merge(
        self,
        syft_sboms: list[T],
        hermeto_sbom: T | None = None,
    ) -> T:  # pragma: no cover
        """
        Merge two SBOMs.
        This method should be implemented by subclasses.
        Args:
            hermeto_sbom: The Hermeto SBOM if available
            syft_sboms: The Syft SBOMs to be merged
        Returns:
            The merged SBOM
        """
        raise NotImplementedError("Merge method logic is implemented in subclasses.")


class CycloneDXMerger(SBOMMerger[CycloneDX1BomWrapper]):  # pylint: disable=too-few-public-methods
    """
    Merger class for CycloneDX SBOMs.
    """

    def __init__(self) -> None:
        self.mapping_index = MergeIndex[Component]()

    def merge(
        self,
        syft_sboms: list[CycloneDX1BomWrapper],
        hermeto_sbom: CycloneDX1BomWrapper | None = None,
    ) -> CycloneDX1BomWrapper:
        """
        Merge two CycloneDX SBOMs.

        Args:
            hermeto_sbom: Hermeto SBOM if available
            syft_sboms: The Syft SBOMs to be merged

        Returns:
            The merged SBOM
        """
        assert syft_sboms, "Cannot merge SBOMs, none were provided."

        if hermeto_sbom is not None:
            self.mapping_index.add_sbom(
                wrap_as_cdx(hermeto_sbom.sbom.components, SBOMSource.HERMETO)
            )
        for syft_sbom in syft_sboms:
            self.mapping_index.add_sbom(
                wrap_as_cdx(syft_sbom.sbom.components, SBOMSource.SYFT)
            )

        result = deepcopy(syft_sboms[0])
        if result.sbom.metadata.component is not None:
            self.mapping_index.add(
                CDXComponent(
                    data=result.sbom.metadata.component, source=SBOMSource.SYFT
                )
            )

        result.sbom.components = [
            item.unwrap() for item in self.mapping_index.get_items()
        ]

        available_sboms = list(syft_sboms)
        if hermeto_sbom is not None:
            available_sboms.append(hermeto_sbom)
        all_tools = self._merge_tools_metadata(available_sboms)
        result.sbom.metadata.tools.tools = [
            tool for tool in all_tools if isinstance(tool, Tool)
        ]
        result.sbom.metadata.tools.components = [
            tool for tool in all_tools if isinstance(tool, Component)
        ]
        result.sbom.dependencies = self._merge_dependencies(available_sboms)
        for bom in available_sboms[1:]:
            result.model_cards.update(bom.model_cards)

        return result

    def _merge_tools_metadata(
        self, sboms: list[CycloneDX1BomWrapper]
    ) -> list[Tool | Component]:
        """Merge the .metadata.tools of the right SBOM into the left SBOM."""
        unique_tools: set[Tool] = set()
        for sbom in sboms:
            for tool in sbom.sbom.metadata.tools.tools:
                if tool not in unique_tools:
                    unique_tools.add(copy(tool))
            for tool_component in sbom.sbom.metadata.tools.components:
                unique_tools.add(tool_component)
        return list(unique_tools)

    def _merge_dependencies(
        self, sboms: list[CycloneDX1BomWrapper]
    ) -> list[Dependency]:
        """Remap dependency refs via id_mapping and merge edges for the same ref."""
        deps_by_ref: dict[str, set[str]] = {}
        for sbom in sboms:
            for dependency_mapping in sbom.sbom.dependencies:
                new_ref = self.mapping_index.id_mapping.get(
                    dependency_mapping.ref.value
                )
                if new_ref is None:
                    continue
                child_refs = deps_by_ref.setdefault(new_ref, set())
                for dep in dependency_mapping.dependencies:
                    mapped_child = self.mapping_index.id_mapping.get(dep.ref.value)
                    if mapped_child is not None:
                        child_refs.add(mapped_child)
        return [
            Dependency(
                BomRef(ref),
                [Dependency(BomRef(child)) for child in sorted(children)],
            )
            for ref, children in deps_by_ref.items()
        ]


class SPDXMerger(SBOMMerger[Document]):  # pylint: disable=too-few-public-methods
    """
    Merger class for SPDX SBOMs.
    Attributes:
        mapping_index: Index for mapping the merged SBOMs.
    """

    def __init__(
        self,
    ) -> None:
        self.mapping_index = MergeIndex[Package]()

    def _resolve_relationship_id(
        self,
        spdx_id: str,
        base_doc_id: str,
        other_doc_ids: set[str],
    ) -> str | None:
        """
        Map an SPDX element id into the merged document's id space.

        In case of document refs, keeps base  doc id, but remaps other
        doc id to it.
        """
        if spdx_id == base_doc_id or spdx_id in other_doc_ids:
            return base_doc_id
        return self.mapping_index.id_mapping.get(spdx_id)

    def _merge_relationships(self, sboms: list[Document]) -> list[Relationship]:
        """Merge relationships from all SBOMs, dropping file/unknown refs."""
        base_doc_id = sboms[0].creation_info.spdx_id
        other_doc_ids = {sbom.creation_info.spdx_id for sbom in sboms[1:]}
        merged: list[Relationship] = []
        for sbom in sboms:
            for relationship in sbom.relationships:
                related_id = relationship.related_spdx_element_id
                if not isinstance(related_id, str):
                    continue
                element = self._resolve_relationship_id(
                    relationship.spdx_element_id, base_doc_id, other_doc_ids
                )
                related = self._resolve_relationship_id(
                    related_id, base_doc_id, other_doc_ids
                )
                if element and related:
                    merged.append(
                        Relationship(
                            spdx_element_id=element,
                            relationship_type=relationship.relationship_type,
                            related_spdx_element_id=related,
                            comment=relationship.comment
                            or None,  # Remove empty comments
                        )
                    )
        return deduplicate_relationships(merged)

    def _merge_annotations(self, sboms: list[Document]) -> list[Annotation]:
        resulting_annotations = []
        for sbom in sboms:
            for annotation in sbom.annotations:
                if new_id := self.mapping_index.id_mapping.get(annotation.spdx_id):
                    copied_annotation = copy(annotation)
                    copied_annotation.spdx_id = new_id
                    resulting_annotations.append(copied_annotation)
        return resulting_annotations

    def _merge_creators(self, sboms: list[Document]) -> list[Actor]:
        assert sboms, "No SBOMs provided!"
        result = []
        visited_actors_serialized = set()
        for sbom in sboms:
            for actor in sbom.creation_info.creators:
                if (serialized_actor := str(actor)) not in visited_actors_serialized:
                    visited_actors_serialized.add(serialized_actor)
                    result.append(actor)
        return result

    def merge(
        self,
        syft_sboms: list[Document],
        hermeto_sbom: Document | None = None,
    ) -> Document:
        """
        Merge two SPDX SBOMs.

        Args:
            syft_sboms: The Syft SBOMs to be merged
            hermeto_sbom: Hermeto SBOM if available

        Returns:
            The merged SBOM document
        """
        result = deepcopy(syft_sboms[0])

        # The annotations to document root need to be preserved
        document_id = result.creation_info.spdx_id
        self.mapping_index.id_mapping[document_id] = document_id

        if hermeto_sbom is not None:
            self.mapping_index.add_sbom(
                wrap_as_spdx(hermeto_sbom.packages, SBOMSource.HERMETO)
            )
            self.mapping_index.id_mapping[hermeto_sbom.creation_info.spdx_id] = (
                document_id
            )
        for syft_sbom in syft_sboms:
            self.mapping_index.add_sbom(
                wrap_as_spdx(syft_sbom.packages, SBOMSource.SYFT)
            )
            self.mapping_index.id_mapping[syft_sbom.creation_info.spdx_id] = document_id

        meta_sboms = list(syft_sboms)
        if hermeto_sbom is not None:
            meta_sboms.append(hermeto_sbom)

        result.relationships = self._merge_relationships(meta_sboms)
        result.creation_info.creators = self._merge_creators(meta_sboms)
        result.packages = [item.unwrap() for item in self.mapping_index.get_items()]
        result.annotations = self._merge_annotations(meta_sboms)

        # we have no handling for .files
        # we don't really care about them, so drop them altogether
        result.files = []

        return result


def _detect_sbom_type(sbom: dict[str, Any]) -> Literal["cyclonedx", "spdx"]:
    """
    Detects the type of SBOM. Either CycloneDX or SPDX.
    """

    if sbom.get("bomFormat") == "CycloneDX":
        return "cyclonedx"
    if sbom.get("spdxVersion"):
        return "spdx"

    raise ValueError("Unknown SBOM format")


def merge_sboms(
    syft_sboms: list[dict[str, Any]],
    hermeto_sbom: dict[str, Any] | None = None,
) -> Document | CycloneDX1BomWrapper:
    """
    Merge multiple SBOMs.

    This is the main entrypoint function for merging SBOMs.
    Currently supports merging multiple Syft SBOMs with up to
    1 Hermeto SBOM.

    Args:
        syft_sboms: List of Syft SBOM dictionaries
        hermeto_sbom: Optional Hermeto SBOM dictionary

    Returns:
        The merged SBOM

    Raises:
        ValueError: If there are not enough SBOMs to merge (at least
        one Syft SBOM with Hermeto SBOM, or multiple Syft SBOMs)
    """

    if not syft_sboms:
        raise ValueError("At least one Syft SBOM is required to merge SBOMs.")
    if not hermeto_sbom:
        if len(syft_sboms) < 2:
            raise ValueError(
                "At least two Syft SBOMs are required when no Hermeto SBOM is provided"
            )
    loaded_syft_sboms = [
        load_dict_to_sbom(sbom, append_mobster=True) for sbom in syft_sboms
    ]
    loaded_hermeto_sbom = load_dict_to_sbom(hermeto_sbom) if hermeto_sbom else None
    merger: SPDXMerger | CycloneDXMerger
    if all(isinstance(syft_sbom, Document) for syft_sbom in loaded_syft_sboms) and (
        isinstance(loaded_hermeto_sbom, Document) or loaded_hermeto_sbom is None
    ):
        merger = SPDXMerger()
    elif all(
        isinstance(syft_sbom, CycloneDX1BomWrapper) for syft_sbom in loaded_syft_sboms
    ) and (
        isinstance(loaded_hermeto_sbom, CycloneDX1BomWrapper)
        or loaded_hermeto_sbom is None
    ):
        merger = CycloneDXMerger()
    else:
        raise ValueError(
            "All input SBOMs must use the same SBOM format (SPDX 2.x or CycloneDX 1.4+)"
        )
    return merger.merge(loaded_syft_sboms, loaded_hermeto_sbom)  # type: ignore[arg-type]
