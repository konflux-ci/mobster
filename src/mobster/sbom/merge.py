"""SBOM merging utilities"""

import functools
import itertools
import json
from abc import ABC, abstractmethod
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, TypeVar
from urllib.parse import quote_plus

from packageurl import PackageURL

T = TypeVar("T")


def try_parse_purl(s: str) -> PackageURL | None:
    """
    Try to parse a Package URL from a string.

    Args:
        s: The string to parse
    Returns:
        PackageURL: The parsed Package URL, or None if parsing failed
    """
    try:
        return PackageURL.from_string(s)
    except ValueError:
        return None


class SBOMItem(ABC):
    """
    Base class for SBOM items.

    Methods are defined to be overridden by subclasses.
    """

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
    def unwrap(self) -> dict[str, Any]:
        """Unwrap the SBOM item into a dictionary."""


def fallback_key(package: SBOMItem) -> str:
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
class CDXComponent(SBOMItem):
    """
    Class representing a CycloneDX component.
    """

    data: dict[str, Any]

    def id(self) -> str:
        return self.data.get("bom-ref", "")  # type: ignore

    def name(self) -> str:
        return self.data["name"]  # type: ignore

    def version(self) -> str:
        return self.data.get("version") or ""

    def purl(self) -> PackageURL | None:
        if purl_str := self.data.get("purl"):
            return try_parse_purl(purl_str)
        return None

    def unwrap(self) -> dict[str, Any]:
        return self.data


def wrap_as_cdx(items: Iterable[dict[str, Any]]) -> list[CDXComponent]:
    """
    Wrap a list of CycloneDX components into CDXComponent objects.
    """
    return list(map(CDXComponent, items))


@dataclass
class SPDXPackage(SBOMItem):
    """
    Class representing an SPDX package.
    """

    data: dict[str, Any]

    def id(self) -> str:
        return self.data["SPDXID"]  # type: ignore

    def name(self) -> str:
        return self.data["name"]  # type: ignore

    def version(self) -> str:
        return self.data.get("versionInfo") or ""

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
            ref["referenceLocator"]
            for ref in self.data.get("externalRefs", [])
            if ref["referenceType"] == "purl"
        ]
        return list(filter(None, map(try_parse_purl, purls)))

    def unwrap(self) -> dict[str, Any]:
        return self.data


def wrap_as_spdx(items: list[dict[str, Any]]) -> list[SPDXPackage]:
    """
    Wrap a list of SPDX packages into SPDXPackage objects.
    """
    return list(map(SPDXPackage, items))


def merge_by_apparent_sameness(
    components_a: Sequence[SBOMItem], components_b: Sequence[SBOMItem]
) -> list[dict[str, Any]]:
    """
    Merge components based on apparent sameness.
    """

    def key(component: SBOMItem) -> str:
        purl = component.purl()
        if purl:
            return purl.to_string()
        return fallback_key(component)

    return [c.unwrap() for c in get_merged_components(components_a, components_b, key)]


def merge_by_prefering_hermeto(
    syft_components: Sequence[SBOMItem], hermeto_components: Sequence[SBOMItem]
) -> list[dict[str, Any]]:
    """
    Merge components by preferring hermeto components over syft components.
    """
    is_duplicate_component = _get_syft_component_filter(hermeto_components)
    merged = [c for c in syft_components if not is_duplicate_component(c)]
    merged += hermeto_components
    return [c.unwrap() for c in merged]


def _get_syft_component_filter(
    hermeto_sbom_components: Sequence[SBOMItem],
) -> Callable[[SBOMItem], bool]:
    """
    Get a function that filters out Syft components for the merged SBOM.

    This function currently considers a Syft component as a duplicate/removable if:
    - it has the same key as a hermeto component
    - it is a local Golang replacement
    - is a non-registry component also reported by hermeto

    Note that for the last bullet, we can only rely on the Pip dependency's name
    to find a duplicate. This is because hermeto does not report a non-PyPI
    Pip dependency's version.

    Even though multiple versions of a same dependency can be available in the
    same project, we are removing all Syft instances by name only because hermeto
    will report them correctly, given that it scans all the source code properly
    and the image is built hermetically.
    """
    hermeto_non_registry_components = [
        component.name()
        for component in hermeto_sbom_components
        if _is_hermeto_non_registry_dependency(component)
    ]
    hermeto_local_paths = {
        Path(subpath)
        for component in hermeto_sbom_components
        if (purl := component.purl()) and (subpath := purl.subpath)
    }

    hermeto_indexed_components = {
        _unique_key_hermeto(component): component
        for component in hermeto_sbom_components
    }

    def is_duplicate_non_registry_component(component: SBOMItem) -> bool:
        return component.name() in hermeto_non_registry_components

    def is_duplicate_npm_localpath_component(component: SBOMItem) -> bool:
        purl = component.purl()
        if not purl or purl.type != "npm":
            return False
        # instead of reporting path dependencies as pkg:npm/name@version?..#subpath,
        # syft reports them as pkg:npm/subpath@version
        return Path(purl.namespace or "", purl.name) in hermeto_local_paths

    def component_is_duplicated(component: SBOMItem) -> bool:
        """
        Determine if a component from Syft is duplicated in hermeto.

        Args:
            component: The Syft component to check

        Returns:
           bool: True if the component should be considered a duplicate, False
           otherwise
        """
        key = _unique_key_syft(component)

        return (
            _is_syft_local_golang_component(component)
            or is_duplicate_non_registry_component(component)
            or is_duplicate_npm_localpath_component(component)
            or key in hermeto_indexed_components.keys()
        )

    return component_is_duplicated


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


def _is_syft_local_golang_component(component: SBOMItem) -> bool:
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


def _is_hermeto_non_registry_dependency(component: SBOMItem) -> bool:
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


def _unique_key_hermeto(component: SBOMItem) -> str:
    """
    Create a unique key from hermeto reported components.

    This is done by taking a purl and removing any qualifiers and subpaths.
    See https://github.com/package-url/purl-spec/tree/master#purl
    for more info on purls.

    Args:
        component: The component to create a key for

    Returns:
        str: A unique key string for the component
    """
    purl = component.purl()
    if not purl:
        return fallback_key(component)
    return purl._replace(qualifiers=None, subpath=None).to_string()


def _unique_key_syft(component: SBOMItem) -> str:
    """
    Create a unique key for Syft reported components.

    This is done by taking a lowercase namespace/name, and URL encoding the version.

    Syft does not set any qualifier for NPM, Pip or Golang, so there's
    no need to remove them
    as done in _unique_key_hermeto.

    If a Syft component lacks a purl (e.g. type OS), we'll use its
    name and version instead.

    Args:
        component: The component to create a key for

    Returns:
        str: A unique key string for the component
    """
    purl = component.purl()
    if not purl:
        return fallback_key(component)

    name = purl.name
    version = purl.version
    subpath = purl.subpath

    if purl.type == "pypi":
        name = name.lower()

    if purl.type == "golang":
        if version:
            version = quote_plus(version)
        if subpath and _subpath_is_version(subpath):
            # put the module version where it belongs (in the module name)
            name = f"{name}/{subpath}"
            subpath = None

    return purl._replace(name=name, version=version, subpath=subpath).to_string()


def get_merged_components(
    items_a: Iterable[T],
    items_b: Iterable[T],
    by_key: Callable[[T], Any],
) -> list[T]:
    """
    Merge two collections of items based on a key function.
    """
    return _dedupe(itertools.chain(items_a, items_b), by_key)


def _dedupe(items: Iterable[T], by_key: Callable[[T], Any]) -> list[T]:
    """
    Removes duplicates from a collection of items based on a key function.
    """
    item_by_key: dict[Any, T] = {}
    for item in items:
        item_by_key.setdefault(by_key(item), item)
    return list(item_by_key.values())


class SBOMMerger(ABC):  # pylint: disable=too-few-public-methods
    """Base class for merging SBOMs."""

    @abstractmethod
    def merge(
        self,
        sbom_a: dict[str, Any],
        sbom_b: dict[str, Any],
    ) -> dict[str, Any]:  # pragma: no cover
        """
        Merge two SBOMs.
        This method should be implemented by subclasses.
        Args:
            sbom_a: The first SBOM to merge
            sbom_b: The second SBOM to merge
        Returns:
            dict[str, Any]: The merged SBOM
        """
        raise NotImplementedError("Merge method logic is implemented in subclasses.")


class CycloneDXMerger(SBOMMerger):  # pylint: disable=too-few-public-methods
    """
    Merger class for CycloneDX SBOMs.
    """

    def __init__(
        self,
        merge_components_func: Callable[
            [Sequence[CDXComponent], Sequence[CDXComponent]], list[dict[str, Any]]
        ],
    ) -> None:
        self.merge_components_func = merge_components_func

    def merge(self, sbom_a: dict[str, Any], sbom_b: dict[str, Any]) -> dict[str, Any]:
        """
        Merge two CycloneDX SBOMs.

        Args:
            sbom_a: The first SBOM to merge
            sbom_b: The second SBOM to merge

        Returns:
            dict[str, Any]: The merged SBOM
        """
        components_a = wrap_as_cdx(sbom_a.get("components", []))
        components_b = wrap_as_cdx(sbom_b.get("components", []))
        merged = self.merge_components_func(components_a, components_b)

        sbom_a["components"] = merged
        self._merge_tools_metadata(sbom_a, sbom_b)

        return sbom_a

    def _merge_tools_metadata(
        self, sbom_a: dict[Any, Any], sbom_b: dict[Any, Any]
    ) -> None:
        """Merge the .metadata.tools of the right SBOM into the left SBOM.

        Handle both the 1.4 style and the 1.5 style of .metadata.tools.
        If the SBOMs don't use the same style, conform to the left SBOM.

        https://cyclonedx.org/docs/1.4/json/#metadata_tools
        vs.
        https://cyclonedx.org/docs/1.5/json/#metadata_tools
        """
        shared_keys = ["name", "version", "hashes", "externalReferences"]

        def tool_to_component(tool: dict[str, Any]) -> dict[str, Any]:
            component = {key: tool[key] for key in shared_keys if key in tool}
            if vendor := tool.get("vendor"):
                component["author"] = vendor
            component["type"] = "application"
            return component

        def component_to_tool(component: dict[str, Any]) -> dict[str, Any]:
            tool = {key: component[key] for key in shared_keys if key in component}
            if author := component.get("author"):
                tool["vendor"] = author
            return tool

        tools_a = sbom_a["metadata"]["tools"]
        tools_b = sbom_b["metadata"]["tools"]

        if isinstance(tools_a, dict):
            components_a = tools_a["components"]
            if isinstance(tools_b, dict):
                components_b = tools_b["components"]
            else:
                components_b = map(tool_to_component, tools_b)

            merged_components = merge_by_apparent_sameness(
                wrap_as_cdx(components_a), wrap_as_cdx(components_b)
            )
            sbom_a["metadata"]["tools"]["components"] = merged_components
        elif isinstance(tools_a, list):
            if isinstance(tools_b, dict):
                tools_b = map(component_to_tool, tools_b["components"])

            sbom_a["metadata"]["tools"] = get_merged_components(
                tools_a, tools_b, lambda t: (t["name"], t.get("version"))
            )
        else:
            raise RuntimeError(
                "The .metadata.tools JSON key is in an unexpected format. "
                f"Expected dict or list, got {type(tools_a)}."
            )


class SPDXMerger(SBOMMerger):  # pylint: disable=too-few-public-methods
    """Merger class for SPDX SBOMs."""

    def __init__(
        self,
        merge_components_func: Callable[
            [Sequence[SPDXPackage], Sequence[SPDXPackage]], list[dict[str, Any]]
        ],
    ):
        self.merge_components_func = merge_components_func

    def merge(self, sbom_a: dict[str, Any], sbom_b: dict[str, Any]) -> dict[str, Any]:
        """
        Merge two SPDX SBOMs.

        Args:
            sbom_a: The first SBOM to merge
            sbom_b: The second SBOM to merge

        Returns:
            dict[str, Any]: The merged SBOM
        """
        packages_a = wrap_as_spdx(sbom_a.get("packages", []))
        packages_b = wrap_as_spdx(sbom_b.get("packages", []))

        merged_packages = self.merge_components_func(packages_a, packages_b)
        merged_packages_ids = {p["SPDXID"] for p in merged_packages}

        def replace_spdxid(spdxid: str) -> str | None:
            if spdxid == sbom_b["SPDXID"]:
                # The merged document can only have one SPDXID, keep the left one
                return sbom_a["SPDXID"]  # type: ignore
            if spdxid == sbom_a["SPDXID"] or spdxid in merged_packages_ids:
                # Unchanged
                return spdxid
            # Drop
            return None

        merged_relationships = self._merge_relationships(
            sbom_a.get("relationships", []),
            sbom_b.get("relationships", []),
            replace_spdxid=replace_spdxid,
        )
        merged_creation_info = self._merge_creation_info(
            sbom_a["creationInfo"],
            sbom_b["creationInfo"],
        )

        merged_sbom = sbom_a | {
            "packages": merged_packages,
            "relationships": merged_relationships,
            "creationInfo": merged_creation_info,
        }
        # we have no handling for .files
        # we don't really care about them, so drop them altogether
        merged_sbom.pop("files", None)

        return merged_sbom

    def _merge_creation_info(
        self, creation_info_a: dict[str, Any], creation_info_b: dict[str, Any]
    ) -> dict[str, Any]:
        """Merge SPDX creation info."""

        def identity(creator: str) -> str:
            return creator

        creators = get_merged_components(
            creation_info_a["creators"], creation_info_b["creators"], by_key=identity
        )
        return creation_info_a | {"creators": creators}

    def _merge_relationships(
        self,
        relationships_a: list[dict[str, Any]],
        relationships_b: list[dict[str, Any]],
        replace_spdxid: Callable[[str], str | None],
    ) -> list[dict[str, Any]]:
        """Merge two lists of SPDX relationships."""
        merged_relationships = []

        for relationship in itertools.chain(relationships_a, relationships_b):
            element = replace_spdxid(relationship["spdxElementId"])
            related_element = replace_spdxid(relationship["relatedSpdxElement"])

            if element and related_element:
                merged_relationships.append(
                    relationship
                    | {"spdxElementId": element, "relatedSpdxElement": related_element}
                )

        return _dedupe(
            merged_relationships,
            lambda r: (
                r["spdxElementId"],
                r["relationshipType"],
                r["relatedSpdxElement"],
            ),
        )


def _create_merger(
    sbom_a: dict[str, Any],
    sbom_b: dict[str, Any],
    merge_components_func: Callable[
        [Sequence[SBOMItem], Sequence[SBOMItem]], list[dict[str, Any]]
    ],
) -> SBOMMerger:
    """
    Creates a merger for the given SBOMs.
    """
    sbom_type = _detect_sbom_type(sbom_a)
    sbom_type2 = _detect_sbom_type(sbom_b)

    if sbom_type != sbom_type2:
        raise ValueError(f"Mismatched SBOM formats: {sbom_type} X {sbom_type2}")

    if sbom_type == "cyclonedx":
        return CycloneDXMerger(merge_components_func)

    return SPDXMerger(merge_components_func)


def _detect_sbom_type(sbom: dict[str, Any]) -> Literal["cyclonedx", "spdx"]:
    """
    Detects the type of SBOM. Either CycloneDX or SPDX.
    """

    if sbom.get("bomFormat") == "CycloneDX":
        return "cyclonedx"
    if sbom.get("spdxVersion"):
        return "spdx"

    raise ValueError("Unknown SBOM format")


def _merge_sboms(
    sbom_a: dict[str, Any],
    sbom_b: dict[str, Any],
    merge_components_func: Callable[
        [Sequence[SBOMItem], Sequence[SBOMItem]], list[dict[str, Any]]
    ],
) -> dict[str, Any]:
    """
    Merge two SBOMs using the specified component merging method.
    """
    merger = _create_merger(sbom_a, sbom_b, merge_components_func)
    return merger.merge(sbom_a, sbom_b)


def merge_syft_and_hermeto_sboms(
    syft_sbom_paths: list[Path], hermeto_sbom_path: Path
) -> dict[str, Any]:
    """
    Merge multiple Syft and 1 hermeto SBOMs.
    """
    syft_sbom = merge_multiple_syft_sboms(syft_sbom_paths)

    with open(hermeto_sbom_path, encoding="UTF-8") as file:
        hermeto_sbom = json.load(file)

    return _merge_sboms(syft_sbom, hermeto_sbom, merge_by_prefering_hermeto)


def merge_multiple_syft_sboms(syft_sbom_paths: list[Path]) -> dict[str, Any]:
    """
    Merge multiple Syft SBOMs.
    """
    sboms = []
    for path in syft_sbom_paths:
        with open(path, encoding="UTF-8") as f:
            sboms.append(json.load(f))

    merge = functools.partial(
        _merge_sboms,
        merge_components_func=merge_by_apparent_sameness,
    )
    merged_sbom: dict[str, Any] = functools.reduce(merge, sboms)
    return merged_sbom


def merge_sboms(
    syft_sbom_paths: list[Path], hermeto_sbom_path: Path | None = None
) -> dict[str, Any]:
    """
    Merge multiple SBOMs.

    This is the main entrypoint function for merging SBOMs.
    Currently supports merging multiple Syft SBOMs with up to
    1 Hermeto SBOM.

    Args:
        syft_sbom_paths: List of paths to Syft SBOMs
        hermeto_sbom_path: Optional path to Hermeto SBOM

    Returns:
        The merged SBOM

    Raises:
        ValueError: If there are not enough SBOMs to merge (at least
        one Syft SBOM with Hermeto SBOM, or multiple Syft SBOMs)
    """

    if not syft_sbom_paths:
        raise ValueError("At least one Syft SBOM path is required to merge SBOMs.")
    if not hermeto_sbom_path:
        if len(syft_sbom_paths) < 2:
            raise ValueError(
                "At least two Syft SBOM paths are required when no ",
                "Hermeto SBOM is provided",
            )
        return merge_multiple_syft_sboms(syft_sbom_paths)
    return merge_syft_and_hermeto_sboms(syft_sbom_paths, hermeto_sbom_path)
