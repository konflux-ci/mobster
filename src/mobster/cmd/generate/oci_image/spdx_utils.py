"""SPDX-2.X utilities for the generate oci-image target"""

import json
from collections import defaultdict
from collections.abc import Generator
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, TypeVar

from packageurl import PackageURL
from spdx_tools.spdx.model.actor import Actor, ActorType
from spdx_tools.spdx.model.annotation import Annotation, AnnotationType
from spdx_tools.spdx.model.document import Document
from spdx_tools.spdx.model.package import Package
from spdx_tools.spdx.model.relationship import Relationship, RelationshipType
from spdx_tools.spdx.model.spdx_no_assertion import SpdxNoAssertion
from spdx_tools.spdx.parser.jsonlikedict.json_like_dict_parser import JsonLikeDictParser

from mobster.cmd.generate.oci_image.constants import BUILDER_IMAGE_PROPERTY
from mobster.image import IMAGE_PKG_SPDX_PREFIX, Image
from mobster.sbom.spdx import (
    DOC_ELEMENT_ID,
    get_image_package,
    get_mobster_tool_string,
    get_namespace,
    get_package_purl,
)

KONFLUX_JSON_ACTOR = Actor(actor_type=ActorType.TOOL, name="konflux:jsonencoded")


class MissingBuilderAnnotation(Exception):
    """
    Raised when an intermediate image package for an image package couldn't be
    created because it doesn't contain a builder image annotation.
    """


async def normalize_actor(actor: str) -> str:
    """
    Adds a necessary actor classificator if not present.
    This allows the SPDX library to load the actor without
    validation issues.
    Defaults to `TOOL`.
    Args:
        actor (str): The input actor.
    Returns:
        str: The normalized actor.
    """
    if not actor.upper().startswith(
        ("TOOL: ", "ORGANIZATION: ", "PERSON: ", "NOASSERTION")
    ):
        return "Tool: " + actor
    return actor


async def normalize_package(package: dict[str, Any]) -> None:
    """
    Adds necessary fields to an SPDX Package to be loaded by the
    SPDX library without validation issues.
    Args:
        package (dict[str, Any]): The package to be normalized.

    Returns:
        None: Nothing, changes are performed in-place.
    """
    if "downloadLocation" not in package:
        package["downloadLocation"] = "NOASSERTION"
    if "name" not in package:
        package["name"] = ""
    if supplier := package.get("supplier"):
        package["supplier"] = await normalize_actor(supplier)


async def normalize_sbom(
    sbom: dict[str, Any], append_mobster_creator: bool = True
) -> None:
    """
    Adds necessary fields to an SPDX SBOM to be loaded by the
    SPDX library without validation issues.
    Args:
        sbom: The SBOM to be normalized.
        append_mobster_creator: If Mobster should append its name as one of
                               the creators of the SBOM.

    Returns:
        None: Nothing, changes are performed in-place.
    """
    if "SPDXID" not in sbom:
        sbom["SPDXID"] = "SPDXRef-DOCUMENT"
    if "dataLicense" not in sbom:
        sbom["dataLicense"] = "CC0-1.0"
    if "spdxVersion" not in sbom:
        sbom["spdxVersion"] = "SPDX-2.3"
    if "name" not in sbom:
        sbom["name"] = "MOBSTER:UNFILLED_NAME (please update this field)"
    if "documentNamespace" not in sbom:
        sbom["documentNamespace"] = get_namespace(sbom["name"])

    creation_info = sbom.get("creationInfo", {})
    if "created" not in creation_info:
        creation_info["created"] = "1970-01-01T00:00:00Z"
    creators = creation_info.get("creators", [])
    new_creators = [await normalize_actor(creator) for creator in creators]
    if append_mobster_creator:
        new_creators.append(get_mobster_tool_string())
    creation_info["creators"] = new_creators
    sbom["creationInfo"] = creation_info

    for package in sbom.get("packages", []):
        await normalize_package(package)


async def normalize_and_load_sbom(
    sbom: dict[str, Any], append_mobster: bool = True
) -> Document:
    """
    Normalize and load the SPDX SBOM.
    Args:
        sbom: The SBOM dict to normalize and load.
        append_mobster: If Mobster should append its name as one of
                               the creators of the SBOM.
    Returns:
        Loaded SPDX SBOM object.
    """
    await normalize_sbom(sbom, append_mobster)
    return JsonLikeDictParser().parse(sbom)  # type: ignore[no-untyped-call]


async def update_sbom_name_and_namespace(sbom: Document, image: Image) -> None:
    """
    Update the SBOM name with the image reference in the format 'repository@digest'.
    Also update its namespace using the same value and Konflux URL.
    Args:
        sbom (spdx_tools.spdx.model.document.Document): The SBOM
        image (Image): The main image

    Returns:
        None: Nothing, changes are performed in-place.
    """
    name = f"{image.repository}@{image.digest}"
    sbom.creation_info.name = name
    sbom.creation_info.document_namespace = get_namespace(name)


async def find_spdx_root_relationships(sbom: Document) -> list[Relationship]:
    """
    Finds the relationship describing the root element.
    Args:
        sbom (spdx_tools.spdx.model.document.Document): The SBOM

    Returns:
        spdx_tools.spdx.model.relationship.Relationship: The root relationship
    """
    relationships = []
    for relationship in sbom.relationships:
        for relationship_type in (
            RelationshipType.DESCRIBES,
            RelationshipType.DESCRIBED_BY,
        ):
            # The root element is either DESCRIBED_BY SPDXRef-DOCUMENT
            # or SPDXRef-DOCUMENT DESCRIBES the root element
            if relationship.relationship_type is relationship_type:
                relationships.append(relationship)
    return relationships


async def find_spdx_root_packages_spdxid(sbom_doc: Document) -> list[str]:
    """
    Finds the root element of an SPDX SBOM and returns its SPDXID.
    Args:
        sbom_doc (spdx_tools.spdx.model.document.Document): The SBOM

    Returns:
        list[str]: The SPDXID of the root package
    """
    spdx_ids = set()
    root_relationships = await find_spdx_root_relationships(sbom_doc)
    for root_relationship in root_relationships:
        if (
            root_relationship.relationship_type is RelationshipType.DESCRIBES
            and isinstance(root_relationship.related_spdx_element_id, str)
        ):
            spdx_ids.add(root_relationship.related_spdx_element_id)
        elif isinstance(root_relationship.spdx_element_id, str):
            spdx_ids.add(root_relationship.spdx_element_id)
    return list(spdx_ids)


async def find_spdx_root_packages(sbom: Document) -> list[Package]:
    """
    Finds the root element of an SPDX SBOM and returns its object representation.
    Args:
        sbom (spdx_tools.spdx.model.document.Document): The SBOM

    Returns:
        list[spdx_tools.spdx.model.package.Package]: The root package
    """
    packages = []
    root_spdxids = set(await find_spdx_root_packages_spdxid(sbom))
    for package in sbom.packages:
        if package.spdx_id in root_spdxids:
            packages.append(package)
    return packages


async def is_virtual_root(package: Package) -> bool:
    """
    Check if the package is a virtual root - usually a package with empty values.

    For example:

        {
            "SPDXID": "SPDXRef-DocumentRoot-Unknown",
            "name": "",
            "versionInfo": ""
        }

        {
            "SPDXID": "SPDXRef-DocumentRoot-Directory-.-some-directory",
            "name": "./some-directory",
            "versionInfo": ""
        }

    Args:
        package (spdx_tools.spdx.model.package.Package):
            A package element from the SBOM.

    Returns:
        bool: A boolean indicating if the package is a virtual root.
    """
    package_name = package.name
    return not package_name or package_name.startswith((".", "/"))


def is_syft_oci_image_root(package: Package) -> bool:
    """
    Check if the package is a Syft OCI image root package.

    Syft creates a root package for OCI images with specific naming patterns.

    Args:
        package (spdx_tools.spdx.model.package.Package):
            A package element from the SBOM.
    """
    return package.spdx_id.startswith("SPDXRef-DocumentRoot-Image-")


async def redirect_spdx_virtual_root_to_new_root(
    sbom: Document, virtual_root_id: str, new_root_id: str
) -> None:
    """
    Redirect the relationship describing the document to a new root node.
    Args:
        sbom (spdx_tools.spdx.model.document.Document): The SBOM
        virtual_root_id (str): SPDX ID of the virtual root (to be replaced)
        new_root_id (str): SPDX ID of the new root (will replace the old one)

    Returns:
        None: Nothing, changes are performed in-place.
    """
    for relationship in sbom.relationships:
        if relationship.spdx_element_id == virtual_root_id:
            relationship.spdx_element_id = new_root_id

        if relationship.related_spdx_element_id == virtual_root_id:
            relationship.related_spdx_element_id = new_root_id


async def redirect_current_roots_to_new_root(
    sbom: Document, new_root_spdx_id: str
) -> None:
    """
    Redirect all the current root nodes to a new root node.

    Args:
        sbom (dict): SBOM in JSON format.
        new_root_spdx_id (str): New root node identifier.

    Returns:
        dict: Updated SBOM with the new root node identifier.
    """
    current_roots = await find_spdx_root_packages(sbom)
    for current_root in current_roots:
        if await is_virtual_root(current_root) or is_syft_oci_image_root(current_root):
            # In case the document is described by the virtual root node
            # let's remove it and replace it with the new root node

            # Remove the virtual root node from the packages list
            sbom.packages.remove(current_root)

            # Redirect the existing relationship to the new root node
            await redirect_spdx_virtual_root_to_new_root(
                sbom, current_root.spdx_id, new_root_spdx_id
            )
        else:
            # Make an edge between the new root node and the current root node
            new_relationship = Relationship(
                spdx_element_id=new_root_spdx_id,
                relationship_type=RelationshipType.CONTAINS,
                related_spdx_element_id=current_root.spdx_id,
            )
            sbom.relationships.append(new_relationship)

    # Update the edge between document and the new edge
    for old_root_relationship in await find_spdx_root_relationships(sbom):
        sbom.relationships.remove(old_root_relationship)
    sbom.relationships.append(
        Relationship(
            relationship_type=RelationshipType.DESCRIBES,
            spdx_element_id="SPDXRef-DOCUMENT",
            related_spdx_element_id=new_root_spdx_id,
        )
    )


async def update_package_in_spdx_sbom(
    sbom: Document, image: Image, is_builder_image: bool
) -> Document:
    """
    Update the SPDX SBOM with the image reference.

    The reference to the image is added to the SBOM in the form of a package and
    appropriate relationships are added to the SBOM.

    Args:
        sbom (dict): SBOM in JSON format.
        image (Image): An instance of the Image class that represents the image.
        is_builder_image (bool): Is the image used in a builder stage for the component?

    Returns:
        dict: Updated SBOM with the image reference added.
    """
    package = get_image_package(image, image.propose_spdx_id())

    sbom.packages.insert(0, package)
    if is_builder_image:
        # Append the builder image package to the packages list

        annotation = Annotation(
            spdx_id=package.spdx_id,
            annotation_type=AnnotationType.OTHER,
            annotator=Actor(actor_type=ActorType.TOOL, name="konflux:jsonencoded"),
            annotation_comment=json.dumps(
                BUILDER_IMAGE_PROPERTY,
                separators=(",", ":"),
            ),
            annotation_date=datetime.now(timezone.utc),
        )
        sbom.annotations.append(annotation)
        root_spdxids = await find_spdx_root_packages_spdxid(sbom)
        # Add the relationship between the builder image and the package
        for root_spdxid in root_spdxids:
            sbom.relationships.append(
                Relationship(
                    spdx_element_id=package.spdx_id,
                    relationship_type=RelationshipType.BUILD_TOOL_OF,
                    related_spdx_element_id=root_spdxid,
                )
            )
    else:
        # Check existing relationships and redirect the current roots to the new root
        await redirect_current_roots_to_new_root(sbom, package.spdx_id)
    return sbom


def get_package_by_spdx_id(doc: Document, spdx_id: str) -> Package | None:
    """
    Gets package by spdx id from document.

    Args:
        doc (Document): The SPDX SBOM document to search in.
        spdx_id (str): The SPDX SBOM ID to search for.

    Returns:
        Package | None: The package with the given spdx id, or None if not found.
    """
    return next(
        (pkg for pkg in doc.packages if pkg.spdx_id == spdx_id),
        None,
    )


def get_annotations_by_spdx_id(doc: Document, spdx_id: str) -> list[Annotation]:
    """
    Gets all annotations with the given spdx id from document.

    Args:
        doc (Document): The SPDX SBOM document to search in.
        spdx_id (str): The SPDX SBOM ID to search for.

    Returns:
        list[Annotation]: The list of all annotations with the given spdx id.
    """
    return [annot for annot in doc.annotations if annot.spdx_id == spdx_id]


class AnnotationParseError(Exception):
    """An error occurred during parsing of a Konflux annotation."""


class AnnotationIntermediateImage:
    """
    Parsed Konflux intermediate image annotation.

    Attributes:
        stage_index: index of the stage the intermediate image is created in
    """

    name = "konflux:container:is_intermediate_image:for_stage"

    def __init__(self, stage_index: int) -> None:
        self.stage_index = stage_index


class AnnotationBuilderImage:
    """
    Parsed Konflux builder image annotation.

    Attributes:
        stage_index: index of the stage the builder image is a base for
    """

    name = "konflux:container:is_builder_image:for_stage"

    def __init__(self, stage_index: int) -> None:
        self.stage_index = stage_index


class AnnotationBaseImage:
    """
    Parsed Konflux base image annotation. Empty, because its presence already
    signals a base image.
    """

    name = "konflux:container:is_base_image"


class KonfluxAnnotationManager:
    """
    Group of convenience methods for creating and parsing Konflux annotations
    in SPDX SBOMs.
    """

    @staticmethod
    def _make_annotation(spdx_id: str, comment: dict[Any, Any]) -> Annotation:
        return Annotation(
            spdx_id=spdx_id,
            annotator=KONFLUX_JSON_ACTOR,
            annotation_type=AnnotationType.OTHER,
            annotation_date=datetime.now(),
            annotation_comment=json.dumps(comment),
        )

    @staticmethod
    def intermediate_image(spdx_id: str, stage_index: int) -> Annotation:
        """
        Create an SPDX Annotation object for an intermediate image package.

        Args:
            spdx_id: SPDX ID of the package to annotate
            stage_index: Build stage index for the intermediate image

        Returns:
            Annotation object marking the package as an intermediate image
        """
        comment = {
            "name": AnnotationIntermediateImage.name,
            "value": str(stage_index),
        }
        return KonfluxAnnotationManager._make_annotation(spdx_id, comment)

    @staticmethod
    def builder_image(spdx_id: str, stage_index: int) -> Annotation:
        """
        Create an SPDX Annotation object for a builder image package.

        Args:
            spdx_id: SPDX ID of the package to annotate
            stage_index: Build stage index for the builder image

        Returns:
            Annotation object marking the package as a builder image
        """
        comment = {
            "name": AnnotationBuilderImage.name,
            "value": str(stage_index),
        }

        return KonfluxAnnotationManager._make_annotation(spdx_id, comment)

    @staticmethod
    def base_image(spdx_id: str) -> Annotation:
        """
        Create an SPDX Annotation object for a base image package.

        Args:
            spdx_id: SPDX ID of the package to annotate

        Returns:
            Annotation object marking the package as a base image
        """
        comment = {
            "name": AnnotationBaseImage,
            "value": "true",
        }

        return KonfluxAnnotationManager._make_annotation(spdx_id, comment)

    @staticmethod
    def parse(
        ann: Annotation,
    ) -> (
        None
        | AnnotationIntermediateImage
        | AnnotationBuilderImage
        | AnnotationBaseImage
    ):
        """
        Parse an SPDX annotation document and return the internal
        representation or return None if it's not a Konflux annotation.

        Args:
            ann: SPDX annotation to parse

        Raises:
            AnnotationParseError: when the annotation could not be decoded
        """
        if ann.annotator != KONFLUX_JSON_ACTOR:
            return None

        decoded = json.loads(ann.annotation_comment)
        try:
            if decoded["name"] == AnnotationIntermediateImage.name:
                stage_index = int(decoded["value"])
                return AnnotationIntermediateImage(stage_index)

            if decoded["name"] == AnnotationBuilderImage.name:
                stage_index = int(decoded["value"])
                return AnnotationBuilderImage(stage_index)

            if decoded["name"] == AnnotationBaseImage.name:
                return AnnotationBaseImage()

        except (KeyError, ValueError) as exc:
            raise AnnotationParseError(
                "Could not decode a Konflux annotation."
            ) from exc

        raise AnnotationParseError("Unrecognized Konflux annotation.")


@dataclass
class PackageContext:
    """
    Dataclass containing data relevant to an SPDX package.

    Attributes:
        pkg: the underlying SPDX package object
        parent_relationships: list of SPDX relationships where the underlying
            package is the "parent": pkg.spdx_id == relationship.spdx_element_id
        annotations: list of SPDX annotations for this package
    """

    pkg: Package
    parent_relationships: list[Relationship] = field(default_factory=list)
    annotations: list[Annotation] = field(default_factory=list)

    T = TypeVar("T")

    def _annotation(self, ann_type: type[T]) -> T | None:
        for ann in self.annotations:
            try:
                parsed = KonfluxAnnotationManager.parse(ann)
                if isinstance(parsed, ann_type):
                    return parsed
            except AnnotationParseError:
                continue

        return None

    @property
    def builder_image_annotation(self) -> AnnotationBuilderImage | None:
        """
        Get the builder image annotation for this package if present.
        """
        return self._annotation(AnnotationBuilderImage)

    @property
    def intermediate_image_annotation(self) -> AnnotationIntermediateImage | None:
        """
        Get the intermediate image annotation for this package if present.
        """
        return self._annotation(AnnotationIntermediateImage)

    def filter_parent_relationships(
        self, rel_type: RelationshipType
    ) -> list[Relationship]:
        """
        Return a list of parent relationships associated with this package
        filtered by the passed relationship type.
        """
        return [
            rel
            for rel in self.parent_relationships
            if rel.relationship_type == rel_type
        ]


class DocumentIndexOCI:
    """
    Index object wrapping an SPDX document for implementing methods for faster
    lookups.

    Attributes:
        doc (Document): the underlying SPDX Document object
    """

    def __init__(self, doc: Document) -> None:
        """
        Initialize the document index from an SPDX document.

        Builds internal lookup structures for fast access to packages by
        SPDX ID, PURL, and identifies image packages.

        Args:
            doc: SPDX document to index
        """
        self.doc: Document = doc
        self._spdx_id_to_ctx: dict[str, PackageContext] = {}
        self._purl_to_ctxs: dict[str, list[PackageContext]] = defaultdict(list)
        self._image_ctxs: list[PackageContext] = []

        for pkg in self.doc.packages:
            pkg_ctx = PackageContext(
                pkg=pkg,
            )

            self._spdx_id_to_ctx[pkg.spdx_id] = pkg_ctx

            purl = get_package_purl(pkg)
            if purl is not None:
                self._purl_to_ctxs[purl].append(pkg_ctx)

            if pkg.spdx_id.startswith(IMAGE_PKG_SPDX_PREFIX):
                self._image_ctxs.append(pkg_ctx)

        for rel in self.doc.relationships:
            if rel.spdx_element_id == DOC_ELEMENT_ID:
                continue

            pkg_ctx = self._spdx_id_to_ctx[rel.spdx_element_id]
            pkg_ctx.parent_relationships.append(rel)

        for ann in self.doc.annotations:
            pkg_ctx = self._spdx_id_to_ctx[ann.spdx_id]
            pkg_ctx.annotations.append(ann)

    def try_package_by_spdx_id(self, spdx_id: str) -> PackageContext | None:
        """
        Return a package from the document by SPDX ID if it exists, otherwise
        returns None.
        """
        return self._spdx_id_to_ctx.get(spdx_id)

    def package_by_spdx_id(self, spdx_id: str) -> PackageContext:
        """
        Return a package from the document by SPDX ID if it exists, otherwise
        raises a KeyError.

        Should only be used when this is unlikely to happen, e.g. tests.

        Args:
            spdx_id: SPDX ID to search for

        Returns:
            PackageContext for the package with the given SPDX ID

        Raises:
            KeyError: if no package with the given SPDX ID exists
        """
        return self._spdx_id_to_ctx[spdx_id]

    def packages_by_purl(self, purl: str) -> list[PackageContext]:
        """
        Return packages from the document by a Package URL string.

        To qualify, a package must have at least one PURL external reference
        that matches the passed purl.

        Args:
            purl: Package URL string to search for

        Returns:
            List of PackageContext objects with matching PURLs, or empty list
            if none found
        """
        return self._purl_to_ctxs.get(purl, [])

    def package_contexts(
        self,
    ) -> Generator[PackageContext, None, None]:
        """
        Generator yielding PackageContexts present in the underlying document.

        Returns:
            Generator yielding all PackageContext objects in the document
        """
        yield from self._spdx_id_to_ctx.values()

    def image_packages(self) -> list[PackageContext]:
        """
        Returns a list of SPDX packages representing OCI images in the
        underlying document.
        """
        return self._image_ctxs

    def image_package_by_pullspec(self, pullspec: str) -> PackageContext | None:
        """
        Returns a PackageContext for a builder OCI image package in the
        underlying document based on matching the passed pullspec.

        Args:
            pullspec: Container image pullspec to match against

        Returns:
            PackageContext for matching builder image package, or None if not found
        """
        for img_pkg_ctx in self._image_ctxs:
            if img_pkg_ctx.builder_image_annotation is None:
                continue

            if DocumentIndexOCI._match_image_package(img_pkg_ctx.pkg, pullspec):
                return img_pkg_ctx

        return None

    def ensure_intermediate_image_package(
        self, builder_package_context: PackageContext
    ) -> PackageContext:
        """
        Returns an intermediate package context equivalent for the passed
        builder package context if it already exists in the SBOM.

        If it doesn't exist, a new package is created and added to the SBOM.

        Args:
            builder_package_context: Builder package context to create
                intermediate equivalent for

        Returns:
            PackageContext for the intermediate image package

        Raises:
            MissingBuilderAnnotation: if the builder package context lacks a
                builder annotation
        """

        # determine whether the intermediate package already exists
        for img_pkg_ctx in self._image_ctxs:
            if img_pkg_ctx.intermediate_image_annotation is None:
                continue

            for rel in img_pkg_ctx.filter_parent_relationships(
                RelationshipType.DESCENDANT_OF
            ):
                if rel.related_spdx_element_id == builder_package_context.pkg.spdx_id:
                    return img_pkg_ctx

        # it doesn't exist, create a new intermediate image package and its
        # associated relationships and annotation
        int_img_pkg = Package(
            spdx_id=f"{builder_package_context.pkg.spdx_id}-intermediate",
            name=f"{builder_package_context.pkg.name}-intermediate",
            files_analyzed=False,
            download_location=SpdxNoAssertion(),
        )

        # intermediate image packages are DESCENDANT_OF builder image packages.
        # create the relationship and update the builder image package's child
        # relationships.
        rel = Relationship(
            spdx_element_id=int_img_pkg.spdx_id,
            related_spdx_element_id=builder_package_context.pkg.spdx_id,
            relationship_type=RelationshipType.DESCENDANT_OF,
        )

        # the stage index for the intermediate package annotation is copied
        # from the builder image annotation
        builder_ann = builder_package_context.builder_image_annotation
        if builder_ann is None:
            raise MissingBuilderAnnotation(
                "Image package is missing a builder annotation: "
                f"{builder_package_context.pkg.spdx_id}"
            )

        ann = KonfluxAnnotationManager.intermediate_image(
            int_img_pkg.spdx_id, builder_ann.stage_index
        )

        # update the underlying document with the new objects
        self.doc.annotations.append(ann)
        self.doc.relationships.append(rel)
        self.doc.packages.append(int_img_pkg)

        # update the index with the new objects
        int_img_ctx = PackageContext(
            pkg=int_img_pkg,
            parent_relationships=[rel],
            annotations=[ann],
        )
        self._spdx_id_to_ctx[int_img_pkg.spdx_id] = int_img_ctx
        self._image_ctxs.append(int_img_ctx)

        return int_img_ctx

    @staticmethod
    def _match_image_package(img_pkg: Package, pullspec: str) -> bool:
        """
        Returns true if the passed Package represents an image with the passed
        pullspec.
        """
        img_purl_str = get_package_purl(img_pkg)
        if img_purl_str is None:
            return False

        img_purl = PackageURL.from_string(img_purl_str)
        if not isinstance(img_purl.qualifiers, dict):
            return False

        img_pullspec = f"{img_purl.qualifiers['repository_url']}@{img_purl.version}"
        if img_pullspec == pullspec:
            return True

        return False

    def reparent_relationship(
        self, relationship: Relationship, new_parent_spdx_id: str
    ) -> bool:
        """
        Change the spdx_element_id of the passed relationship to the
        new_parent_spdx_id and update the index for internal consistency.

        Args:
            relationship: The SPDX relationship to reparent
            new_parent_spdx_id: The SPDX ID of the new parent element

        Returns:
            True on success, False when the operation could not be done because
            of an invalid SBOM.

        Example:
            Before reparenting:
                SPDXRef-ImageA CONTAINS SPDXRef-Package1

            After reparenting relationship to SPDXRef-ImageB:
                SPDXRef-ImageB CONTAINS SPDXRef-Package1

            The CONTAINS relationship is moved from ImageA to ImageB, changing
            which container image is considered the parent of Package1 in the SBOM.
        """

        # To ensure consistency of the index, we need to find the package
        # whose parent is going to be changing and remove the relationship
        # from the parent_relationships for that package.
        old_parent_pkg_ctx = self.package_by_spdx_id(relationship.spdx_element_id)
        if old_parent_pkg_ctx is None:
            return False

        idx = None
        for i, rel in enumerate(old_parent_pkg_ctx.parent_relationships):
            if rel.related_spdx_element_id == relationship.related_spdx_element_id:
                idx = i
                break

        if idx is None:
            return False

        old_parent_pkg_ctx.parent_relationships.pop(idx)

        # reparent the relationship
        new_parent_pkg_ctx = self.package_by_spdx_id(new_parent_spdx_id)
        if new_parent_pkg_ctx is None:
            return False

        new_parent_pkg_ctx.parent_relationships.append(relationship)
        relationship.spdx_element_id = new_parent_spdx_id
        return True
