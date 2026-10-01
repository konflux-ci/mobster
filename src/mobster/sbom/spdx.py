"""A module for SPDX SBOM format"""

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from packageurl import PackageURL
from spdx_tools.spdx.model.actor import Actor, ActorType
from spdx_tools.spdx.model.annotation import Annotation, AnnotationType
from spdx_tools.spdx.model.checksum import Checksum, ChecksumAlgorithm
from spdx_tools.spdx.model.document import CreationInfo, Document
from spdx_tools.spdx.model.package import (
    ExternalPackageRef,
    ExternalPackageRefCategory,
    Package,
)
from spdx_tools.spdx.model.relationship import Relationship, RelationshipType
from spdx_tools.spdx.model.spdx_no_assertion import SpdxNoAssertion
from spdx_tools.spdx.model.spdx_none import SpdxNone
from spdx_tools.spdx.parser.jsonlikedict.json_like_dict_parser import JsonLikeDictParser

from mobster import get_mobster_version
from mobster.artifact import Artifact
from mobster.image import Image
from mobster.release import ReleaseId

DOC_ELEMENT_ID = "SPDXRef-DOCUMENT"


def get_root_package_relationship(spdx_id: str) -> Relationship:
    """Get a relationship for the root package in relation to the SPDX document.

    Args:
        spdx_id: An SPDX ID for the root package.

    Returns:
        Relationship: An object representing the relationship for the root package.
    """
    return Relationship(
        spdx_element_id=DOC_ELEMENT_ID,
        relationship_type=RelationshipType.DESCRIBES,
        related_spdx_element_id=spdx_id,
    )


def get_namespace(sbom_name: str) -> str:
    """
    Create a namespace for the SBOM using its name
    and a Konflux URL.
    Args:
        sbom_name (str): Name of the SBOM

    Returns:
        str: The generated documentNamespace
    """
    return f"https://konflux-ci.dev/spdxdocs/{sbom_name}-{uuid4()}"


def get_creation_info(sbom_name: str) -> CreationInfo:
    """Create the creation information for the SPDX document.

    Args:
        sbom_name: The name for the SBOM document.

    Returns:
        CreationInfo: A creation information object for the SPDX document.
    """
    return CreationInfo(
        spdx_version="SPDX-2.3",
        spdx_id=DOC_ELEMENT_ID,
        name=sbom_name,
        data_license="CC0-1.0",
        document_namespace=get_namespace(sbom_name),
        creators=[
            get_red_hat_org_actor(),
            Actor(ActorType.TOOL, "Konflux CI"),
            get_mobster_tool_actor(),
        ],
        created=datetime.now(timezone.utc),
    )


def get_image_package(
    image: Image, spdx_id: str, package_name: str | None = None
) -> Package:
    """Transform the parsed image object into SPDX package object.

    Args:
        image: A parsed image object.
        spdx_id: An SPDX ID for the image.
        package_name: An optional package name. The image name and architecture
            will be used if not provided.

    Returns:
        Package: A package object representing the OCI image.
    """
    if not package_name:
        package_name = image.name if not image.arch else f"{image.name}_{image.arch}"

    return get_package(
        spdx_id,
        name=package_name,
        version=image.tag,
        external_refs=[
            ExternalPackageRef(
                category=ExternalPackageRefCategory.PACKAGE_MANAGER,
                reference_type="purl",
                locator=image.purl_str(),
            )
        ],
        checksums=[
            Checksum(
                algorithm=ChecksumAlgorithm.SHA256,
                value=image.digest_hex_val,
            )
        ],
    )


def get_package_from_artifact(artifact: Artifact) -> Package:
    """Transform the parsed artifact object into SPDX package object.

    Args:
        artifact: A parsed artifact object.

    Returns:
        Package: A package object representing the artifact.
    """
    return get_package(
        spdx_id=artifact.propose_spdx_id(),
        name=artifact.filename,
        download_location=artifact.source,
        external_refs=[
            ExternalPackageRef(
                category=ExternalPackageRefCategory.PACKAGE_MANAGER,
                reference_type="purl",
                locator=artifact.purl_str(),
            )
        ],
        checksums=[
            Checksum(
                algorithm=ChecksumAlgorithm.SHA256,
                value=artifact.sha256sum,
            )
        ],
    )


# pylint: disable=too-many-arguments,too-many-positional-arguments
def get_package(
    spdx_id: str,
    name: str,
    external_refs: list[ExternalPackageRef],
    checksums: list[Checksum],
    version: str | None = None,
    download_location: str | SpdxNoAssertion | SpdxNone | None = None,
) -> Package:
    """Create an SPDX package from input data.

    Args:
        spdx_id: An SPDX ID of the package.
        name: Name field of the package.
        external_refs: List of SPDX external references.
        checksums: List of SPDX checksums.
        version: Version field of the package.
        download_location: Package download location. If not provided,
            SpdxNoAssertion is used.

    Returns:
        Package: An SPDX package object.
    """
    if download_location is None:
        download_location = SpdxNoAssertion()

    return Package(
        spdx_id=spdx_id,
        name=name,
        version=version,
        download_location=download_location,
        supplier=get_red_hat_org_actor(),
        license_declared=SpdxNoAssertion(),
        files_analyzed=False,
        external_references=external_refs,
        checksums=checksums,
    )


def get_release_id_annotation(release_id: ReleaseId) -> Annotation:
    """
    Create an SPDX annotation with release_id
    """
    return Annotation(
        spdx_id=DOC_ELEMENT_ID,
        annotation_date=datetime.now(timezone.utc),
        annotation_type=AnnotationType.OTHER,
        annotator=get_mobster_tool_actor(),
        annotation_comment=f"release_id={str(release_id)}",
    )


def get_mobster_tool_actor() -> Actor:
    """
    Get the Actor object representation of the current mobster tool.
    """
    return Actor(ActorType.TOOL, f"Mobster-{get_mobster_version()}")


def get_mobster_tool_string() -> str:
    """
    Get the string representation of the current mobster tool.
    """
    return str(get_mobster_tool_actor())


def get_red_hat_org_actor() -> Actor:
    """
    Get the Actor object representation of Red Hat organization.
    """
    return Actor(ActorType.ORGANIZATION, "Red Hat")


def get_red_hat_org_string() -> str:
    """
    Get the string representation of the Red Hat organization creator.
    """
    return str(get_red_hat_org_actor())


def get_package_purl(package: Package) -> str | None:
    """
    The purl of a package (external reference of category PACKAGE-MANAGER and purl type)

    Args:
        package: The package to find the purl of.

    Returns:
        The purl of the given package or None.
    """
    for ref in package.external_references:
        if (
            ref.category == ExternalPackageRefCategory.PACKAGE_MANAGER
            and ref.reference_type == "purl"
        ):
            return ref.locator
    return None


def normalize_actor(actor: str) -> str:
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


def normalize_red_hat_creator(creators: list[str]) -> list[str]:
    """
    Ensure exactly one canonical "Organization: Red Hat" entry is present in
    the creators list. Any case-insensitive variant (e.g. "Organization: red hat")
    is removed and replaced with the correct form.

    Args:
        creators: The list of SPDX creator strings to normalize.

    Returns:
        list[str]: Updated creators list with the canonical Red Hat entry.
    """
    red_hat_org = get_red_hat_org_string()
    result = [c for c in creators if c.lower() != red_hat_org.lower()]
    result.append(red_hat_org)
    return result


def normalize_package(package: dict[str, Any]) -> None:
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
        package["supplier"] = normalize_actor(supplier)


def get_normalized_purl(purl: str) -> str:
    """
    Get a normalized purl by only including fields that are valid for
    comparison.

    Args:
        purl: purl string to normalize

    Returns
        str: the normalized purl string
    """

    purl_obj = PackageURL.from_string(purl)
    normalized = PackageURL(
        name=purl_obj.name,
        type=purl_obj.type,
        version=purl_obj.version,
        namespace=purl_obj.namespace,
    )
    return normalized.to_string()


def normalize_sbom(sbom: dict[str, Any], append_mobster_creator: bool = True) -> None:
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
    new_creators = [normalize_actor(creator) for creator in creators]
    new_creators = normalize_red_hat_creator(new_creators)
    if append_mobster_creator:
        new_creators.append(get_mobster_tool_string())
    creation_info["creators"] = new_creators
    sbom["creationInfo"] = creation_info

    for package in sbom.get("packages", []):
        normalize_package(package)


def normalize_and_load_sbom(
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
    normalize_sbom(sbom, append_mobster)
    return JsonLikeDictParser().parse(sbom)  # type: ignore[no-untyped-call]


def _serialize_relationship(
    relationship: Relationship,
) -> tuple[str, RelationshipType, str, str | None]:
    if (
        isinstance(relationship.related_spdx_element_id, str)
        or relationship.related_spdx_element_id is None
    ):
        related_serialized = relationship.related_spdx_element_id
    else:
        related_serialized = str(relationship.related_spdx_element_id)
    return (
        relationship.spdx_element_id,
        relationship.relationship_type,
        related_serialized,
        relationship.comment,
    )


def deduplicate_relationships(relationships: list[Relationship]) -> list[Relationship]:
    """
    Deduplicates relationships in SBOM.
    Useful for example if it used to contain multiple
    virtual roots which are all replaced
    (creates duplicate relationships).
    Args:
        relationships: The relationships to be deduplicated.

    Returns:
        The deduplicated relationships. Does not
        modify in-place.
    """
    new_relationships = []
    already_present_relationships = set()
    for relationship in relationships:
        if (
            new_relationship_serialized := _serialize_relationship(relationship)
        ) not in already_present_relationships:
            new_relationships.append(relationship)
            already_present_relationships.add(new_relationship_serialized)
    return new_relationships
