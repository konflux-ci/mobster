from pathlib import Path

import pytest
from pytest_lazy_fixtures import lf
from spdx_tools.spdx.model.package import Package
from spdx_tools.spdx.model.relationship import RelationshipType
from spdx_tools.spdx.model.spdx_no_assertion import SpdxNoAssertion
from spdx_tools.spdx.parser.parse_anything import parse_file

from mobster.cmd.generate.oci_image.contextual_sbom.constants import (
    ANCESTOR_IMAGE,
    BASE_IMAGE,
    BUILDER_IMAGE,
    INTERMEDIATE_IMAGE,
)
from tests.integration.img_utils import make_metadata_yaml
from tests.integration.oci_client import ReferrersTagOCIClient
from tests.integration.oci_image.conftest import (
    GenerateData,
    SBOMPackage,
    run_mobster_generate,
    verify_content_item,
    verify_image_item,
    verify_packages_not_included,
    verify_sbom_relationships,
)
from tests.spdx_builder import AnnotatedPackage


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ["contextualize_parent"],
    [
        pytest.param(True, id="contextualized-parent"),
        pytest.param(False, id="non-contextualized-parent"),
    ],
)
@pytest.mark.parametrize(
    ["deep_grandparent", "grandparent_input"],
    [
        pytest.param(True, lf("grandparent_input_sbom_deep"), id="deep-grandparent"),
        pytest.param(False, lf("grandparent_input_sbom"), id="shallow-grandparent"),
    ],
)
async def test_parent_content_contextualization(
    oci_client: ReferrersTagOCIClient,
    tmp_path: Path,
    grandparent_packages: list[AnnotatedPackage],
    parent_packages: list[AnnotatedPackage],
    parent_only_packages: list[AnnotatedPackage],
    component_packages: list[AnnotatedPackage],
    grandparent_input: Path,
    deep_grandparent: bool,
    contextualize_parent: bool,
    parent_input_sbom: Path,
    component_input_sbom: Path,
) -> None:
    """
    Test the parent content contextualization in 'mobster generate oci-image' by
    generating three SBOMs (grandparent, parent, component). All three input
    SBOMs share grandparent packages, parent and component share some packages
    and some packages are component-only.

    This test verifies that after these three mobster calls, the final
    component SBOM has its package relationships updated to reflect the true
    origin of packages.

    In some cases tests what happens when a grandparent is "deep", i.e. it is
    itself a child image of another image (represented by a BUILD_TOOL_OF
    relationship in the grandparent SBOM)

    It also verifies that the packages found in the parent but not the
    component (parent only packages) are excluded from the contextualized
    component SBOM.
    """

    grandparent_img = await oci_client.create_image("grandparent", "latest")
    parent_img = await oci_client.create_image("parent", "latest")
    component_img = await oci_client.create_image("component", "latest")

    grandparent_gdata = GenerateData(
        image=grandparent_img,
        input_sbom_path=grandparent_input,
        output_sbom_path=tmp_path / "grandparent.output.spdx.json",
    )

    run_mobster_generate(grandparent_gdata)

    with open(grandparent_gdata.output_sbom_path, "rb") as f:
        await oci_client.attach_sbom(grandparent_img, "spdx", f.read())

    parent_gdata = GenerateData(
        metadata_path=make_metadata_yaml(
            tmp_path, parent_img, base_img=grandparent_img
        ),
        input_sbom_path=parent_input_sbom,
        output_sbom_path=tmp_path / "parent.output.spdx.json",
        contextualize=contextualize_parent,
    )

    run_mobster_generate(parent_gdata)

    with open(parent_gdata.output_sbom_path, "rb") as f:
        await oci_client.attach_sbom(parent_img, "spdx", f.read())

    if contextualize_parent:
        expected_package_groups = [
            parent_packages + parent_only_packages,
            grandparent_packages,
        ]
        # if the grandparent is deep, we expect another element in the
        # dependency chain (the grandgrandparent), but it has no packages
        if deep_grandparent:
            expected_package_groups.append([])
    else:
        expected_package_groups = [
            parent_packages + parent_only_packages + grandparent_packages,
            [],  # no grandparent-specific packages - we're not contextualizing
        ]

    verify_sbom_relationships(
        parent_gdata.output_sbom_path,
        expected_package_groups,
    )

    component_gdata = GenerateData(
        input_sbom_path=component_input_sbom,
        output_sbom_path=tmp_path / "component.output.spdx.json",
        metadata_path=make_metadata_yaml(tmp_path, component_img, base_img=parent_img),
    )

    run_mobster_generate(component_gdata)

    if contextualize_parent:
        expected_package_groups = [
            component_packages,
            parent_packages,  # no parent-only packages, they have been removed
            grandparent_packages,
        ]
        if deep_grandparent:
            # if the grandparent is deep, we expect another element in the
            # dependency chain (the grandgrandparent), but it has no packages
            expected_package_groups.append([])
    else:
        expected_package_groups = [
            component_packages,
            parent_packages + grandparent_packages,
            [],  # no packages specific to grandparent, parent was not contextualized
        ]

    verify_sbom_relationships(
        component_gdata.output_sbom_path,
        expected_package_groups,
    )

    verify_packages_not_included(
        component_gdata.output_sbom_path,
        parent_only_packages,
    )


@pytest.mark.asyncio
async def test_inheriting_builder_image_packages_from_parent(
    oci_client: ReferrersTagOCIClient,
    tmp_path: Path,
    parent_packages: list[AnnotatedPackage],
    component_packages: list[AnnotatedPackage],
    parent_builder_content_pkg: SBOMPackage,
    parent_builder_image_package: AnnotatedPackage,
    parent_intermediate_content_pkg: SBOMPackage,
    parent_intermediate_image_package: AnnotatedPackage,
    grandparent_builder_content_pkg: SBOMPackage,
    grandparent_builder_image_package: AnnotatedPackage,
    grandparent_intermediate_content_pkg: SBOMPackage,
    grandparent_intermediate_image_package: AnnotatedPackage,
    grandparent_image_package: AnnotatedPackage,
    parent_with_builder_content_sbom: Path,
    component_input_sbom_with_parent_builder_content: Path,
) -> None:
    """
    This test verifies builder image packages and content packages inheritance
    into component from parent and ancestors. Builder content contextualization
    of the component itself is tested in test_builder_content.py.

    Does not test:
     - anonymous packages (matching contract must be implemented)
     - duplicate packages (matching contract must be implemented)
     - duplicate image packages in the chain

    INPUT 1: Parent image is multistage (parent_builder with parent_intermediate),
    and its SBOM has been contextualized during build (it has already inherited
    grandparent builder, intermediate, and content information).

    Parent SBOM (contextualized):
        Grandparent (built FROM scratch - only builder content):
            grandparent_builder      BUILD_TOOL_OF grandparent
            grandparent_intermediate DESCENDANT_OF grandparent_builder
            ---
            grandparent_builder      CONTAINS grandparent_builder_package
            grandparent_intermediate CONTAINS grandparent_intermediate_package
        Parent:
            parent(parent name) DESCENDANT_OF grandparent
            parent_builder      BUILD_TOOL_OF parent(parent name)
            parent_intermediate DESCENDANT_OF parent_builder
            ---
            parent(parent name) CONTAINS parent_package
            parent_builder      CONTAINS parent_builder_package
            parent_intermediate CONTAINS parent_intermediate_package

    INPUT 2: Component image is single-stage. SBOM is inheriting all the
    content from ancestors yet content-origin unaware.
    Component SBOM (to-be-contextualized):
        Component:
            component DESCENDANT_OF parent(component name)
            ---
            component CONTAINS component_package
            component CONTAINS parent_package
            component CONTAINS parent_builder_package
            component CONTAINS parent_intermediate_package
            component CONTAINS grandparent_builder_package
            component CONTAINS grandparent_intermediate_package

    Inherited: from parent SBOM to component SBOM - inherited is relationship,
        related package (targeted related package is marked as *),
        and package annotation
    Reparented: component CONTAINS package -> origin CONTAINS package
    Renamed: inherited relationships from parent to component mentioning parent
        must be renamed by parent name from component (parent(parent name) ->
        parent(component name)). parent(component name) is the parent SPDX ID
        already referenced by component DESCENDANT_OF.
    RESULT:
    Component SBOM (contextualized):
        Grandparent:
            grandparent_builder*      BUILD_TOOL_OF grandparent (inherited)
            grandparent_intermediate* DESCENDANT_OF grandparent_builder (inherited)
            ---
            grandparent_builder      CONTAINS grandparent_builder_package (reparented)
            grandparent_intermediate CONTAINS
                grandparent_intermediate_package (reparented)
        Parent:
            parent(c. name)        DESCENDANT_OF grandparent* (inherited && renamed)
            parent_builder*        BUILD_TOOL_OF parent(c. name) (inherited && renamed)
            parent_intermediate*   DESCENDANT_OF parent_builder (inherited)
            ---
            parent(c. name)        CONTAINS parent_package (reparented)
            parent_builder         CONTAINS parent_builder_package (reparented)
            parent_intermediate    CONTAINS parent_intermediate_package (reparented)
        Component:
            component DESCENDANT_OF parent(c. name)
            ---
            component CONTAINS component_package
    """
    parent_img = await oci_client.create_image("parent", "latest")
    component_img = await oci_client.create_image("component", "latest")

    with open(parent_with_builder_content_sbom, "rb") as f:
        await oci_client.attach_sbom(parent_img, "spdx", f.read())

    component_gdata = GenerateData(
        input_sbom_path=component_input_sbom_with_parent_builder_content,
        output_sbom_path=tmp_path / "component.output.spdx.json",
        metadata_path=make_metadata_yaml(tmp_path, component_img, base_img=parent_img),
    )

    # contextualize component SBOM with already contextualized parent
    run_mobster_generate(component_gdata)

    component_sbom_doc = parse_file(str(component_gdata.output_sbom_path))
    # Determine the component's SPDX ID.
    component_name = next(
        rel.related_spdx_element_id
        for rel in component_sbom_doc.relationships
        if rel.spdx_element_id == "SPDXRef-DOCUMENT"
        and rel.relationship_type == RelationshipType.DESCRIBES
    )
    assert isinstance(component_name, str)

    # Determine the component's parent SPDX ID.
    parent_name_from_component = next(
        rel.related_spdx_element_id
        for rel in component_sbom_doc.relationships
        if rel.spdx_element_id == component_name
        and rel.relationship_type == RelationshipType.DESCENDANT_OF
    )
    assert isinstance(parent_name_from_component, str)
    # Create lightweight expected endpoints for verifying the component's
    # direct relationship to its parent and the inherited image subtree.
    component = AnnotatedPackage(
        package=Package(
            spdx_id=component_name,
            name="component",
            download_location=SpdxNoAssertion(),
        )
    )
    # The parent SPDX ID is generated in the component SBOM, so reuse it when
    # checking relationships without adding another package to the document.
    parent = AnnotatedPackage(
        package=Package(
            spdx_id=parent_name_from_component,
            name="parent",
            download_location=SpdxNoAssertion(),
        )
    )

    # Expected image items - relationship, package and package annotation are
    # checked for each item.
    image_items = [
        # The ancestor builder subtree must be inherited into
        # component (parent of this ancestor is not present)
        (grandparent_builder_image_package, BUILDER_IMAGE, grandparent_image_package),
        (
            grandparent_intermediate_image_package,
            INTERMEDIATE_IMAGE,
            grandparent_builder_image_package,
        ),
        # The parent builder subtree must be inherited into component
        # (with its parent - grandparent of the component)
        (grandparent_image_package, ANCESTOR_IMAGE, parent),
        (parent_builder_image_package, BUILDER_IMAGE, parent),
        (
            parent_intermediate_image_package,
            INTERMEDIATE_IMAGE,
            parent_builder_image_package,
        ),
        # The component must retain its direct relationship to the parent
        # image, which is the base image from the component's perspective.
        (parent, BASE_IMAGE, component),
    ]

    # CHECK 1: Check the number of image relationships by type:
    # builders, intermediates, ancestors and base image.
    image_relationship_types = {kind.relationship_type for _, kind, _ in image_items}
    actual_image_relationships = [
        relationship
        for relationship in component_sbom_doc.relationships
        if relationship.relationship_type in image_relationship_types
    ]
    assert len(actual_image_relationships) == len(image_items), (
        "Unexpected number of image relationships in contextualized component "
        f"SBOM: expected {len(image_items)}, found "
        f"{len(actual_image_relationships)}."
    )

    # CHECK 2: Check the exact image relationships.
    for image_package, kind, expected_related_image in image_items:
        verify_image_item(
            component_sbom_doc,
            image_package,
            kind,
            expected_related_image,
        )

    # CHECK 3: Check that only expected image and content packages are present.
    expected_package_ids = {
        component.spdx_id,
        parent.spdx_id,
        grandparent_image_package.spdx_id,
        parent_builder_image_package.spdx_id,
        parent_intermediate_image_package.spdx_id,
        grandparent_builder_image_package.spdx_id,
        grandparent_intermediate_image_package.spdx_id,
        *(package.spdx_id for package in component_packages),
        *(package.spdx_id for package in parent_packages),
        parent_builder_content_pkg.to_spdx().spdx_id,
        parent_intermediate_content_pkg.to_spdx().spdx_id,
        grandparent_builder_content_pkg.to_spdx().spdx_id,
        grandparent_intermediate_content_pkg.to_spdx().spdx_id,
    }
    actual_package_ids = {package.spdx_id for package in component_sbom_doc.packages}
    assert actual_package_ids == expected_package_ids, (
        "Unexpected package set in contextualized component SBOM. "
        f"Missing: {expected_package_ids - actual_package_ids}; "
        f"unexpected: {actual_package_ids - expected_package_ids}."
    )
    content_items = [
        # Grandparent builder subtree content remains owned by its source
        # builder and intermediate images.
        (grandparent_builder_content_pkg.to_spdx(), grandparent_builder_image_package),
        (
            grandparent_intermediate_content_pkg.to_spdx(),
            grandparent_intermediate_image_package,
        ),
        # Parent content is reparented to the parent image.
        *[(package, parent) for package in parent_packages],
        (parent_builder_content_pkg.to_spdx(), parent_builder_image_package),
        (parent_intermediate_content_pkg.to_spdx(), parent_intermediate_image_package),
        # Component-only content remains owned by the component.
        *[(package, component) for package in component_packages],
    ]
    # CHECK 4: Check that content packages were correctly reparented.
    for content_package, owner_image in content_items:
        verify_content_item(component_sbom_doc, content_package, owner_image)


@pytest.mark.asyncio
async def test_parent_content_contextualizaton_legacy(
    oci_client: ReferrersTagOCIClient,
    tmp_path: Path,
    grandparent_packages: list[AnnotatedPackage],
    parent_packages: list[AnnotatedPackage],
    parent_only_packages: list[AnnotatedPackage],
    component_packages: list[AnnotatedPackage],
    legacy_parent_sbom: Path,
    component_input_sbom: Path,
) -> None:
    """
    Simulates a contextualization of a component whose parent image uses a
    pre-mobster SBOM with a BUILD_TOOL_OF relationship.

    Verifies that contextualization of a component works as expected even in
    this case.
    """
    parent_img = await oci_client.create_image("parent", "latest")
    component_img = await oci_client.create_image("component", "latest")

    with open(legacy_parent_sbom, "rb") as f:
        await oci_client.attach_sbom(parent_img, "spdx", f.read())

    component_gdata = GenerateData(
        input_sbom_path=component_input_sbom,
        output_sbom_path=tmp_path / "component.output.spdx.json",
        metadata_path=make_metadata_yaml(tmp_path, component_img, base_img=parent_img),
    )

    run_mobster_generate(component_gdata)

    # don't check that grandparent packages have good relationships, because
    # the parent input is not contextualized
    verify_sbom_relationships(
        component_gdata.output_sbom_path,
        [component_packages, parent_packages + grandparent_packages, []],
    )

    verify_packages_not_included(
        component_gdata.output_sbom_path,
        parent_only_packages,
    )
