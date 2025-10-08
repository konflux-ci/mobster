from pathlib import Path
from typing import Any

import pytest
from pytest_lazy_fixtures import lf

from tests.integration.oci_client import ReferrersTagOCIClient
from tests.integration.oci_image.conftest import (
    GenerateData,
    run_mobster_generate,
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
    make_parsed_dockerfile_json: Any,
    make_base_images_digests: Any,
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
        image=parent_img,
        input_sbom_path=parent_input_sbom,
        output_sbom_path=tmp_path / "parent.output.spdx.json",
        df_json_path=make_parsed_dockerfile_json(grandparent_img),
        base_images_path=make_base_images_digests(grandparent_img),
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
        image=component_img,
        input_sbom_path=component_input_sbom,
        output_sbom_path=tmp_path / "component.output.spdx.json",
        df_json_path=make_parsed_dockerfile_json(parent_img),
        base_images_path=make_base_images_digests(parent_img),
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
async def test_parent_content_contextualizaton_legacy(
    oci_client: ReferrersTagOCIClient,
    tmp_path: Path,
    grandparent_packages: list[AnnotatedPackage],
    parent_packages: list[AnnotatedPackage],
    parent_only_packages: list[AnnotatedPackage],
    component_packages: list[AnnotatedPackage],
    make_parsed_dockerfile_json: Any,
    make_base_images_digests: Any,
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
        image=component_img,
        input_sbom_path=component_input_sbom,
        output_sbom_path=tmp_path / "component.output.spdx.json",
        df_json_path=make_parsed_dockerfile_json(parent_img),
        base_images_path=make_base_images_digests(parent_img),
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
