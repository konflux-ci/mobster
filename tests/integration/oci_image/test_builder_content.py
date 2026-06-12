"""Integration tests for builder content contextualization.

Some assertions and tests are deferred until the matching contract
is defined in ISV-7349. Skipped tests reference this ticket.
"""

from pathlib import Path
from typing import Literal

import pytest
from spdx_tools.spdx.model.relationship import RelationshipType as RT
from spdx_tools.spdx.parser.parse_anything import parse_file

from mobster.cmd.generate.oci_image.contextual_sbom.builder import (
    BuilderPkgMetadata,
)
from mobster.image import Image
from mobster.utils import identify_arch
from tests.integration.img_utils import make_metadata_yaml
from tests.integration.oci_client import ReferrersTagOCIClient
from tests.integration.oci_image.conftest import (
    GenerateData,
    SBOMPackage,
    run_mobster_generate,
    verify_packages_not_included,
    verify_relationships,
    verify_sbom_relationships,
)


@pytest.fixture
def builder_img() -> Image:
    return Image(
        repository="localhost:9000/builder",
        digest="sha256:0000000000000000000000000000000000000000000000000000000000000001",
        tag="latest",
    )


@pytest.fixture
def extra_builder_img() -> Image:
    return Image(
        repository="localhost:9000/builder2",
        digest="sha256:0000000000000000000000000000000000000000000000000000000000000002",
        tag="latest",
    )


async def setup_images(
    tmp_path: Path, parent_input_sbom: Path, oci_client: ReferrersTagOCIClient
) -> tuple[Image, Image]:
    """Initialize the parent and component image necessary for most
    builder content tests."""
    parent_img = await oci_client.create_image("parent", "latest")
    component_img = await oci_client.create_image("component", "latest")
    # this is required to make propose_spdx_id match the actual id of the sbom
    # when verifying relationships
    component_img.arch = identify_arch()

    # generate the parent sbom (no contextualization)
    parent_gdata = GenerateData(
        image=parent_img,
        input_sbom_path=parent_input_sbom,
        output_sbom_path=tmp_path / "parent.output.spdx.json",
    )

    run_mobster_generate(parent_gdata)

    with open(parent_gdata.output_sbom_path, "rb") as f:
        await oci_client.attach_sbom(parent_img, "spdx", f.read())
    return (parent_img, component_img)


async def capture_builder_content_workflow(
    tmp_path: Path,
    input_sbom: Path,
    build_metadata: BuilderPkgMetadata,
    img: Image,
    builder_imgs: list[Image],
    base_img: Image,
) -> tuple[str, str, Path]:
    """Generate build metadata and generate an SBOM for builder content
    testing, while capturing stdout/stderr. Useful for asserting certain things
    were logged."""
    build_metadata_path = tmp_path / "buildmetadata.json"
    with open(build_metadata_path, "w") as fp:
        fp.write(build_metadata.model_dump_json())

    gdata = GenerateData(
        metadata_path=make_metadata_yaml(
            tmp_path,
            img,
            builder_imgs + [base_img],
        ),
        build_metadata_path=build_metadata_path,
        input_sbom_path=input_sbom,
        output_sbom_path=tmp_path / "builder_content.output.spdx.json",
        contextualize=True,
    )

    result = run_mobster_generate(gdata)
    return result.stdout.decode(), result.stderr.decode(), gdata.output_sbom_path


async def run_builder_content_workflow(
    tmp_path: Path,
    input_sbom: Path,
    build_metadata: BuilderPkgMetadata,
    img: Image,
    builder_imgs: list[Image],
    base_img: Image,
) -> Path:
    """Generate build metadata and generate an SBOM for builder content
    testing. This returns just the output path, without stdout/stderr."""
    _, _, output_sbom_path = await capture_builder_content_workflow(
        tmp_path,
        input_sbom,
        build_metadata,
        img,
        builder_imgs,
        base_img,
    )
    return output_sbom_path


@pytest.mark.asyncio
async def test_builder_content(
    oci_client: ReferrersTagOCIClient,
    tmp_path: Path,
    parent_input_sbom: Path,
    component_input_sbom: Path,
    builder_img: Image,
    gin_pkg: SBOMPackage,
    crypto_pkg: SBOMPackage,
    random_pkg: SBOMPackage,
    malware_pkg: SBOMPackage,
    stdlib_pkg: SBOMPackage,
) -> None:
    """Basic happy-path test of builder content. This just simulates one
    package being COPY'd from the builder image & ensures the origin is swapped
    to the builder image when mobster runs the generate command w/
    --build-metadata-path and --contextualize set."""
    parent_img, component_img = await setup_images(
        tmp_path, parent_input_sbom, oci_client
    )
    # mock build metadata
    component_build_metadata = BuilderPkgMetadata(
        packages=[
            # simulates a package COPY'd from the above builder image
            crypto_pkg.to_metadata("builder", builder_img.reference),
            # simulates a package installed/built in the builder image before
            # being copied
            random_pkg.to_metadata("intermediate", builder_img.reference),
        ]
    )
    output_sbom_path = await run_builder_content_workflow(
        tmp_path,
        component_input_sbom,
        component_build_metadata,
        component_img,
        [builder_img],
        parent_img,
    )

    # verify DESCENDANT_OF relationships for the component/parent packages
    # (we can't use verify_sbom_relationships here since the intermediate
    # package will have two roots)
    sbom_doc = parse_file(str(output_sbom_path))
    verify_relationships(
        parent_img.propose_spdx_id(),
        sbom_doc.relationships,
        [gin_pkg.to_spdx(), malware_pkg.to_spdx()],
        RT.CONTAINS,
    )
    verify_relationships(
        component_img.propose_spdx_id(),
        sbom_doc.relationships,
        [stdlib_pkg.to_spdx()],
        RT.CONTAINS,
    )
    # verify that the crypto package is marked as actually coming from the
    # builder image
    verify_relationships(
        builder_img.propose_spdx_id(),
        sbom_doc.relationships,
        [crypto_pkg.to_spdx()],
        RT.CONTAINS,
    )
    verify_relationships(
        builder_img.propose_spdx_id() + "-intermediate",
        sbom_doc.relationships,
        [random_pkg.to_spdx()],
        RT.CONTAINS,
    )


@pytest.mark.asyncio
@pytest.mark.skip(reason="deferred until behavior is defined (ISV-7349)")
@pytest.mark.parametrize(["origin_type"], [["builder"], ["intermediate"]])
async def test_builder_content_duplicate(
    oci_client: ReferrersTagOCIClient,
    tmp_path: Path,
    parent_input_sbom: Path,
    component_input_sbom: Path,
    builder_img: Image,
    gin_pkg: SBOMPackage,
    crypto_pkg: SBOMPackage,
    random_pkg: SBOMPackage,
    malware_pkg: SBOMPackage,
    stdlib_pkg: SBOMPackage,
    origin_type: Literal["builder", "intermediate"],
) -> None:
    """Test that builder content handles duplicated packages from Capo."""
    parent_img, component_img = await setup_images(
        tmp_path, parent_input_sbom, oci_client
    )

    # mock build metadata
    component_build_metadata = BuilderPkgMetadata(
        packages=[
            # like the above test, but we specify the crypto package twice
            crypto_pkg.to_metadata(origin_type, builder_img.reference),
            crypto_pkg.to_metadata(origin_type, builder_img.reference),
        ]
    )
    _, stderr, output_sbom_path = await capture_builder_content_workflow(
        tmp_path,
        component_input_sbom,
        component_build_metadata,
        component_img,
        [builder_img],
        parent_img,
    )

    # assertions should be roughly the same as the happy path
    verify_sbom_relationships(
        output_sbom_path,
        [
            # component packages
            [
                stdlib_pkg.to_spdx(),
            ],
            # parent packages
            [
                gin_pkg.to_spdx(),
                random_pkg.to_spdx(),
                malware_pkg.to_spdx(),
            ],
        ],
    )

    # this is all mobster does currently:
    sbom_doc = parse_file(str(output_sbom_path))
    verify_relationships(
        builder_img.propose_spdx_id(),
        sbom_doc.relationships,
        [crypto_pkg.to_spdx()],
    )

    # this will probably log a warning later - replace this with the actual
    # warning text once this is added
    assert "Duplicated package in build metadata" in stderr


@pytest.mark.asyncio
async def test_builder_content_extra(
    oci_client: ReferrersTagOCIClient,
    tmp_path: Path,
    parent_input_sbom: Path,
    component_input_sbom: Path,
    builder_img: Image,
    crypto_pkg: SBOMPackage,
    ginkgo_pkg: SBOMPackage,
) -> None:
    """Test that builder content flow handles Capo packages that aren't
    actually in the SBOM."""
    parent_img, component_img = await setup_images(
        tmp_path, parent_input_sbom, oci_client
    )

    # mock build metadata
    component_build_metadata = BuilderPkgMetadata(
        packages=[
            crypto_pkg.to_metadata("builder", builder_img.reference),
            # ginkgo package isn't in the component input SBOM
            # we should log a warning
            ginkgo_pkg.to_metadata("builder", builder_img.reference),
        ]
    )
    output_sbom_path = await run_builder_content_workflow(
        tmp_path,
        component_input_sbom,
        component_build_metadata,
        component_img,
        [builder_img],
        parent_img,
    )

    # make sure ginkgo wasn't added to the sbom
    verify_packages_not_included(output_sbom_path, [ginkgo_pkg.to_spdx()])


@pytest.mark.asyncio
@pytest.mark.skip(reason="deferred until behavior is defined (ISV-7349)")
async def test_builder_content_same_package_from_multiple_builders(
    oci_client: ReferrersTagOCIClient,
    tmp_path: Path,
    parent_input_sbom: Path,
    component_input_sbom: Path,
    builder_img: Image,
    extra_builder_img: Image,
    crypto_pkg: SBOMPackage,
) -> None:
    """Test that the process notes a package as coming from *two* separate
    builder images if specified by the build metadata."""
    parent_img, component_img = await setup_images(
        tmp_path, parent_input_sbom, oci_client
    )

    # mock build metadata
    component_build_metadata = BuilderPkgMetadata(
        packages=[
            # crypto package comes from TWO builder images
            crypto_pkg.to_metadata("builder", builder_img.reference),
            crypto_pkg.to_metadata("builder", extra_builder_img.reference),
        ]
    )
    output_sbom_path = await run_builder_content_workflow(
        tmp_path,
        component_input_sbom,
        component_build_metadata,
        component_img,
        [builder_img, extra_builder_img],
        parent_img,
    )

    sbom_doc = parse_file(str(output_sbom_path))
    # the sbom should show the package as coming from *both* images
    verify_relationships(
        builder_img.propose_spdx_id(),
        sbom_doc.relationships,
        [crypto_pkg.to_spdx()],
        RT.CONTAINS,
    )
    verify_relationships(
        extra_builder_img.propose_spdx_id(),
        sbom_doc.relationships,
        [crypto_pkg.to_spdx()],
        RT.CONTAINS,
    )
