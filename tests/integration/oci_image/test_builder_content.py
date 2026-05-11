from pathlib import Path

import pytest
from spdx_tools.spdx.writer.write_anything import write_file

from mobster.cmd.generate.oci_image.contextual_sbom.builder import (
    BuilderPkgMetadata,
    BuilderPkgMetadataItem,
)
from mobster.cmd.generate.oci_image.metadata import ImageData, SBOMMetadata
from tests.integration.oci_image.conftest import (
    GenerateData,
    run_mobster_generate,
    verify_sbom_relationships,
)
from tests.spdx_builder import SPDXPackageBuilder, SPDXSBOMBuilder

repo = "registry.redhat.io/ubi10"
tag = "latest"
digest = "sha256:4ab0d32a67e22a27ea3ba4ad00a3a5aee008386ae4f0086c9a720401ab1aca43"
arch = "amd64"
pullspec = f"{repo}:{tag}"
purl = f"pkg:oci/{repo}@{digest}?arch={arch}"

oras_name = "oras"
oras_repo = "quay.io/konflux-ci/syft"
oras_tag = "latest"
oras_digest = "sha256:4ab0d32a67e22a27ea3ba4ad00a3a5aee008386ae4f0086c9a720401ab1aca44"
oras_pullspec = f"{oras_repo}:{oras_tag}"
oras_img_purl = f"pkg:oci/{oras_name}@{oras_digest}?repository_url={oras_repo}"
oras_version = "v1.3.0"
oras_pkg_purl = f"pkg:golang/oras.land/oras@{oras_version}"

syft_name = "syft"
syft_repo = "quay.io/konflux-ci/syft"
syft_tag = "latest"
syft_digest = "sha256:4ab0d32a67e22a27ea3ba4ad00a3a5aee008386ae4f0086c9a720401ab1aca45"
syft_pullspec = f"{syft_repo}:{syft_tag}"
syft_img_purl = f"pkg:oci/{syft_name}@{syft_digest}?repository_url={syft_repo}"
syft_version = "1.42.1"
syft_pkg_purl = f"pkg:golang/github.com/anchore/syft@{syft_version}"

oras_img_pkg = (
    SPDXPackageBuilder()
    .name("oras")
    .version(oras_version)
    .purl(oras_img_purl)
    .spdx_id("SPDXRef-image-oras-1234")
    .is_builder_image_for_stage_annotation(0)
    .build()
)

oras_app_pkg = (
    SPDXPackageBuilder()
    .name("oras")
    .version(oras_version)
    .purl(oras_pkg_purl)
    .spdx_id("SPDXRef-image-oras-1234")
    .is_builder_image_for_stage_annotation(0)
    .build()
)

oras_metadata_builder = BuilderPkgMetadataItem(
    purl=oras_img_purl, origin_type="builder", pullspec=f"{oras_repo}@{oras_version}"
)

oras_metadata_intermediate = BuilderPkgMetadataItem(
    purl=oras_img_purl,
    origin_type="intermediate",
    pullspec=f"{oras_repo}@{oras_version}",
)

syft_img_pkg = (
    SPDXPackageBuilder()
    .name("syft")
    .version(syft_version)
    .purl(syft_img_purl)
    .spdx_id("SPDXRef-image-syft-1234")
    .is_builder_image_for_stage_annotation(1)
    .build()
)

syft_app_pkg = (
    SPDXPackageBuilder()
    .name("syft")
    .version(syft_version)
    .purl(f"pkg:foo/{syft_name}@{syft_version}")
    .spdx_id("SPDXRef-package-syft-1234")
    .build()
)

syft_metadata_builder = BuilderPkgMetadataItem(
    purl=syft_pkg_purl, origin_type="builder", pullspec=pullspec
)

syft_metadata_intermediate = BuilderPkgMetadataItem(
    purl=syft_pkg_purl, origin_type="intermediate", pullspec=syft_pullspec
)


@pytest.fixture
def parent_only_sbom(tmp_path: Path) -> Path:
    sbom = (
        SPDXSBOMBuilder()
        .name("parentonly")
        .root_contains([oras_app_pkg, syft_app_pkg])
        .root_purl(purl)
        .build()
    )
    path = tmp_path / "parentonly.input.spdx.json"
    write_file(sbom, str(path))
    return path


@pytest.fixture
def parent_only_build_metadata(tmp_path: Path) -> Path:
    build_metadata = BuilderPkgMetadata(
        packages=[syft_metadata_builder, oras_metadata_builder]
    )
    path = tmp_path / "parentonly.buildmetadata.json"
    with open(path, "w") as file:
        file.write(build_metadata.model_dump_json())
    return path


@pytest.fixture
def split_build_metadata(tmp_path: Path) -> Path:
    build_metadata = BuilderPkgMetadata(
        packages=[syft_metadata_intermediate, oras_metadata_builder]
    )
    path = tmp_path / "parentonly.buildmetadata.json"
    with open(path, "w") as file:
        file.write(build_metadata.model_dump_json())
    return path


@pytest.fixture
def parent_only_metadata(tmp_path: Path) -> Path:
    build_metadata = SBOMMetadata(
        image=ImageData(pullspec=pullspec, digest=digest),
        base_images=[ImageData(pullspec=syft_pullspec, digest=syft_digest)],
    )
    path = tmp_path / "parentonly.metadata.yaml"
    with open(path, "w") as file:
        # yaml parser will accept json just fine, so we can do it this way
        file.write(build_metadata.model_dump_json())
    return path


def test_parent_sbom_builder_content_parentonly(
    tmp_path: Path, parent_only_sbom, parent_only_build_metadata, parent_only_metadata
) -> None:
    output_path = tmp_path / "parentonly.output.spdx.json"
    gdata = GenerateData(
        input_sbom_path=parent_only_sbom,
        output_sbom_path=output_path,
        build_metadata_path=parent_only_build_metadata,
        metadata_path=parent_only_metadata,
        contextualize=True,
    )
    run_mobster_generate(gdata)
    verify_sbom_relationships(output_path, [[syft_app_pkg, oras_app_pkg], []])


def test_parent_sbom_builder_content_split(
    tmp_path: Path, parent_only_sbom, split_build_metadata, parent_only_metadata
) -> None:
    output_path = tmp_path / "parentonly.output.spdx.json"
    gdata = GenerateData(
        input_sbom_path=parent_only_sbom,
        output_sbom_path=output_path,
        build_metadata_path=split_build_metadata,
        metadata_path=parent_only_metadata,
        contextualize=True,
    )
    run_mobster_generate(gdata)
    verify_sbom_relationships(output_path, [[oras_app_pkg], [syft_app_pkg]])
