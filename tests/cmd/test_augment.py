from base64 import b64encode
from hashlib import sha256
import json
from pathlib import Path
from typing import Any
import tempfile
import os
from functools import partial

import pytest
from unittest.mock import MagicMock
from packageurl import PackageURL

from mobster.error import SBOMVerificationError
from mobster.image import Image, IndexImage
from mobster.oci.cosign import Cosign
from mobster.oci.artifact import Provenance02, SBOM, SBOMFormat
from mobster.release import Snapshot, Component

from mobster.cmd.augment import AugmentComponentCommand, update_sboms
from mobster.cmd.augment.handlers import get_purl_digest

# @pytest.mark.asyncio
# async def test_AugmentComponentCommand_execute() -> None:
#     command = AugmentComponentCommand(MagicMock())
#
#     assert await command.execute() is None
#
# @pytest.mark.asyncio
# async def test_AugmentComponentCommand_save() -> None:
#     command = AugmentComponentCommand(MagicMock())
#     assert await command.save() is None

TESTDATA_PATH = Path(__file__).parent.parent.joinpath("data/component")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ["success"],
    [
        pytest.param(True),
        pytest.param(False),
    ],
)
async def test_update_sbom_verification(success: bool) -> None:
    digest = "sha256:aaaaaaaa"
    snapshot = Snapshot(
        components=[
            Component(
                name="spdx-singlearch",
                image=Image(
                    "registry.redhat.io/repo",
                    digest,
                ),
                tags=["1.0", "latest"],
            ),
        ],
    )

    cosign = FakeCosign.from_snapshot(snapshot)

    if success:
        sbom_blob_url = f"registry.redhat.io/repo@{cosign.sboms[digest].digest}"
    else:
        sbom_blob_url = f"registry.redhat.io/repo@sha256:deadbeef"

    # set the sbom_blob_url in the provenance
    cosign.provenances[digest].predicate["buildConfig"]["tasks"][0]["results"] = [
        {"name": "IMAGE_DIGEST", "value": digest},
        {"name": "SBOM_BLOB_URL", "value": sbom_blob_url},
    ]

    tmpdir = tempfile.TemporaryDirectory(delete=False)
    dirpath = Path(tmpdir.name)

    if success:
        await update_sboms(snapshot, dirpath, cosign, verify=True)
    else:
        with pytest.raises(SBOMVerificationError):
            await update_sboms(snapshot, dirpath, cosign, verify=True)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ["snapshot"],
    [
        pytest.param(
            Snapshot(
                components=[
                    Component(
                        name="spdx-singlearch",
                        image=Image(
                            "registry.redhat.io/org/tenant/test",
                            "sha256:aaaaaaaa",
                        ),
                        tags=["1.0", "latest"],
                    ),
                ],
            ),
            id="spdx-singlearch",
        ),
        pytest.param(
            Snapshot(
                components=[
                    Component(
                        name="spdx-multiarch",
                        image=IndexImage(
                            "registry.redhat.io/org/tenant/test",
                            "sha256:bbbbbbbb",
                            children=[
                                Image(
                                    "registry.redhat.io/org/tenant/test",
                                    "sha256:cccccccc",
                                )
                            ],
                        ),
                        tags=["1.0", "latest"],
                    ),
                ],
            ),
            id="spdx-multiarch",
        ),
        pytest.param(
            Snapshot(
                components=[
                    Component(
                        name="cdx-singlearch",
                        image=Image(
                            "registry.redhat.io/org/tenant/cdx-singlearch",
                            "sha256:dddddddd",
                        ),
                        tags=["1.0", "latest"],
                    ),
                ],
            ),
            id="cdx-singlearch",
        ),
    ],
)
async def test_sbom_update(snapshot: Snapshot) -> None:
    cosign = FakeCosign.from_snapshot(snapshot)

    tmpdir = tempfile.TemporaryDirectory(delete=False)
    dirpath = Path(tmpdir.name)

    await update_sboms(snapshot, dirpath, cosign, False)
    try:
        await assert_sboms(snapshot, dirpath)
        tmpdir.cleanup()
    except Exception as err:
        raise AssertionError(
            f"Failed to verify generated SBOMs. Output directory: {dirpath}"
        ) from err


class FakeCosign(Cosign):
    def __init__(
        self, provenances: dict[str, Provenance02], sboms: dict[str, SBOM]
    ) -> None:
        self.provenances = provenances
        self.sboms = sboms

    async def fetch_latest_provenance(self, image: Image) -> Provenance02:
        return [self.provenances[image.digest]][0]

    async def fetch_sbom(self, image: Image) -> SBOM:
        return self.sboms[image.digest]

    @staticmethod
    def from_snapshot(snapshot: Snapshot) -> "FakeCosign":
        provenances = {}
        sboms = {}

        sbom_path = TESTDATA_PATH.joinpath("sboms")
        prov_path = TESTDATA_PATH.joinpath("provenances")
        for component in snapshot.components:
            with open(sbom_path.joinpath(component.image.digest), "rb") as fp:
                sboms[component.image.digest] = SBOM.from_cosign_output(fp.read())

            prov = load_provenance(prov_path, component.image.digest)
            if prov is not None:
                provenances[component.image.digest] = prov

            if isinstance(component.image, IndexImage):
                for child_img in component.image.children:
                    with open(sbom_path.joinpath(child_img.digest), "rb") as fp:
                        sboms[child_img.digest] = SBOM.from_cosign_output(fp.read())

                    prov = load_provenance(prov_path, child_img.digest)
                    if prov is not None:
                        provenances[child_img.digest] = prov

        return FakeCosign(provenances, sboms)


def load_provenance(prov_dir: Path, digest: str) -> Provenance02 | None:
    ppath = prov_dir.joinpath(digest)
    if ppath.exists():
        with open(ppath, "rb") as fp:
            payload = b64encode(fp.read()).decode()
            return Provenance02.from_cosign_output(
                json.dumps({"payload": payload}).encode()
            )


def get_all_digests(snapshot: Snapshot) -> list[str]:
    digests = []
    for component in snapshot.components:
        digests.append(component.image.digest)
        if isinstance(component.image, IndexImage):
            for child_img in component.image.children:
                digests.append(child_img.digest)
    return digests


async def assert_sboms(snapshot: Snapshot, directory: Path) -> None:
    digests = get_all_digests(snapshot)
    for digest in digests:
        sbom_file = directory.joinpath(digest)
        assert sbom_file.exists(), f"SBOM file for {digest} not found."

        with open(sbom_file, "rb") as fp:
            sbom = SBOM.from_cosign_output(fp.read())

        # TODO: this is not ideal
        if sbom.format in [
            SBOMFormat.SPDX_2_0,
            SBOMFormat.SPDX_2_1,
            SBOMFormat.SPDX_2_2,
            SBOMFormat.SPDX_2_2_1,
            SBOMFormat.SPDX_2_2_2,
            SBOMFormat.SPDX_2_3,
        ]:
            expected_path = TESTDATA_PATH.joinpath(f"sboms/{digest}.expected")
            with open(expected_path, "rb") as fp:
                expected = SBOM.from_cosign_output(fp.read())
            assert sbom.doc == expected.doc
        else:
            VerifyCycloneDX.verify_components_updated(snapshot, sbom.doc)


class VerifyCycloneDX:
    @staticmethod
    def verify_purl(purl: PackageURL, image: Image) -> None:
        assert purl.qualifiers is not None
        assert purl.qualifiers.get("repository_url") == image.repository  # type: ignore
        assert purl.name == image.repository.split("/")[-1]

    @staticmethod
    def verify_tags(kflx_component: Component, cdx_component: dict) -> None:
        """
        Verify that all tags are present in PURLs in the evidence.identity field
        if there are more than one.
        """
        if len(kflx_component.tags) == 1:
            # in this case, we don't populate the evidence.identity field so
            # let's make sure we add the tag to the component.purl field
            purl = PackageURL.from_string(cdx_component["purl"])
            assert purl.qualifiers is not None
            assert purl.qualifiers.get("tag") == kflx_component.tags[0]  # type: ignore
            return

        tags = set(kflx_component.tags)

        try:
            identity = cdx_component["evidence"]["identity"]
        except KeyError:
            raise AssertionError("CDX component is missing evidence.identity field.")

        for id_item in identity:
            if id_item.get("field") != "purl":
                continue
            purl = PackageURL.from_string(id_item["concludedValue"])
            VerifyCycloneDX.verify_purl(purl, kflx_component.image)

            purl_tag = purl.qualifiers.get("tag")  # type: ignore
            assert isinstance(purl_tag, str), f"Missing tag in identity purl {purl}."
            tags.remove(purl_tag)

        assert (
            len(tags) == 0
        ), f"Not all tags present in identity purls, missing {tags}."

    @staticmethod
    def find_matching_konflux_component(
        snapshot: Snapshot, digest: str
    ) -> Component | Any:
        for component in snapshot.components:
            if component.image.digest == digest:
                return component

        return None

    @staticmethod
    def verify_component_updated(
        snapshot: Snapshot,
        cdx_component: dict,
        verify_tags: bool,
    ) -> None:
        if (purl_str := cdx_component.get("purl")) is None:
            return

        digest = get_purl_digest(purl_str)
        kflx_component = VerifyCycloneDX.find_matching_konflux_component(
            snapshot, digest
        )
        if kflx_component is None:
            return

        VerifyCycloneDX.verify_purl(
            PackageURL.from_string(purl_str), kflx_component.image
        )

        if verify_tags:
            VerifyCycloneDX.verify_tags(kflx_component, cdx_component)

    @staticmethod
    def verify_components_updated(snapshot: Snapshot, sbom: dict) -> None:
        """
        This method verifies that all CycloneDX container components that have a
        matching Konflux component in the release are updated.
        """
        VerifyCycloneDX.verify_component_updated(
            snapshot, sbom["metadata"]["component"], verify_tags=False
        )

        for component in sbom.get("components", []):
            VerifyCycloneDX.verify_component_updated(
                snapshot, component, verify_tags=True
            )
