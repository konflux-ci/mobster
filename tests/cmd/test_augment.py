import json
import os
from base64 import b64encode
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from packageurl import PackageURL

from mobster.cmd.augment import (
    AugmentImageCommand,
    update_sbom,
    verify_sbom,
)
from mobster.cmd.augment.handlers import CycloneDXVersion1, get_purl_digest
from mobster.error import SBOMError, SBOMVerificationError
from mobster.image import Image, IndexImage
from mobster.oci.artifact import SBOM, Provenance02
from mobster.oci.cosign import Cosign
from mobster.release import Component, Snapshot
from mobster.sbom import cyclonedx
from tests.conftest import assert_spdx_sbom, awaitable

TESTDATA_PATH = Path(__file__).parent.parent.joinpath("data/component")


@dataclass
class AugmentArgs:
    snapshot: Path
    output: Path
    verification_key: Path | None
    reference: str | None


MakeAugmentCommand = Callable[[AugmentArgs, Snapshot | None], AugmentImageCommand]


class TestAugmentCommand:
    @pytest.fixture(params=[True, False], ids=["specific-image", "entire-snapshot"])
    def make_augment_command(
        self, monkeypatch: pytest.MonkeyPatch, request: Any
    ) -> MakeAugmentCommand:
        pass_reference = request.param

        def _make_augment_command(
            args: AugmentArgs, snapshot: Snapshot | None
        ) -> AugmentImageCommand:
            if not pass_reference:
                args.reference = None

            cmd = AugmentImageCommand(cli_args=args)
            monkeypatch.setattr(
                "mobster.cmd.augment.make_snapshot", lambda *_: awaitable(snapshot)
            )
            return cmd

        return _make_augment_command

    @pytest.fixture()
    def fake_cosign(self) -> "FakeCosign":
        return FakeCosign.load()

    @pytest.fixture(autouse=True)
    def patch_fake_cosign(
        self, monkeypatch: pytest.MonkeyPatch, fake_cosign: "FakeCosign"
    ) -> None:
        monkeypatch.setattr(
            "mobster.cmd.augment.CosignClient",
            lambda _: fake_cosign,
        )

    @pytest.fixture()
    def prepare_sbom(self) -> Callable[[str], SBOM]:
        def _load_sbom(reference: str) -> SBOM:
            _, digest = reference.split("@", 1)
            expected_path = TESTDATA_PATH.joinpath(f"sboms/{digest}.expected")
            with open(expected_path, "rb") as fp:
                return SBOM.from_cosign_output(fp.read(), reference)

        return _load_sbom

    @pytest.fixture()
    def augment_command_save(
        self,
        make_augment_command: MakeAugmentCommand,
    ) -> AugmentImageCommand:
        args = MagicMock()
        args.snapshot = Path("snapshot.json")
        args.output = Path("output")
        args.verification_key = Path("key.pub")

        cmd = make_augment_command(args, None)
        cmd.sbom_update_ok = True
        cmd.sboms = [
            SBOM({}, "", "quay.io/repo@sha256:aaaaaaaa"),
            SBOM({}, "", "quay.io/repo@sha256:bbbbbbbb"),
        ]

        return cmd

    @pytest.mark.asyncio
    async def test_augment_command_save(
        self,
        augment_command_save: AugmentImageCommand,
    ) -> None:
        with patch("mobster.cmd.augment.write_sbom") as mock_write_sbom:
            assert await augment_command_save.save()
            mock_write_sbom.assert_awaited()

    @pytest.mark.asyncio
    async def test_augment_command_save_failure(
        self, augment_command_save: AugmentImageCommand
    ) -> None:
        with patch("mobster.cmd.augment.write_sbom") as mock_write_sbom:
            mock_write_sbom.side_effect = ValueError
            assert not await augment_command_save.save()
            mock_write_sbom.assert_awaited()

    @pytest.mark.asyncio
    async def test_augment_execute_singlearch(
        self,
        make_augment_command: MakeAugmentCommand,
        prepare_sbom: Callable[[str], SBOM],
    ) -> None:
        reference = "quay.io/org/tenant/test@sha256:aaaaaaaa"
        repo, digest = reference.split("@", 1)

        args = AugmentArgs(
            snapshot=Path(""),
            output=Path("output"),
            verification_key=Path("key"),
            reference=reference,
        )

        snapshot = Snapshot(
            components=[
                Component(
                    name="spdx-singlearch",
                    image=Image(
                        repo,
                        digest,
                    ),
                    tags=["1.0", "latest"],
                    repository="registry.redhat.io/org/tenant/test",
                ),
            ],
        )

        cmd = make_augment_command(args, snapshot)

        await cmd.execute()

        expected = prepare_sbom(reference).doc

        assert len(cmd.sboms) == 1
        assert_spdx_sbom(cmd.sboms[0].doc, expected)

    @pytest.mark.asyncio
    async def test_augment_execute_multiarch(
        self,
        make_augment_command: MakeAugmentCommand,
        prepare_sbom: Callable[[str], SBOM],
    ) -> None:
        index_reference = "quay.io/org/tenant/test@sha256:bbbbbbbb"
        index_repo, index_digest = index_reference.split("@", 1)

        image_reference = "quay.io/org/tenant/test@sha256:cccccccc"
        image_repo, image_digest = image_reference.split("@", 1)

        args = AugmentArgs(
            snapshot=Path(""),
            output=Path("output"),
            verification_key=None,
            reference=index_reference,
        )

        snapshot = Snapshot(
            components=[
                Component(
                    name="spdx-multiarch",
                    image=IndexImage(
                        index_repo,
                        index_digest,
                        children=[Image(image_repo, image_digest)],
                    ),
                    tags=["1.0", "latest"],
                    repository="registry.redhat.io/org/tenant/test",
                ),
            ],
        )

        cmd = make_augment_command(args, snapshot)

        await cmd.execute()

        expected_sboms = [
            prepare_sbom(
                index_reference,
            ),
            prepare_sbom(image_reference),
        ]

        assert len(expected_sboms) == len(cmd.sboms)

        for actual, expected in zip(cmd.sboms, expected_sboms, strict=False):
            assert_spdx_sbom(actual.doc, expected.doc)

    @pytest.mark.asyncio
    async def test_augment_execute_cdx_singlearch(
        self,
        make_augment_command: MakeAugmentCommand,
    ) -> None:
        reference = "quay.io/org/tenant/test@sha256:dddddddd"
        repo, digest = reference.split("@", 1)

        args = AugmentArgs(
            snapshot=Path(""),
            output=Path("output"),
            verification_key=None,
            reference=reference,
        )

        snapshot = Snapshot(
            components=[
                Component(
                    name="cdx-singlearch",
                    image=Image(
                        repo,
                        digest,
                    ),
                    tags=["1.0", "latest"],
                    repository="registry.redhat.io/org/tenant/cdx-singlearch",
                ),
            ],
        )

        cmd = make_augment_command(args, snapshot)

        await cmd.execute()

        assert len(cmd.sboms) == 1
        sbom = cmd.sboms[0]
        VerifyCycloneDX.verify_components_updated(snapshot, sbom.doc)

    @pytest.mark.asyncio
    async def test_verify_sbom_failure(
        self,
        fake_cosign: "FakeCosign",
    ) -> None:
        image = Image("quay.io/repo", "sha256:aaaaaaaa")
        sbom = SBOM({}, "bad_digest", "ref")

        with pytest.raises(SBOMVerificationError):
            await verify_sbom(sbom, image, fake_cosign)

    @pytest.mark.asyncio
    async def test_update_sbom_error_handling(
        self,
        fake_cosign: "FakeCosign",
    ) -> None:
        img = Image("quay.io/repo", "sha256:aaaaaaaa")
        component = Component(
            "comp",
            image=img,
            tags=[],
            repository="quay.io/repo",
        )

        with patch("mobster.cmd.augment.update_sbom_in_situ") as mock_update:
            mock_update.side_effect = SBOMError
            assert await update_sbom(component, img, fake_cosign, verify=False) is None


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
    def load() -> "FakeCosign":
        provenances = {}
        sboms = {}

        sbom_path = TESTDATA_PATH.joinpath("sboms")
        prov_path = TESTDATA_PATH.joinpath("provenances")

        for sbom_file in os.listdir(sbom_path):
            full = sbom_path.joinpath(sbom_file)
            with open(full, "rb") as fp:
                sboms[sbom_file] = SBOM.from_cosign_output(
                    fp.read(), f"quay.io/repo@{sbom_file}"
                )

        for prov_file in os.listdir(prov_path):
            full = prov_path.joinpath(prov_file)
            with open(full, "rb") as fp:
                payload = b64encode(fp.read()).decode()
                prov = Provenance02.from_cosign_output(
                    json.dumps({"payload": payload}).encode()
                )
                provenances[prov_file] = prov

        return FakeCosign(provenances, sboms)


def load_provenance(prov_dir: Path, digest: str) -> Provenance02 | None:
    ppath = prov_dir.joinpath(digest)
    if ppath.exists():
        with open(ppath, "rb") as fp:
            payload = b64encode(fp.read()).decode()
            return Provenance02.from_cosign_output(
                json.dumps({"payload": payload}).encode()
            )

    return None


class VerifyCycloneDX:
    @staticmethod
    def verify_purl(purl: PackageURL, repository: str) -> None:
        assert purl.qualifiers is not None
        assert purl.qualifiers.get("repository_url") == repository  # type: ignore
        assert purl.name == repository.split("/")[-1]

    @staticmethod
    def verify_tags(kflx_component: Component, cdx_component: Any) -> None:
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
        except KeyError as err:
            raise AssertionError(
                "CDX component is missing evidence.identity field."
            ) from err

        for id_item in identity:
            if id_item.get("field") != "purl":
                continue
            purl = PackageURL.from_string(id_item["concludedValue"])
            VerifyCycloneDX.verify_purl(purl, kflx_component.repository)

            purl_tag = purl.qualifiers.get("tag")  # type: ignore
            assert isinstance(purl_tag, str), f"Missing tag in identity purl {purl}."
            tags.remove(purl_tag)

        assert len(tags) == 0, (
            f"Not all tags present in identity purls, missing {tags}."
        )

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
        cdx_component: Any,
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
            PackageURL.from_string(purl_str), kflx_component.repository
        )

        if verify_tags:
            VerifyCycloneDX.verify_tags(kflx_component, cdx_component)

    @staticmethod
    def verify_mobster_version_info(sbom: Any) -> None:
        """
        Verify that the mobster version info is added to the SBOM metadata.
        """
        components = sbom["metadata"]["tools"]["components"]
        assert cyclonedx.get_tools_component_dict() in components

    @staticmethod
    def verify_components_updated(snapshot: Snapshot, sbom: Any) -> None:
        """
        This method verifies that all CycloneDX container components that have a
        matching Konflux component in the release are updated.
        """
        VerifyCycloneDX.verify_component_updated(
            snapshot, sbom["metadata"]["component"], verify_tags=False
        )
        VerifyCycloneDX.verify_mobster_version_info(sbom)

        for component in sbom.get("components", []):
            VerifyCycloneDX.verify_component_updated(
                snapshot, component, verify_tags=True
            )


@pytest.mark.parametrize(
    ["purl_str", "expected"],
    [
        pytest.param(
            "pkg:oci/hello-wasm@sha256%3A244fd47e07d10?tag=v1", "sha256:244fd47e07d10"
        ),
        pytest.param("pkg:oci/hello-wasm", SBOMError),
    ],
)
def test_get_purl_digest(purl_str: str, expected: str | BaseException) -> None:
    if isinstance(expected, str):
        assert get_purl_digest(purl_str) == expected
    else:
        with pytest.raises(expected):  # type: ignore
            get_purl_digest(purl_str)


def test_cdx_augment_metadata_tools_components_empty_metadata() -> None:
    metadata: dict[str, Any] = {}
    CycloneDXVersion1()._augment_metadata_tools_components(metadata)

    assert "tools" in metadata
    assert "components" in metadata["tools"]
    assert len(metadata["tools"]["components"]) == 1
