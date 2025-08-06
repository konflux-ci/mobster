import asyncio
import json
import logging
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
    get_sbom_to_filename_dict,
    update_sbom,
    update_sboms,
    verify_sbom,
)
from mobster.cmd.augment.handlers import CycloneDXVersion1, get_purl_digest
from mobster.error import SBOMError, SBOMVerificationError
from mobster.image import Image, IndexImage
from mobster.oci.artifact import SBOM, Provenance02
from mobster.oci.cosign import Cosign
from mobster.release import Component, ReleaseId, Snapshot
from mobster.sbom import cyclonedx
from tests.conftest import assert_spdx_sbom, awaitable

TESTDATA_PATH = Path(__file__).parent.parent.joinpath("data/component")


@dataclass
class AugmentArgs:
    snapshot: Path
    output: Path
    verification_key: Path | None
    reference: str | None
    concurrency: int = 1
    release_id: str | None = None


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
        cmd.sboms = [
            SBOM({}, "", "quay.io/repo@sha256:aaaaaaaa"),
            SBOM({}, "", "quay.io/repo@sha256:bbbbbbbb"),
        ]

        return cmd

    @pytest.mark.asyncio
    async def test_augment_command_name(
        self,
        augment_command_save: AugmentImageCommand,
    ) -> None:
        """
        Test to avoid breaking monitoring in case that AugmentImageCommand is changed
        Used by Splunk
        """
        assert augment_command_save.name == "AugmentImageCommand"

    @pytest.mark.asyncio
    async def test_augment_command_save(
        self,
        augment_command_save: AugmentImageCommand,
    ) -> None:
        with patch("mobster.cmd.augment.write_sbom") as mock_write_sbom:
            await augment_command_save.save()
            mock_write_sbom.assert_awaited()

    @pytest.mark.asyncio
    async def test_augment_command_save_failure(
        self, augment_command_save: AugmentImageCommand
    ) -> None:
        with patch("mobster.cmd.augment.write_sbom") as mock_write_sbom:
            mock_write_sbom.side_effect = ValueError
            await augment_command_save.save()
            assert augment_command_save.exit_code == 1
            mock_write_sbom.assert_awaited()

    @pytest.mark.asyncio
    async def test_augment_execute_failure(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """
        Test that the exit code is set to 1 if SBOM update fails.
        """
        args = AugmentArgs(
            snapshot=Path(""),
            output=Path("output"),
            verification_key=Path("key"),
            reference="",
        )
        cmd = AugmentImageCommand(cli_args=args)

        monkeypatch.setattr(
            "mobster.cmd.augment.make_snapshot", lambda _, __, ___: awaitable(None)
        )

        with patch(
            "mobster.cmd.augment.update_sboms",
        ) as fake_update_sboms:
            fake_update_sboms.return_value = (False, [])
            await cmd.execute()
            assert cmd.exit_code == 1

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
            release_id="release-id-1",
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
            sem = asyncio.Semaphore(1)
            assert (
                await update_sbom(
                    component, img, fake_cosign, verify=False, semaphore=sem
                )
                is None
            )


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


def test_get_sbom_to_filename_dict_duplicate_prevention() -> None:
    """
    Test the get_sbom_to_filename_dict functions correctly handles SBOMs with
    duplicate image references.
    """
    sbom1 = SBOM({}, "digest1", "quay.io/repo@sha256:aaaaaaaa")
    sbom2 = SBOM({}, "digest2", "quay.io/repo@sha256:aaaaaaaa")
    sbom3 = SBOM({}, "digest3", "quay.io/repo@sha256:aaaaaaaa")

    sboms = [sbom1, sbom2, sbom3]
    result = get_sbom_to_filename_dict(sboms)

    assert len(result) == 3
    assert sbom1 in result
    assert sbom2 in result
    assert sbom3 in result

    # check that all filenames are unique despite same reference
    filenames = list(result.values())
    assert len(set(filenames)) == len(filenames)

    # check that all filenames contain the same digest
    for filename in filenames:
        assert "sha256:aaaaaaaa" in filename


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


class TestUpdateFormatSupport:
    @pytest.fixture
    def component(self) -> Component:
        return Component(
            name="test",
            image=Image("quay.io/test", "sha256:abc123"),
            tags=["latest"],
            repository="registry.redhat.io/test",
        )

    @pytest.fixture
    def index_component(self) -> Component:
        return Component(
            name="test",
            image=IndexImage(
                "quay.io/test",
                "sha256:def456",
                children=[Image("quay.io/test", "sha256:child123")],
            ),
            tags=["latest"],
            repository="registry.redhat.io/test",
        )

    @pytest.fixture
    def mock_cosign(self) -> MagicMock:
        return MagicMock()

    @pytest.fixture
    def semaphore(self) -> asyncio.Semaphore:
        return asyncio.Semaphore(1)

    @pytest.fixture
    def setup_load_sbom(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> Callable[[SBOM], None]:
        def _setup_load_sbom(test_sbom: SBOM) -> None:
            monkeypatch.setattr(
                "mobster.cmd.augment.load_sbom", lambda *_: awaitable(test_sbom)
            )

        return _setup_load_sbom

    @pytest.mark.parametrize(
        "version",
        ["SPDX-2.0", "SPDX-2.1", "SPDX-2.2", "SPDX-2.2.1", "SPDX-2.2.2", "SPDX-2.3"],
    )
    @pytest.mark.asyncio
    async def test_spdx_supported(
        self,
        component: Component,
        mock_cosign: MagicMock,
        semaphore: asyncio.Semaphore,
        setup_load_sbom: Callable[[SBOM], None],
        version: str,
    ) -> None:
        test_sbom = SBOM({"spdxVersion": version}, "digest", "ref")
        setup_load_sbom(test_sbom)
        with patch("mobster.cmd.augment.handlers.SPDXVersion2.update_sbom"):
            result = await update_sbom(
                component, component.image, mock_cosign, False, semaphore
            )
            assert result is not None

    @pytest.mark.parametrize(
        "version",
        ["SPDX-2.0", "SPDX-2.1", "SPDX-2.2", "SPDX-2.2.1", "SPDX-2.2.2", "SPDX-2.3"],
    )
    @pytest.mark.asyncio
    async def test_spdx_with_index_image(
        self,
        index_component: Component,
        mock_cosign: MagicMock,
        semaphore: asyncio.Semaphore,
        setup_load_sbom: Callable[[SBOM], None],
        version: str,
    ) -> None:
        test_sbom = SBOM({"spdxVersion": version}, "digest", "ref")
        setup_load_sbom(test_sbom)
        with patch("mobster.cmd.augment.handlers.SPDXVersion2.update_sbom"):
            result = await update_sbom(
                index_component, index_component.image, mock_cosign, False, semaphore
            )
            assert result is not None

    @pytest.mark.parametrize("version", ["1.4", "1.5", "1.6"])
    @pytest.mark.asyncio
    async def test_cyclonedx_supported(
        self,
        component: Component,
        mock_cosign: MagicMock,
        semaphore: asyncio.Semaphore,
        setup_load_sbom: Callable[[SBOM], None],
        version: str,
    ) -> None:
        test_sbom = SBOM(
            {"bomFormat": "CycloneDX", "specVersion": version}, "digest", "ref"
        )
        setup_load_sbom(test_sbom)
        with patch("mobster.cmd.augment.handlers.CycloneDXVersion1.update_sbom"):
            result = await update_sbom(
                component, component.image, mock_cosign, False, semaphore
            )
            assert result is not None

    @pytest.mark.asyncio
    async def test_cyclonedx_with_index_image_returns_none(
        self,
        index_component: Component,
        mock_cosign: MagicMock,
        semaphore: asyncio.Semaphore,
        setup_load_sbom: Callable[[SBOM], None],
    ) -> None:
        test_sbom = SBOM(
            {"bomFormat": "CycloneDX", "specVersion": "1.6"}, "digest", "ref"
        )
        setup_load_sbom(test_sbom)
        result = await update_sbom(
            index_component, index_component.image, mock_cosign, False, semaphore
        )
        assert result is None

    @pytest.mark.asyncio
    async def test_unsupported_format_returns_none(
        self,
        component: Component,
        mock_cosign: MagicMock,
        semaphore: asyncio.Semaphore,
        setup_load_sbom: Callable[[SBOM], None],
    ) -> None:
        test_sbom = SBOM({"unknown": "format"}, "digest", "ref")
        setup_load_sbom(test_sbom)
        result = await update_sbom(
            component, component.image, mock_cosign, False, semaphore
        )
        assert result is None


def test_cdx_augment_metadata_tools_components_empty_metadata() -> None:
    metadata: dict[str, Any] = {}
    CycloneDXVersion1()._augment_metadata_tools_components(metadata)

    assert "tools" in metadata
    assert "components" in metadata["tools"]
    assert len(metadata["tools"]["components"]) == 1


def test_cdx_augment_properties_release_id() -> None:
    sbom: dict[str, Any] = {}
    release_id = ReleaseId.new()
    CycloneDXVersion1()._augment_properties_release_id(sbom, release_id)
    assert {"name": "release_id", "value": str(release_id)} in sbom["properties"]


def test_cdx_update_sbom_raises_error_for_index_image() -> None:
    handler = CycloneDXVersion1()

    index_image = IndexImage("quay.io/repo", "sha256:test", children=[])
    component = Component(
        "test",
        image=Image("quay.io/repo", "sha256:other"),
        tags=[],
        repository="quay.io/repo",
    )
    with pytest.raises(
        ValueError, match="CDX update SBOM does not support index images."
    ):
        handler.update_sbom(component, index_image, {})


class TestUpdateSbomsBatching:
    """Tests for the batching functionality in update_sboms."""

    @pytest.fixture
    def fake_cosign(self) -> "FakeCosign":
        return FakeCosign.load()

    @pytest.fixture
    def mock_snapshot(self) -> Snapshot:
        """Create a snapshot with multiple components for testing batching."""
        components = []
        for i in range(25):  # 25 components to test batching
            components.append(
                Component(
                    name=f"component-{i}",
                    image=Image("quay.io/repo", f"sha256:{'a' * 63}{i:01d}"),
                    tags=["latest"],
                    repository="registry.redhat.io/test",
                )
            )
        return Snapshot(components=components)

    @pytest.mark.asyncio
    async def test_update_sboms_processes_in_batches(
        self,
        mock_snapshot: Snapshot,
        fake_cosign: "FakeCosign",
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Test that update_sboms processes components in batches."""
        with patch("mobster.cmd.augment.update_component_sboms") as mock_update:
            mock_update.return_value = (True, [])

            # Use concurrency limit of 10 to create 3 batches (25 components)
            concurrency_limit = 10
            with caplog.at_level(logging.INFO, logger="mobster.cmd.augment"):
                await update_sboms(mock_snapshot, fake_cosign, False, concurrency_limit)

            # Verify batch logging
            assert "Processing batch 1/3 (10 components)" in caplog.text
            assert "Processing batch 2/3 (10 components)" in caplog.text
            assert "Processing batch 3/3 (5 components)" in caplog.text

            # Verify all components were processed
            assert mock_update.call_count == 25

    @pytest.mark.asyncio
    async def test_update_sboms_batch_size_equals_concurrency(
        self,
        mock_snapshot: Snapshot,
        fake_cosign: "FakeCosign",
    ) -> None:
        """Test that batch size equals concurrency limit."""
        with patch("mobster.cmd.augment.update_component_sboms") as mock_update:
            mock_update.return_value = (True, [])

            concurrency_limit = 5
            await update_sboms(mock_snapshot, fake_cosign, False, concurrency_limit)

            # Should process in 5 batches of 5 components each
            assert mock_update.call_count == 25

    @pytest.mark.asyncio
    async def test_update_sboms_handles_failures_across_batches(
        self,
        mock_snapshot: Snapshot,
        fake_cosign: "FakeCosign",
    ) -> None:
        """Test that failures in one batch don't prevent processing other batches."""
        with patch("mobster.cmd.augment.update_component_sboms") as mock_update:
            # First batch succeeds, second batch has failures, third batch succeeds
            mock_update.side_effect = (
                [
                    (True, [MagicMock()])
                    for _ in range(10)  # First batch
                ]
                + [
                    (False, [])
                    for _ in range(10)  # Second batch fails
                ]
                + [
                    (True, [MagicMock()])
                    for _ in range(5)  # Third batch
                ]
            )

            concurrency_limit = 10
            all_ok, all_sboms = await update_sboms(
                mock_snapshot, fake_cosign, False, concurrency_limit
            )

            # Should return False due to failures in second batch
            assert not all_ok
            # Should still have SBOMs from successful batches
            assert len(all_sboms) == 15  # 10 from first + 5 from third batch

    @pytest.mark.asyncio
    async def test_update_sboms_single_batch_when_components_less_than_limit(
        self,
        fake_cosign: "FakeCosign",
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Test that when components < concurrency limit, only one batch is created."""
        # Create snapshot with only 3 components
        components = [
            Component(
                name=f"component-{i}",
                image=Image("quay.io/repo", f"sha256:{'b' * 63}{i:01d}"),
                tags=["latest"],
                repository="registry.redhat.io/test",
            )
            for i in range(3)
        ]
        snapshot = Snapshot(components=components)

        with patch("mobster.cmd.augment.update_component_sboms") as mock_update:
            mock_update.return_value = (True, [])

            concurrency_limit = 10  # More than component count
            with caplog.at_level(logging.INFO, logger="mobster.cmd.augment"):
                await update_sboms(snapshot, fake_cosign, False, concurrency_limit)

            # Should show only one batch
            assert "Processing batch 1/1 (3 components)" in caplog.text
            assert mock_update.call_count == 3
