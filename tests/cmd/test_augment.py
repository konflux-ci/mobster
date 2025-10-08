import asyncio
import json
import os
from base64 import b64encode
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from _pytest.logging import LogCaptureFixture
from packageurl import PackageURL

from mobster.cmd.augment import (
    AugmentConfig,
    AugmentImageCommand,
    get_sbom_to_filename_dict,
    load_sbom,
    update_sbom,
    verify_sbom,
)
from mobster.cmd.augment.handlers import CycloneDXVersion1, get_purl_digest
from mobster.error import SBOMError, SBOMVerificationError
from mobster.image import Image, IndexImage
from mobster.oci.artifact import SBOM, Provenance02, SBOMFormat
from mobster.oci.cosign import Cosign, RekorConfig
from mobster.release import Component, ReleaseId, ReleaseRepository, Snapshot
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
            lambda *_: fake_cosign,
        )

    @pytest.fixture(autouse=True)
    def mock_write_sbom(self, monkeypatch: pytest.MonkeyPatch) -> AsyncMock:
        """
        Fixture to patch mobster.cmd.augment.write_sbom function.
        """
        mock = AsyncMock()
        monkeypatch.setattr("mobster.cmd.augment.write_sbom", mock)
        return mock

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
            "mobster.cmd.augment.augment_sboms",
        ) as fake_update_sboms:
            fake_update_sboms.return_value = [None]
            await cmd.execute()
            assert cmd.exit_code == 1

    @pytest.mark.asyncio
    async def test_augment_execute_singlearch(
        self,
        make_augment_command: MakeAugmentCommand,
        prepare_sbom: Callable[[str], SBOM],
        mock_write_sbom: AsyncMock,
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
                    release_repositories=[
                        ReleaseRepository(
                            public_repo_url="registry.redhat.io/org/tenant/test",
                            tags=["1.0", "latest"],
                            internal_repo_url="quay.io/org/tenant/test",
                        )
                    ],
                ),
            ],
        )

        cmd = make_augment_command(args, snapshot)
        expected = prepare_sbom(reference).doc

        await cmd.execute()
        write_calls = mock_write_sbom.call_args_list
        written_doc = write_calls[0].args[0]
        assert_spdx_sbom(written_doc, expected)

    @pytest.mark.asyncio
    async def test_augment_execute_multiarch(
        self,
        make_augment_command: MakeAugmentCommand,
        prepare_sbom: Callable[[str], SBOM],
        mock_write_sbom: AsyncMock,
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
                    release_repositories=[
                        ReleaseRepository(
                            public_repo_url="registry.redhat.io/org/tenant/test",
                            tags=["1.0", "latest"],
                            internal_repo_url="quay.io/org/tenant/test",
                        )
                    ],
                ),
            ],
        )

        cmd = make_augment_command(args, snapshot)

        await cmd.execute()
        write_calls = mock_write_sbom.call_args_list

        expected_sboms = [
            prepare_sbom(
                index_reference,
            ),
            prepare_sbom(image_reference),
        ]

        assert len(expected_sboms) == len(write_calls)

        for write_call, expected in zip(write_calls, expected_sboms, strict=False):
            assert_spdx_sbom(write_call.args[0], expected.doc)

    @pytest.mark.asyncio
    async def test_augment_execute_cdx_singlearch(
        self,
        make_augment_command: MakeAugmentCommand,
        mock_write_sbom: AsyncMock,
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
                    release_repositories=[
                        ReleaseRepository(
                            public_repo_url="registry.redhat.io/org/tenant/cdx-singlearch",
                            tags=["1.0", "latest"],
                            internal_repo_url="quay.io/org/tenant/cdx-singlearch",
                        )
                    ],
                ),
            ],
        )

        cmd = make_augment_command(args, snapshot)

        await cmd.execute()
        write_calls = mock_write_sbom.call_args_list

        assert len(write_calls) == 1
        written_sbom = write_calls[0].args[0]
        VerifyCycloneDX.verify_components_updated(snapshot, written_sbom)

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
    @patch("mobster.cmd.augment.verify_sbom")
    async def test_load_sbom_warn(
        self,
        mock_verify_sbom: AsyncMock,
        fake_cosign: "FakeCosign",
        caplog: LogCaptureFixture,
    ) -> None:
        """
        This test verifies the workflow doesn't raise an exception
        when SBOM has a different digest than mentioned in the attestation.
        """
        mock_verify_sbom.side_effect = SBOMVerificationError("a", "b")

        image = Image("quay.io/repo", "sha256:aaaaaaaa")
        _, attestation_valid = await load_sbom(image, fake_cosign, True)
        assert attestation_valid is False
        assert caplog.records[-1].exc_text
        assert (
            "SBOM digest verification from provenance failed. "
            "Expected digest: a, actual digest: b" in caplog.records[-1].exc_text
        )

    @pytest.mark.asyncio
    async def test_update_sbom_error_handling(
        self,
        fake_cosign: "FakeCosign",
    ) -> None:
        img = Image("quay.io/repo", "sha256:aaaaaaaa")
        repo = ReleaseRepository(
            public_repo_url="quay.io/repo", tags=[], internal_repo_url="quay.io/repo"
        )

        with patch("mobster.cmd.augment.update_sbom_in_situ") as mock_update:
            mock_update.side_effect = SBOMError
            sem = asyncio.Semaphore(1)
            config = AugmentConfig(
                cosign=fake_cosign,
                verify=False,
                semaphore=sem,
                output_dir=Path("/tmp"),
            )
            assert await update_sbom(config, repo, img) is None


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

    async def attest_sbom(
        self,
        sbom_path: Path,
        image_ref: str,
        sbom_format: SBOMFormat,
        rekor_config: RekorConfig | None = None,
    ) -> None:
        pass

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

    def can_sign(self) -> bool:
        return True

    async def attest_provenance(self, provenance: Provenance02, image_ref: str) -> None:
        pass


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
    def verify_purl(purl: PackageURL, repositories: list[ReleaseRepository]) -> None:
        repo_urls = {repo.public_repo_url for repo in repositories}
        repo_names = {repo.public_repo_url.split("/")[-1] for repo in repositories}
        assert purl.qualifiers is not None
        assert purl.qualifiers.get("repository_url") in repo_urls  # type: ignore
        assert purl.name in repo_names

    @staticmethod
    def verify_tags(kflx_component: Component, cdx_component: Any) -> None:
        """
        Verify that all tags are present in PURLs in the evidence.identity field
        if there are more than one.
        """
        if (
            len(kflx_component.release_repositories) == 1
            and len(kflx_component.release_repositories[0].tags) == 1
        ):
            # in this case, we don't populate the evidence.identity field so
            # let's make sure we add the tag to the component.purl field
            purl = PackageURL.from_string(cdx_component["purl"])
            assert purl.qualifiers is not None
            assert (
                purl.qualifiers.get("tag")  # type: ignore
                == kflx_component.release_repositories[0].tags[0]
            )
            return

        tags = set()
        for repo in kflx_component.release_repositories:
            tags.update(repo.tags)

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
            VerifyCycloneDX.verify_purl(purl, kflx_component.release_repositories)

            purl_tag = purl.qualifiers.get("tag")  # type: ignore
            assert isinstance(purl_tag, str), f"Missing tag in identity purl {purl}."
            tags.discard(purl_tag)

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
            PackageURL.from_string(purl_str), kflx_component.release_repositories
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
            release_repositories=[
                ReleaseRepository(
                    public_repo_url="registry.redhat.io/test",
                    tags=["latest"],
                    internal_repo_url="quay.io/test",
                )
            ],
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
            release_repositories=[
                ReleaseRepository(
                    public_repo_url="registry.redhat.io/test",
                    tags=["latest"],
                    internal_repo_url="quay.io/test",
                )
            ],
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
                "mobster.cmd.augment.load_sbom", lambda *_: awaitable((test_sbom, True))
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
            config = AugmentConfig(
                cosign=mock_cosign,
                verify=False,
                semaphore=semaphore,
                output_dir=Path("/tmp"),
            )
            result = await update_sbom(
                config, component.release_repositories[0], component.image
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
            config = AugmentConfig(
                cosign=mock_cosign,
                verify=False,
                semaphore=semaphore,
                output_dir=Path("/tmp"),
            )
            result = await update_sbom(
                config, index_component.release_repositories[0], index_component.image
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
            config = AugmentConfig(
                cosign=mock_cosign,
                verify=False,
                semaphore=semaphore,
                output_dir=Path("/tmp"),
            )
            result = await update_sbom(
                config, component.release_repositories[0], component.image
            )
            assert result is not None

    @pytest.mark.asyncio
    async def test_cyclonedx_with_index_image_fails(
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
        config = AugmentConfig(
            cosign=mock_cosign,
            verify=False,
            semaphore=semaphore,
            output_dir=Path("/tmp"),
        )
        assert (
            await update_sbom(
                config, index_component.release_repositories[0], index_component.image
            )
            is None
        )

    @pytest.mark.asyncio
    async def test_unsupported_format_fails(
        self,
        component: Component,
        mock_cosign: MagicMock,
        semaphore: asyncio.Semaphore,
        setup_load_sbom: Callable[[SBOM], None],
    ) -> None:
        test_sbom = SBOM({"unknown": "format"}, "digest", "ref")
        setup_load_sbom(test_sbom)
        config = AugmentConfig(
            cosign=mock_cosign,
            verify=False,
            semaphore=semaphore,
            output_dir=Path("/tmp"),
        )
        assert (
            await update_sbom(
                config, component.release_repositories[0], component.image
            )
            is None
        )


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
    with pytest.raises(
        ValueError, match="CDX update SBOM does not support index images."
    ):
        handler.update_sbom(
            ReleaseRepository(
                public_repo_url="quay.io/repo",
                tags=["latest"],
                internal_repo_url="quay.io/repo",
            ),
            index_image,
            {},
        )
