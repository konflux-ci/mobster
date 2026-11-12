import asyncio
import json
import os
from base64 import b64encode
from collections.abc import Callable
from copy import deepcopy
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from packageurl import PackageURL

from mobster.cmd.augment.bom import AugmentConfig, BOMRefDetail
from mobster.cmd.augment.handlers import CycloneDXVersion1, get_purl_digest
from mobster.cmd.augment.sbom import AugmentImageCommand, SBOMAugmenter
from mobster.error import SBOMError, SBOMVerificationError
from mobster.image import Image, IndexImage
from mobster.oci.artifact import BOM, SLSAProvenance
from mobster.oci.cosign import SupportsFetch
from mobster.release import Component, ReleaseId, ReleaseRepository, Snapshot
from mobster.sbom import cyclonedx
from tests.conftest import assert_spdx_sbom, awaitable

TESTDATA_PATH = Path(__file__).parent.parent.parent.joinpath("data/component")


@dataclass
class AugmentArgs:
    snapshot: Path
    output: Path
    verification_key: str | None
    reference: str | None
    concurrency: int = 1
    release_id: str | None = None
    cpes: list[str] = field(default_factory=list)


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
                "mobster.cmd.augment.sbom.make_snapshot", lambda *_: awaitable(snapshot)
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
            "mobster.cmd.augment.bom.cosign.StaticKeyFetcher",
            lambda *_: fake_cosign,
        )

    @pytest.fixture(autouse=True)
    def mock_write_sbom(self, monkeypatch: pytest.MonkeyPatch) -> AsyncMock:
        """
        Fixture to patch the shared BOM writer.
        """
        mock = AsyncMock()
        monkeypatch.setattr("mobster.cmd.augment.bom.write_bom", mock)
        return mock

    @pytest.fixture()
    def prepare_sbom(self) -> Callable[[str], BOM]:
        def _load_sbom(reference: str) -> BOM:
            _, digest = reference.split("@", 1)
            expected_path = TESTDATA_PATH.joinpath(f"sboms/{digest}.expected")
            with open(expected_path, "rb") as fp:
                return BOM.from_cosign_output(
                    fp.read(), Image(*reference.split("@", 1))
                )

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
            verification_key="key",
            reference="",
        )
        cmd = AugmentImageCommand(cli_args=args)

        monkeypatch.setattr(
            "mobster.cmd.augment.sbom.make_snapshot", lambda _, __, ___: awaitable(None)
        )

        with patch(
            "mobster.cmd.augment.bom.BOMAugmenter.augment_boms",
        ) as fake_update_sboms:
            fake_update_sboms.return_value = [None]
            await cmd.execute()
            assert cmd.exit_code == 1

    @pytest.mark.asyncio
    @pytest.mark.parametrize("verification_key", [None, "key.pub"])
    async def test_augment_uses_static_key_fetcher(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        fake_cosign: "FakeCosign",
        verification_key: str | None,
    ) -> None:
        args = AugmentArgs(
            snapshot=Path("snapshot.json"),
            output=tmp_path,
            verification_key=verification_key,
            reference=None,
        )
        command = AugmentImageCommand(cli_args=args)

        monkeypatch.setattr(
            "mobster.cmd.augment.sbom.make_snapshot", lambda *_: awaitable(None)
        )

        capture_config = AsyncMock(return_value=[])
        monkeypatch.setattr(
            "mobster.cmd.augment.bom.BOMAugmenter.augment_boms", capture_config
        )

        await command.execute()

        capture_config.assert_awaited_once()
        assert capture_config.call_args.args[0].cosign is fake_cosign
        assert capture_config.call_args.args[0].verify is (verification_key is not None)

    @pytest.mark.asyncio
    async def test_augment_fails_when_fetcher_cannot_verify_attestation(
        self,
        make_augment_command: MakeAugmentCommand,
        fake_cosign: "FakeCosign",
        mock_write_sbom: AsyncMock,
        tmp_path: Path,
    ) -> None:
        image = Image("quay.io/org/tenant/test", "sha256:aaaaaaaa")
        args = AugmentArgs(
            snapshot=Path("snapshot.json"),
            output=tmp_path,
            verification_key="key.pub",
            reference=image.reference,
        )
        snapshot = Snapshot(
            components=[
                Component(
                    name="unverifiable-sbom",
                    image=image,
                    release_repositories=[
                        ReleaseRepository(
                            public_repo_url="registry.redhat.io/repo",
                            tags=["latest"],
                            internal_repo_url="quay.io/repo",
                        )
                    ],
                )
            ]
        )
        command = make_augment_command(args, snapshot)
        with (
            patch.object(
                fake_cosign,
                "fetch_sbom",
                AsyncMock(side_effect=SBOMVerificationError("key mismatch")),
            ) as fetch_sbom,
            patch(
                "mobster.cmd.augment.sbom.SBOMAugmenter.verify_sbom"
            ) as verify_provenance,
        ):
            await command.execute()

        assert command.exit_code == 1
        fetch_sbom.assert_awaited_once_with(image)
        verify_provenance.assert_not_awaited()
        mock_write_sbom.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_augment_execute_singlearch(
        self,
        make_augment_command: MakeAugmentCommand,
        prepare_sbom: Callable[[str], BOM],
        mock_write_sbom: AsyncMock,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        reference = "quay.io/org/tenant/test@sha256:aaaaaaaa"
        repo, digest = reference.split("@", 1)

        args = AugmentArgs(
            snapshot=Path(""),
            output=Path("output"),
            verification_key="key",
            reference=reference,
            release_id="release-id-1",
            cpes=["cpe:/a:redhat:discovery:1.0::el9"],
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
        prepare_sbom: Callable[[str], BOM],
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
    @pytest.mark.parametrize(
        "cpes",
        [
            [],
            ["cpe:/a:redhat:discovery:1.0::el9"],
            [
                "cpe:/a:redhat:discovery:1.0::el9",
                "cpe:/a:redhat:discovery:1.0::el8",
                "cpe:/a:redhat:discovery:1.0::el7",
            ],
        ],
        ids=["no-cpes", "one-cpe", "multiple-cpes"],
    )
    async def test_augment_execute_cdx_singlearch(
        self,
        make_augment_command: MakeAugmentCommand,
        mock_write_sbom: AsyncMock,
        cpes: list[str],
    ) -> None:
        reference = "quay.io/org/tenant/test@sha256:dddddddd"
        repo, digest = reference.split("@", 1)

        args = AugmentArgs(
            snapshot=Path(""),
            output=Path("output"),
            verification_key=None,
            reference=reference,
            cpes=cpes,
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
        VerifyCycloneDX.verify_components_updated(snapshot, written_sbom, cpes)

    @pytest.mark.asyncio
    async def test_verify_sbom_failure(
        self,
        fake_cosign: "FakeCosign",
    ) -> None:
        image = Image("quay.io/repo", "sha256:aaaaaaaa")
        sbom = BOM({}, "bad_digest", image)

        with pytest.raises(SBOMVerificationError):
            await SBOMAugmenter().verify_sbom(sbom, image, fake_cosign)

    @pytest.mark.asyncio
    async def test_verify_sbom_missing_provenance_digest(self) -> None:
        """Missing provenance evidence must identify the unverified image."""
        image = Image("quay.io/repo", "sha256:aaaaaaaa")
        sbom = BOM({}, "sha256:bbbbbbbb", image)
        provenance = SLSAProvenance(None, {})
        cosign = FakeCosign({image.digest: provenance}, {image.digest: sbom})

        with pytest.raises(SBOMVerificationError) as exc_info:
            await SBOMAugmenter.verify_sbom(sbom, image, cosign)

        assert str(exc_info.value) == (
            f"Provenance does not contain SBOM_BLOB_URL for image {image.reference}."
        )

    @pytest.mark.asyncio
    @pytest.mark.parametrize("verify", [True, False])
    @pytest.mark.parametrize("signature_verified", [True, False])
    async def test_load_sbom_verification(
        self,
        fake_cosign: "FakeCosign",
        verify: bool,
        signature_verified: bool,
    ) -> None:
        image = Image("quay.io/repo", "sha256:aaaaaaaa")
        sbom = fake_cosign.sboms[image.digest]
        sbom.signature_verified = signature_verified
        mock_config = MagicMock()
        mock_config.cosign = fake_cosign
        mock_config.verify = verify

        with patch("mobster.cmd.augment.sbom.SBOMAugmenter.verify_sbom") as mock_verify:
            loaded_sbom = await SBOMAugmenter().load_bom(image, mock_config)

        assert loaded_sbom is not sbom
        assert loaded_sbom.doc == sbom.doc
        assert loaded_sbom.digest == sbom.digest
        assert loaded_sbom.image == image
        assert loaded_sbom.signature_verified == signature_verified
        if verify and not signature_verified:
            mock_verify.assert_awaited_once_with(loaded_sbom, image, fake_cosign)
        else:
            mock_verify.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_update_sbom_error_handling(
        self,
        fake_cosign: "FakeCosign",
    ) -> None:
        img = Image("quay.io/repo", "sha256:aaaaaaaa")
        repo = ReleaseRepository(
            public_repo_url="quay.io/repo", tags=[], internal_repo_url="quay.io/repo"
        )

        with patch(
            "mobster.cmd.augment.sbom.SBOMAugmenter.update_bom_in_situ"
        ) as mock_update:
            mock_update.side_effect = SBOMError
            sem = asyncio.Semaphore(1)
            config = AugmentConfig(
                cosign=fake_cosign,
                verify=False,
                semaphore=sem,
                output_dir=Path("/tmp"),
            )
            assert await SBOMAugmenter().update_bom(config, repo, img) is None
            mock_update.assert_called_once()

    @pytest.mark.asyncio
    async def test_update_signed_attestation_without_konflux_provenance(
        self,
        fake_cosign: "FakeCosign",
        tmp_path: Path,
        mock_write_sbom: AsyncMock,
    ) -> None:
        image = Image("quay.io/org/tenant/test", "sha256:aaaaaaaa")
        sbom = fake_cosign.sboms["sha256:aaaaaaaa"]
        sbom.signature_verified = True
        verified_fetcher = FakeCosign({}, {image.digest: sbom})
        repository = ReleaseRepository(
            public_repo_url="registry.redhat.io/repo",
            tags=["latest"],
            internal_repo_url="quay.io/repo",
        )
        config = AugmentConfig(
            cosign=verified_fetcher,
            verify=True,
            semaphore=asyncio.Semaphore(1),
            output_dir=tmp_path,
        )

        result = await SBOMAugmenter().update_bom(config, repository, image)

        assert result is not None
        mock_write_sbom.assert_awaited_once()


class FakeCosign(SupportsFetch):
    def __init__(
        self, provenances: dict[str, SLSAProvenance], sboms: dict[str, BOM]
    ) -> None:
        self.provenances = provenances
        self.sboms = sboms

    async def fetch_latest_provenance(self, image: Image) -> SLSAProvenance:
        return [self.provenances[image.digest]][0]

    async def fetch_sbom(self, image: Image) -> BOM:
        sbom = deepcopy(self.sboms[image.digest])
        sbom.image = image
        return sbom

    @staticmethod
    def load() -> "FakeCosign":
        provenances = {}
        sboms = {}

        sbom_path = TESTDATA_PATH.joinpath("sboms")

        prov_path = TESTDATA_PATH.joinpath("provenances")

        for sbom_file in os.listdir(sbom_path):
            full = sbom_path.joinpath(sbom_file)
            with open(full, "rb") as fp:
                sboms[sbom_file] = BOM.from_cosign_output(
                    fp.read(), Image("quay.io/repo", sbom_file)
                )

        for prov_file in os.listdir(prov_path):
            full = prov_path.joinpath(prov_file)
            with open(full, "rb") as fp:
                payload = b64encode(fp.read()).decode()
                prov = SLSAProvenance.parse(json.dumps({"payload": payload}).encode())
                provenances[prov_file] = prov

        return FakeCosign(provenances, sboms)

    async def attest_provenance(self, predicate: Any, image_ref: str) -> None:
        pass


def test_get_sbom_to_filename_dict_duplicate_prevention() -> None:
    """
    Test the get_sbom_to_filename_dict functions correctly handles SBOMs with
    duplicate image references.
    """
    sbom1 = BOM({}, "digest1", Image("quay.io/repo", "sha256:aaaaaaaa"))
    sbom2 = BOM({}, "digest2", Image("quay.io/repo", "sha256:aaaaaaaa"))
    sbom3 = BOM({}, "digest3", Image("quay.io/repo", "sha256:aaaaaaaa"))

    sboms = [sbom1, sbom2, sbom3]
    result = SBOMAugmenter().get_sbom_to_filename_dict(sboms)

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
        cpes: list[str],
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

        assert cdx_component.get("cpe") == (cpes[0] if cpes else None)
        identity = cdx_component.get("evidence", {}).get("identity", [])
        assert [item for item in identity if item.get("field") == "cpe"] == [
            {"field": "cpe", "concludedValue": cpe} for cpe in cpes[1:]
        ]

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
    def verify_components_updated(
        snapshot: Snapshot, sbom: Any, cpes: list[str]
    ) -> None:
        """
        This method verifies that all CycloneDX container components that have a
        matching Konflux component in the release are updated.
        """
        VerifyCycloneDX.verify_component_updated(
            snapshot, sbom["metadata"]["component"], verify_tags=False, cpes=cpes
        )
        VerifyCycloneDX.verify_mobster_version_info(sbom)

        for component in sbom.get("components", []):
            VerifyCycloneDX.verify_component_updated(
                snapshot,
                component,
                verify_tags=True,
                cpes=cpes,
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
    ) -> Callable[[BOM], AsyncMock]:
        def _setup_load_sbom(test_sbom: BOM) -> AsyncMock:
            mock = AsyncMock(return_value=test_sbom)
            monkeypatch.setattr("mobster.cmd.augment.sbom.SBOMAugmenter.load_bom", mock)
            return mock

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
        tmp_path: Path,
        setup_load_sbom: Callable[[BOM], AsyncMock],
        version: str,
    ) -> None:
        test_sbom = BOM({"spdxVersion": version}, "digest", component.image)
        load_sbom = setup_load_sbom(test_sbom)
        with patch("mobster.cmd.augment.handlers.SPDXVersion2.update_sbom"):
            config = AugmentConfig(
                cosign=mock_cosign,
                verify=False,
                semaphore=semaphore,
                output_dir=tmp_path,
            )
            result = await SBOMAugmenter().update_bom(
                config, component.release_repositories[0], component.image
            )
            assert isinstance(result, BOMRefDetail)
            load_sbom.assert_awaited_once_with(component.image, config)

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
        setup_load_sbom: Callable[[BOM], AsyncMock],
        version: str,
    ) -> None:
        test_sbom = BOM({"spdxVersion": version}, "digest", index_component.image)
        setup_load_sbom(test_sbom)
        with patch("mobster.cmd.augment.handlers.SPDXVersion2.update_sbom"):
            config = AugmentConfig(
                cosign=mock_cosign,
                verify=False,
                semaphore=semaphore,
                output_dir=Path("/tmp"),
            )
            result = await SBOMAugmenter().update_bom(
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
        tmp_path: Path,
        setup_load_sbom: Callable[[BOM], AsyncMock],
        version: str,
    ) -> None:
        test_sbom = BOM(
            {"bomFormat": "CycloneDX", "specVersion": version},
            "digest",
            component.image,
        )
        load_sbom = setup_load_sbom(test_sbom)
        with patch("mobster.cmd.augment.handlers.CycloneDXVersion1.update_sbom"):
            config = AugmentConfig(
                cosign=mock_cosign,
                verify=False,
                semaphore=semaphore,
                output_dir=tmp_path,
            )
            result = await SBOMAugmenter().update_bom(
                config, component.release_repositories[0], component.image
            )
            assert isinstance(result, BOMRefDetail)
            load_sbom.assert_awaited_once_with(component.image, config)

    @pytest.mark.asyncio
    async def test_cyclonedx_with_index_image_fails(
        self,
        index_component: Component,
        mock_cosign: MagicMock,
        semaphore: asyncio.Semaphore,
        setup_load_sbom: Callable[[BOM], AsyncMock],
    ) -> None:
        test_sbom = BOM(
            {"bomFormat": "CycloneDX", "specVersion": "1.6"},
            "digest",
            index_component.image,
        )
        setup_load_sbom(test_sbom)
        config = AugmentConfig(
            cosign=mock_cosign,
            verify=False,
            semaphore=semaphore,
            output_dir=Path("/tmp"),
        )
        assert (
            await SBOMAugmenter().update_bom(
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
        setup_load_sbom: Callable[[BOM], AsyncMock],
    ) -> None:
        test_sbom = BOM({"unknown": "format"}, "digest", component.image)
        setup_load_sbom(test_sbom)
        config = AugmentConfig(
            cosign=mock_cosign,
            verify=False,
            semaphore=semaphore,
            output_dir=Path("/tmp"),
        )
        assert (
            await SBOMAugmenter().update_bom(
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


@pytest.mark.asyncio
@pytest.mark.parametrize("digest", ["sha256:aaaaaaaa"], ids=["spdx"])
async def test_release_sbom_to_two_repositories(digest: str, tmp_path: Path) -> None:
    """Test that the SBOMs are updated separately for each release repository."""
    cosign = FakeCosign.load()
    sbom = cosign.sboms[digest]
    repositories = [
        ReleaseRepository(
            public_repo_url="registry.redhat.io/product/stable",
            internal_repo_url="quay.io/release/stable",
            tags=["1.0", "stable"],
        ),
        ReleaseRepository(
            public_repo_url="registry.redhat.io/product/preview",
            internal_repo_url="quay.io/release/preview",
            tags=["2.0", "preview"],
        ),
    ]
    component = Component("test", sbom.image, repositories)
    config = AugmentConfig(cosign, False, asyncio.Semaphore(2), tmp_path)

    results = await SBOMAugmenter().update_component_boms(config, component)

    for result, repository in zip(results, repositories, strict=True):
        assert result is not None
        doc = json.loads(result.path.read_text())
        purl_strings = [
            ref["referenceLocator"]
            for package in doc["packages"]
            for ref in package["externalRefs"]
            if ref["referenceType"] == "purl"
        ]
        purls = [PackageURL.from_string(value) for value in purl_strings]
        tags = set()
        for purl in purls:
            assert isinstance(purl.qualifiers, dict)
            assert purl.qualifiers["repository_url"] == repository.public_repo_url
            tags.add(purl.qualifiers["tag"])
        assert tags == set(repository.tags)


def test_cdx_augment_preserves_legacy_identity_with_multiple_cpes() -> None:
    """Convert a CycloneDX 1.5 identity object to a list without losing evidence."""
    image = Image("quay.io/example/image", "sha256:" + "a" * 64)
    repository = ReleaseRepository(
        public_repo_url="registry.example.com/release",
        internal_repo_url="quay.io/release",
        tags=["latest"],
    )
    legacy_identity = {"field": "name", "confidence": 0.9}
    component = {
        "type": "container",
        "name": "image",
        "purl": image.purl_str(),
        "evidence": {"identity": deepcopy(legacy_identity)},
    }
    sbom: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "metadata": {"component": deepcopy(component)},
        "components": [deepcopy(component)],
    }
    cpes = ["cpe:/a:acme:product:1.0:update1", "cpe:/a:acme:product:1.0:update2"]

    CycloneDXVersion1().update_sbom(repository, image, sbom, cpes)

    assert sbom["specVersion"] == "1.6"
    for updated in [sbom["metadata"]["component"], sbom["components"][0]]:
        assert updated["cpe"] == cpes[0]
        assert updated["evidence"]["identity"] == [
            legacy_identity,
            {"field": "cpe", "concludedValue": cpes[1]},
        ]
