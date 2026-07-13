import base64
import datetime
import hashlib
import json
from collections.abc import Callable, Generator
from pathlib import Path
from typing import Any, Literal
from unittest.mock import ANY, AsyncMock, MagicMock, patch

import pytest
from dateutil.parser import isoparse
from pytest import LogCaptureFixture

from mobster.error import SBOMError
from mobster.image import Image
from mobster.oci import cosign
from mobster.oci.artifact import SBOMFormat


class TestStaticFetcher:
    verification_key = Path("/verification-key")

    @pytest.fixture()
    def provenance_path(self, provenances_path: Path) -> Path:
        return provenances_path.joinpath("sha256:aaaaaaaa")

    @pytest.fixture
    def make_provenance_raw(
        self,
        make_provenance_predicate: Callable[
            [datetime.datetime | None],
            Callable[[datetime.datetime | None], dict[str, Any]],
        ],
    ) -> Callable[[datetime.datetime | None], bytes]:
        def _make_provenance_raw(build_finished_on: datetime.datetime | None) -> bytes:
            payload = base64.b64encode(
                json.dumps(
                    {
                        "predicateType": "https://slsa.dev/provenance/v0.2",
                        "predicate": make_provenance_predicate(build_finished_on),
                    }
                ).encode()
            ).decode()

            return json.dumps({"payload": payload}).encode()

        return _make_provenance_raw

    @pytest.fixture
    def make_provenance_predicate(
        self, provenance_path: Path
    ) -> Callable[[datetime.datetime | None], dict[str, Any]]:
        def _make_provenance_predicate(
            build_finished_on: datetime.datetime | None,
        ) -> dict[str, Any]:
            with open(provenance_path) as fp:
                loaded = json.load(fp)
                predicate = loaded["predicate"]
                if build_finished_on is not None:
                    predicate["metadata"]["buildFinishedOn"] = (
                        build_finished_on.isoformat()
                    )
                else:
                    del predicate["metadata"]["buildFinishedOn"]
            return predicate  # type: ignore

        return _make_provenance_predicate

    @pytest.fixture
    def image(self) -> Image:
        return Image("quay.io/test/repo", "sha256:deadbeef")

    @pytest.fixture
    def client(self) -> cosign.StaticKeyFetcher:
        return cosign.StaticKeyFetcher(
            cosign.VerifyConfig(static_verify_key=self.verification_key)
        )

    @pytest.mark.asyncio
    async def test_fetch_latest_provenance(
        self,
        image: Image,
        client: cosign.StaticKeyFetcher,
        monkeypatch: pytest.MonkeyPatch,
        make_provenance_raw: Callable[[datetime.datetime | None], bytes],
    ) -> None:
        old_date = isoparse("2023-01-01T12:05:30Z")
        new_date = isoparse("2025-01-01T12:05:30Z")

        async def mock_run_async_subprocess(
            cmd: Any, env: Any, retry_times: Any
        ) -> tuple[int, bytes, bytes]:
            no_date = make_provenance_raw(None)
            old = make_provenance_raw(old_date)
            new = make_provenance_raw(new_date)
            return 0, (old + b"\n" + new + b"\n" + no_date), b""

        monkeypatch.setattr(
            "mobster.oci.cosign.static.run_async_subprocess",
            mock_run_async_subprocess,
        )

        prov = await client.fetch_latest_provenance(image)
        assert prov.build_finished_on == new_date

    @pytest.mark.asyncio
    async def test_fetch_attested_sbom(
        self,
        image: Image,
        client: cosign.StaticKeyFetcher,
        monkeypatch: pytest.MonkeyPatch,
        sbom_doc: dict[str, Any],
    ) -> None:
        expected_payload = {
            "predicateType": "https://in-toto.io/Statement/v0.1",
            "predicate": sbom_doc,
        }
        expected_attestation = {
            "payload": base64.b64encode(json.dumps(expected_payload).encode()).decode()
        }
        attestation_raw = json.dumps(expected_attestation).encode()

        async def fake_verify_attestation(*_: Any) -> list[bytes]:
            return [attestation_raw]

        monkeypatch.setattr(
            client,
            "_verify_attestation",
            fake_verify_attestation,
        )

        sbom = await client.fetch_attested_sbom(image, SBOMFormat.SPDX_2_3)

        assert sbom
        assert sbom.doc == sbom_doc
        assert sbom.reference == image.reference
        assert sbom.digest == hashlib.sha256(attestation_raw).hexdigest()

    @pytest.mark.asyncio
    async def test_fetch_attested_sbom_no_attestations(
        self,
        image: Image,
        client: cosign.StaticKeyFetcher,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        async def fake_verify_attestation(*_: Any) -> list[bytes]:
            return []

        monkeypatch.setattr(
            client,
            "_verify_attestation",
            fake_verify_attestation,
        )
        assert not await client.fetch_attested_sbom(image, SBOMFormat.CDX_V1_6)

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ["code", "stderr"],
        [
            pytest.param(
                1,
                b"none of the attestations matched the predicate type",
                id="no-provenances",
            ),
            pytest.param(1, b"", id="empty stdout"),
        ],
    )
    async def test_fetch_latest_provenance_failure(
        self,
        code: int,
        stderr: bytes,
        image: Image,
        client: cosign.StaticKeyFetcher,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        async def mock_run_async_subprocess(
            cmd: Any, env: Any, retry_times: Any
        ) -> tuple[int, bytes, bytes]:
            return code, b"", stderr

        monkeypatch.setattr(
            "mobster.oci.cosign.static.run_async_subprocess",
            mock_run_async_subprocess,
        )

        with pytest.raises(SBOMError):
            await client.fetch_latest_provenance(image)

    @pytest.fixture
    def sbom_raw(self, sboms_path: Path) -> bytes:
        with open(sboms_path.joinpath("sha256:aaaaaaaa"), "rb") as fp:
            return fp.read()

    @pytest.fixture
    def sbom_doc(self, sbom_raw: bytes) -> dict[str, Any]:
        return json.loads(sbom_raw)  # type: ignore

    @pytest.mark.asyncio
    async def test_fetch_sbom(
        self,
        image: Image,
        client: cosign.StaticKeyFetcher,
        monkeypatch: pytest.MonkeyPatch,
        sbom_raw: bytes,
        sbom_doc: dict[str, Any],
    ) -> None:
        async def mock_run_async_subprocess(
            cmd: Any, env: Any, retry_times: Any
        ) -> tuple[int, bytes, bytes]:
            return 0, sbom_raw, b""

        monkeypatch.setattr(
            "mobster.oci.cosign.static.run_async_subprocess",
            mock_run_async_subprocess,
        )

        sbom = await client.fetch_sbom(image)

        assert sbom.doc == sbom_doc

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ["code"],
        [
            pytest.param(0, id="no-sboms"),
            pytest.param(1, id="exit-code"),
        ],
    )
    async def test_fetch_sbom_failure(
        self,
        image: Image,
        client: cosign.StaticKeyFetcher,
        monkeypatch: pytest.MonkeyPatch,
        code: int,
    ) -> None:
        async def mock_run_async_subprocess(
            *_: Any,
            **__: Any,
        ) -> tuple[int, bytes, bytes]:
            return code, b"", b""

        monkeypatch.setattr(
            "mobster.oci.cosign.static.run_async_subprocess",
            mock_run_async_subprocess,
        )

        with pytest.raises(SBOMError):
            await client.fetch_sbom(image)


class TestStaticSigner:
    verification_key = Path("/verification-key")
    signing_key = Path("/signing_key")

    @pytest.fixture
    def client(self) -> cosign.StaticKeySigner:
        return cosign.StaticKeySigner(
            cosign.SignConfig(
                static_sign_config=cosign.StaticSignConfig(sign_key=self.signing_key)
            )
        )

    @pytest.mark.asyncio
    async def test_attest_sbom_no_signing_key(self) -> None:
        with pytest.raises(SBOMError):
            cosign.StaticKeySigner(cosign.SignConfig())

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ["blob_type", "subprocess_code", "subprocess_stderr", "raises_exc"],
        [
            ("all", 0, b"", None),
            ("sbom", 1, b"NO WAY (to execute this)", SBOMError),
        ],
    )
    @patch("mobster.oci.cosign.static.run_async_subprocess")
    async def test_clean(
        self,
        mock_subprocess: AsyncMock,
        client: cosign.StaticKeySigner,
        blob_type: Literal["all", "signature", "attestation", "sbom"],
        subprocess_code: int,
        subprocess_stderr: bytes,
        raises_exc: type[Exception] | None,
        caplog: LogCaptureFixture,
    ) -> None:
        image_ref = "quay.io/test/repo@sha256:deadbeef"
        mock_subprocess.return_value = subprocess_code, b"", subprocess_stderr
        if raises_exc:
            with pytest.raises(raises_exc):
                await client.clean(image_ref, blob_type)
                assert subprocess_stderr.decode() in caplog.messages[-1]
        else:
            await client.clean(image_ref, blob_type)
        mock_subprocess.assert_awaited_once()
        cosign_command = mock_subprocess.call_args_list[0].args[0]
        assert cosign_command[0] == "cosign"
        assert cosign_command[1] == "clean"
        assert f"--type={blob_type}" in cosign_command


class TestKeylessSigner:
    @pytest.fixture
    def keyless_config(self) -> Generator[cosign.SignConfig, None, None]:
        yield cosign.SignConfig(
            keyless_token_file=Path("/tmp"),
            url_config=cosign.URLSigningConfig()
            .set_tlog_url("foo")
            .set_fulcio_url("bar")
            .set_issuer_url("WhatIsYourIssueIWillSolveIt.com"),
        )

    @pytest.fixture
    def fake_keyless_cosign(
        self, keyless_config: cosign.SignConfig
    ) -> Generator[cosign.KeylessSigner, None, None]:
        with patch("mobster.oci.cosign.keyless.check_tuf") as fake_check_tuf:
            fake_check_tuf.return_value = True
            cosign_client = cosign.KeylessSigner(keyless_config)
            yield cosign_client

    @pytest.mark.asyncio
    @patch("mobster.oci.cosign.config.URLSigningConfig.file")
    async def test_attest_sbom(
        self,
        mock_url_config_manager: MagicMock,
        fake_keyless_cosign: cosign.KeylessSigner,
    ) -> None:
        with patch(
            "mobster.oci.cosign.keyless.run_async_subprocess",
            return_value=(0, b"", b""),
        ) as mocked_run:
            await fake_keyless_cosign.attest_sbom(
                Path("/sbom.json"), "quay.io/foo/bar@sha256:a", SBOMFormat.SPDX_2_3
            )
        mocked_run.assert_awaited_once_with(
            [
                "cosign",
                "attest",
                "--signing-config",
                str(
                    mock_url_config_manager.return_value.__enter__.return_value.absolute.return_value
                ),
                "--yes",
                "--type",
                "spdxjson",
                "--identity-token",
                "/tmp",
                "--predicate",
                "/sbom.json",
                "quay.io/foo/bar@sha256:a",
            ],
            env={"DOCKER_CONFIG": ANY},
            retry_times=3,
        )

    @pytest.mark.asyncio
    async def test_attest_sbom_no_config(self) -> None:
        """Without all signing information, we cannot sign"""
        with pytest.raises(SBOMError):
            await cosign.KeylessSigner(cosign.SignConfig()).attest_sbom(
                Path("a"), "b", MagicMock()
            )

    @pytest.mark.asyncio
    async def test_attest_sbom_fail(
        self, fake_keyless_cosign: cosign.KeylessSigner
    ) -> None:
        with patch(
            "mobster.oci.cosign.keyless.run_async_subprocess",
            return_value=(1, b"", b"Or nor, Cleor!"),
        ):
            with pytest.raises(SBOMError):
                await fake_keyless_cosign.attest_sbom(
                    Path("a"), "b", SBOMFormat.CDX_V1_6
                )


class TestKeylessFetcher:
    @pytest.mark.asyncio
    @patch("mobster.oci.cosign.keyless.check_tuf")
    @patch("mobster.oci.cosign.keyless.run_async_subprocess")
    @patch("mobster.oci.cosign.keyless.make_oci_auth_file", MagicMock())
    async def test_fetch(
        self, mock_run_subprocess: AsyncMock, mock_check_tuf: MagicMock
    ) -> None:
        mock_check_tuf.return_value = True
        mock_run_subprocess.return_value = (
            0,
            b'{"payload": "eyJwcmVkaWNhdGUiOiB7Im5ldmVyIGdvbm5hIjogW3siZ2l2ZSB5'
            b'b3UiOiAidXAifSwgeyJsZXQgeW91IjogImRvd24ifV19fQ=="}',
            b"",
        )
        assert (
            await cosign.KeylessSBOMFetcher(
                cosign.VerifyConfig(
                    keyless_verify_config=cosign.KeylessVerifyConfig(
                        identity_pattern="aaa", oidc_issuer="aa"
                    )
                )
            ).fetch_sbom(MagicMock(reference="aaaa"))
        ).doc == {"never gonna": [{"give you": "up"}, {"let you": "down"}]}

    @pytest.mark.asyncio
    @patch("mobster.oci.cosign.keyless.check_tuf")
    @patch("mobster.oci.cosign.keyless.run_async_subprocess")
    @patch("mobster.oci.cosign.keyless.make_oci_auth_file", MagicMock())
    async def test_fetch_fail(
        self, mock_run_subprocess: AsyncMock, mock_check_tuf: MagicMock
    ) -> None:
        mock_check_tuf.return_value = True
        mock_run_subprocess.return_value = 1, b"", b"No SBOM for you, stinky!"
        with pytest.raises(SBOMError):
            await cosign.KeylessSBOMFetcher(
                cosign.VerifyConfig(
                    keyless_verify_config=cosign.KeylessVerifyConfig(
                        identity_pattern="aaa", oidc_issuer="aa"
                    )
                )
            ).fetch_sbom(MagicMock(reference="aaaa"))


class TestGetCosign:
    @patch("mobster.oci.cosign.keyless.check_tuf", MagicMock(return_value=True))
    @pytest.mark.parametrize(
        ["config", "expected_type"],
        [
            (
                cosign.VerifyConfig(static_verify_key=Path("A")),
                cosign.StaticKeyFetcher,
            ),
            (
                cosign.VerifyConfig(
                    keyless_verify_config=cosign.KeylessVerifyConfig(
                        identity_pattern="bar", oidc_issuer="foo"
                    )
                ),
                cosign.KeylessSBOMFetcher,
            ),
        ],
    )
    def test_get_cosign_fetcher(
        self, config: cosign.VerifyConfig, expected_type: type
    ) -> None:
        assert isinstance(cosign.get_cosign_fetcher(config), expected_type)


class TestAnonymousFetcher:
    @patch(
        "mobster.oci.cosign.anonymous_fetcher.make_oci_auth_file",
        MagicMock(reference="foo"),
    )
    @pytest.mark.parametrize(
        ["successful_sbom_type", "which_attempt_will_succeed", "expect_problems"],
        [
            pytest.param(
                SBOMFormat.SPDX_2_3, 1, False, id="first attempt successful, attested"
            ),
            pytest.param(
                SBOMFormat.CDX_V1_6, 2, False, id="second attempt successful, attested"
            ),
            pytest.param(None, 3, False, id="third attempt successful, attached"),
            pytest.param(SBOMFormat.SPDX_2_3, 5, True, id="out of attempts"),
        ],
    )
    @pytest.mark.asyncio
    async def test_fetch_sbom_retry(
        self,
        successful_sbom_type: SBOMFormat | None,
        which_attempt_will_succeed: int,
        expect_problems: bool,
    ) -> None:
        call_no = 0

        async def mock_run_async_subprocess_func(
            cmd_arr: list[str],
            **_: Any,
        ) -> tuple[int, bytes, bytes]:
            """
            Mocks both attached and attested SBOM downloads.
            Configurable to fail any number of attempts.
            """
            failed_result = 1, b"", b"Le error error has occurred"
            successful_attest_result = (
                0,
                b'{"payload": '
                b'"eyJwcmVkaWNhdGUiOiB7ImxlIHNib20iOiAiaGFzIGFycml2ZWQifX0="}',
                b"",
            )
            nonlocal call_no
            if successful_sbom_type is None and cmd_arr == [
                "cosign",
                "download",
                "sbom",
                "foo",
            ]:
                call_no += 1
                return (
                    (0, b'{"le sbom": "has arrived"}', b"")
                    if call_no >= which_attempt_will_succeed
                    else failed_result
                )
            if (
                successful_sbom_type is SBOMFormat.SPDX_2_3 and "spdxjson" in cmd_arr
            ) or (
                successful_sbom_type is SBOMFormat.CDX_V1_6 and "cyclonedx" in cmd_arr
            ):
                call_no += 1
                return (
                    successful_attest_result
                    if call_no >= which_attempt_will_succeed
                    else failed_result
                )
            return failed_result

        with patch(
            "mobster.oci.cosign.anonymous_fetcher.run_async_subprocess"
        ) as mock_subprocess:
            mock_subprocess.side_effect = mock_run_async_subprocess_func
            fetcher = cosign.AnonymousFetcher()
            mock_image = MagicMock()
            mock_image.reference = "foo"
            if not expect_problems:
                sbom = await fetcher.fetch_sbom(mock_image)
                assert sbom.doc == {"le sbom": "has arrived"}
            else:
                with pytest.raises(SBOMError, match="Failed to fetch SBOM"):
                    await fetcher.fetch_sbom(mock_image)
