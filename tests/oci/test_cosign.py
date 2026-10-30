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

from mobster.error import SBOMError, SBOMVerificationError
from mobster.image import Image
from mobster.oci import cosign
from mobster.oci.artifact import SBOM
from mobster.sbom.detect import SBOMFormat


class TestStaticFetcher:
    verification_key = "/verification-key"

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
        assert sbom.signature_verified is None

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

    @staticmethod
    def make_attestation(
        image: Image, sbom_doc: dict[str, Any], bundle: bool = False
    ) -> bytes:
        statement = {
            "_type": "https://in-toto.io/Statement/v0.1",
            "subject": [
                {
                    "name": image.reference,
                    "digest": {"sha256": image.digest.split(":", 1)[1]},
                }
            ],
            "predicate": sbom_doc,
        }
        encoded_payload = base64.b64encode(json.dumps(statement).encode()).decode()
        if bundle:
            return json.dumps(
                {
                    "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
                    "dsseEnvelope": {"payload": encoded_payload},
                }
            ).encode()
        return json.dumps({"payload": encoded_payload}).encode()

    @staticmethod
    def mock_cosign(
        monkeypatch: pytest.MonkeyPatch,
        responses: dict[str, tuple[int, bytes, bytes]],
    ) -> list[list[str]]:
        """
        Mock cosign in the static and anonymous fetcher modules. Commands are
        matched by keys "download-sbom", "download-spdxjson",
        "download-cyclonedx", "verify-spdxjson" and "verify-cyclonedx".
        Returns the list of executed commands.
        """
        commands: list[list[str]] = []

        async def mock_run_async_subprocess(
            command: list[str], **_: Any
        ) -> tuple[int, bytes, bytes]:
            commands.append(command)
            if command[1:3] == ["download", "sbom"]:
                key = "download-sbom"
            elif command[1:3] == ["download", "attestation"]:
                key = f"download-{command[-2]}"
            elif command[1] == "verify-attestation":
                attestation_type = next(
                    option.split("=", 1)[1]
                    for option in command
                    if option.startswith("--type=")
                )
                key = f"verify-{attestation_type}"
            else:
                raise AssertionError(f"Unexpected Cosign command: {command}")
            return responses.get(key, (1, b"", b"no attestations found"))

        for module in ("static", "anonymous_fetcher"):
            monkeypatch.setattr(
                f"mobster.oci.cosign.{module}.run_async_subprocess",
                mock_run_async_subprocess,
            )
        return commands

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ["sbom_doc", "bundle", "attestation_type"],
        [
            pytest.param(
                {"spdxVersion": "SPDX-2.3"}, False, "spdxjson", id="spdx-v2-envelope"
            ),
            pytest.param(
                {"spdxVersion": "SPDX-2.3"}, True, "spdxjson", id="spdx-v3-bundle"
            ),
            pytest.param(
                {"bomFormat": "CycloneDX", "specVersion": "1.6"},
                False,
                "cyclonedx",
                id="cyclonedx",
            ),
        ],
    )
    @pytest.mark.parametrize(
        "missing_error",
        [
            pytest.param(
                b"Error: MANIFEST_UNKNOWN: manifest unknown", id="manifest-unknown"
            ),
            pytest.param(
                b"Error: no SBOM found attached to image index", id="image-index"
            ),
            pytest.param(
                b"Error: no sbom attached to reference\n"
                b"error during command execution: no sbom attached to reference\n",
                id="no-sbom-attached",
            ),
        ],
    )
    async def test_fetch_sbom_falls_back_to_verified_attestation(
        self,
        image: Image,
        client: cosign.StaticKeyFetcher,
        monkeypatch: pytest.MonkeyPatch,
        sbom_doc: dict[str, Any],
        bundle: bool,
        attestation_type: str,
        missing_error: bytes,
    ) -> None:
        attestation = self.make_attestation(image, sbom_doc, bundle)
        commands = self.mock_cosign(
            monkeypatch,
            {
                "download-sbom": (1, b"", missing_error),
                f"download-{attestation_type}": (0, attestation + b"\n", b""),
                f"verify-{attestation_type}": (0, attestation + b"\n", b""),
            },
        )

        sbom = await client.fetch_sbom(image)

        assert sbom.doc == sbom_doc
        assert sbom.signature_verified is True
        assert [command[1] for command in commands].count("download") == (
            2 if attestation_type == "spdxjson" else 3
        )
        verification_commands = [
            command for command in commands if command[1] == "verify-attestation"
        ]
        assert len(verification_commands) == 1
        assert "--key=/verification-key" in verification_commands[0]
        assert f"--type={attestation_type}" in verification_commands[0]
        assert verification_commands[0][-1] == image.reference

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "error",
        [
            "unauthorized: authentication required",
            "no matching signatures",
            "dial tcp: connect: connection refused",
        ],
    )
    async def test_fetch_sbom_does_not_fallback_for_non_missing_errors(
        self,
        image: Image,
        client: cosign.StaticKeyFetcher,
        monkeypatch: pytest.MonkeyPatch,
        error: str,
    ) -> None:
        commands = self.mock_cosign(
            monkeypatch, {"download-sbom": (1, b"", error.encode())}
        )

        with pytest.raises(SBOMError, match=error):
            await client.fetch_sbom(image)

        assert len(commands) == 1
        assert commands[0][1:3] == ["download", "sbom"]

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "verify_error",
        [
            pytest.param(
                b"Error: no matching attestations: invalid signature when "
                b"validating ASN.1 encoded signature",
                id="signature-mismatch",
            ),
            pytest.param(
                b"Error: none of the attestations matched the predicate type: "
                b"spdxjson, found: https://slsa.dev/provenance/v0.2",
                id="predicate-mismatch",
            ),
        ],
    )
    async def test_fetch_sbom_returns_unverified_when_attestation_signature_fails(
        self,
        image: Image,
        client: cosign.StaticKeyFetcher,
        monkeypatch: pytest.MonkeyPatch,
        caplog: LogCaptureFixture,
        verify_error: bytes,
    ) -> None:
        sbom_doc = {"spdxVersion": "SPDX-2.3"}
        attestation = self.make_attestation(image, sbom_doc)
        commands = self.mock_cosign(
            monkeypatch,
            {
                "download-sbom": (1, b"", b"manifest unknown"),
                "download-spdxjson": (0, attestation + b"\n", b""),
                "verify-spdxjson": (1, b"", verify_error),
            },
        )

        with caplog.at_level("WARNING"):
            sbom = await client.fetch_sbom(image)

        assert sbom.doc == sbom_doc
        assert sbom.signature_verified is False
        assert "could not be verified" in caplog.text
        assert not any(record.exc_info for record in caplog.records)
        # The attachment is downloaded only once, without falling back to
        # the anonymous fetcher, which would download it again.
        assert [command[1:3] for command in commands] == [
            ["download", "sbom"],
            ["download", "attestation"],
            ["verify-attestation", "--key=/verification-key"],
        ]

    @pytest.mark.asyncio
    async def test_fetch_sbom_fails_on_attestation_verification_errors(
        self,
        image: Image,
        client: cosign.StaticKeyFetcher,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        attestation = self.make_attestation(image, {"spdxVersion": "SPDX-2.3"})
        self.mock_cosign(
            monkeypatch,
            {
                "download-sbom": (1, b"", b"manifest unknown"),
                "download-spdxjson": (0, attestation + b"\n", b""),
                "verify-spdxjson": (1, b"", b"unexpected status code 503"),
            },
        )

        with pytest.raises(SBOMError, match="503") as exc_info:
            await client.fetch_sbom(image)

        assert not isinstance(exc_info.value, SBOMVerificationError)

    @pytest.mark.asyncio
    async def test_fetch_sbom_fails_closed_on_malformed_attestation_response(
        self,
        image: Image,
        client: cosign.StaticKeyFetcher,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        attestation = self.make_attestation(image, {"spdxVersion": "SPDX-2.3"})
        self.mock_cosign(
            monkeypatch,
            {
                "download-sbom": (1, b"", b"manifest unknown"),
                "download-spdxjson": (0, attestation + b"\n", b""),
                "verify-spdxjson": (0, b"not-json\n", b""),
            },
        )

        with pytest.raises(json.JSONDecodeError):
            await client.fetch_sbom(image)

    @pytest.mark.asyncio
    async def test_fetch_sbom_fails_when_no_attested_sbom_exists(
        self,
        image: Image,
        client: cosign.StaticKeyFetcher,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        commands = self.mock_cosign(
            monkeypatch,
            {"download-sbom": (1, b"", b"MANIFEST_UNKNOWN: manifest unknown")},
        )

        with pytest.raises(
            SBOMError, match="no attached or attested SBOM found.*MANIFEST_UNKNOWN"
        ):
            await client.fetch_sbom(image)

        assert not any(command[1] == "verify-attestation" for command in commands)


def test_sbom_signature_verification_is_not_derived_from_document() -> None:
    sbom = SBOM(
        {"spdxVersion": "SPDX-2.3", "signature_verified": True}, "digest", "ref"
    )

    assert sbom.signature_verified is None


class TestStaticSigner:
    verification_key = "/verification-key"
    signing_key = "/signing_key"

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
        sbom = await cosign.KeylessSBOMFetcher(
            cosign.VerifyConfig(
                keyless_verify_config=cosign.KeylessVerifyConfig(
                    identity_pattern="aaa", oidc_issuer="aa"
                )
            )
        ).fetch_sbom(MagicMock(reference="aaaa"))
        assert sbom.doc == {"never gonna": [{"give you": "up"}, {"let you": "down"}]}
        assert sbom.signature_verified is True

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
                cosign.VerifyConfig(static_verify_key="A"),
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


def test_verify_config_url_persistence() -> None:
    """Test against regression. Pathlike converts k8s:// to k8s:/"""
    # In case of a regression, the following line will raise a validation error
    config = cosign.VerifyConfig(static_verify_key="k8s://foo/bar")
    assert config.static_verify_key == "k8s://foo/bar"


def test_sign_config_url_persistence() -> None:
    config = cosign.SignConfig(
        static_sign_config=cosign.StaticSignConfig(
            sign_key="awskms:///arn:aws:kms:us-eu-1:signkey"
        )
    )
    assert config.static_sign_config is not None
    assert config.static_sign_config.sign_key == "awskms:///arn:aws:kms:us-eu-1:signkey"
