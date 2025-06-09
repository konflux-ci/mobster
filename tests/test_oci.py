import base64
import datetime
import json
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from dateutil.parser import isoparse

from mobster.error import SBOMError
from mobster.image import Image
from mobster.oci import (
    _find_auth_file,
    get_image_manifest,
    make_oci_auth_file,
    run_async_subprocess,
)
from mobster.oci.artifact import SBOM, Provenance02
from mobster.oci.cosign import CosignClient
from tests.cmd.test_augment import load_provenance


@pytest.fixture
def testdata_path() -> Path:
    return Path(__file__).parent.joinpath("data/component")


@pytest.fixture
def provenances_path(testdata_path: Path) -> Path:
    return testdata_path.joinpath("provenances")


@pytest.fixture
def sboms_path(testdata_path: Path) -> Path:
    return testdata_path.joinpath("sboms")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "retry_times, env, exec_results, expected",
    [
        pytest.param(
            0, None, [(0, b"output", b"error")], (0, b"output", b"error"), id="success"
        ),
        pytest.param(
            0,
            {"ENV_VAR": "/usr/bin"},
            [(0, b"output", b"")],
            (0, b"output", b""),
            id="custom-env",
        ),
        pytest.param(
            1,
            None,
            [(1, b"", b"error1"), (0, b"output", b"")],
            (0, b"output", b""),
            id="failure-retry-success",
        ),
        pytest.param(
            2,
            None,
            [(1, b"", b"error1"), (2, b"", b"error2"), (3, b"", b"error3")],
            (3, b"", b"error3"),
            id="all-failures",
        ),
        pytest.param(
            0,
            None,
            [(1, b"", b"error")],
            (1, b"", b"error"),
            id="single-attempt-failure",
        ),
    ],
)
async def test_run_async_subprocess(
    retry_times: int,
    env: dict[str, Any],
    exec_results: list[tuple[int, bytes, bytes]],
    expected: tuple[int, bytes, bytes],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("EXISTING", "VAR")
    with patch("asyncio.create_subprocess_exec") as mock_exec:
        mock_processes = []
        for return_code, stdout, stderr in exec_results:
            mock_process = AsyncMock()
            mock_process.communicate.return_value = (stdout, stderr)
            mock_process.returncode = return_code
            mock_processes.append(mock_process)

        mock_exec.side_effect = mock_processes

        code, stdout, stderr = await run_async_subprocess(
            ["cmd"], env=env, retry_times=retry_times
        )

        assert (code, stdout, stderr) == expected
        assert mock_exec.call_count == min(len(exec_results), retry_times + 1)

        for call in mock_exec.call_args_list:
            # make sure we keep the existing env vars
            assert "EXISTING" in call.kwargs["env"]
            # make sure we pass env vars
            if env is not None:
                assert env.items() <= call.kwargs["env"].items()


@pytest.mark.asyncio
async def test_run_async_subprocess_negative_retry() -> None:
    with pytest.raises(ValueError) as excinfo:
        await run_async_subprocess(["cmd"], retry_times=-1)

    assert "Retry count cannot be negative" in str(excinfo.value)


@pytest.fixture
def mock_auth_file() -> MagicMock:
    auth_file = "/tmp/mock_auth_file"
    mock_context = MagicMock()
    mock_context.__enter__.return_value = auth_file
    return mock_context


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ["reference", "manifest_data", "expected_result"],
    [
        (
            "example.com/repo:tag",
            json.dumps(
                {
                    "schemaVersion": 2,
                    "mediaType": "application/vnd.oci.image.manifest.v1+json",
                }
            ),
            {
                "schemaVersion": 2,
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
            },
        ),
        (
            "example.com/repo@sha256:1234",
            json.dumps({"schemaVersion": 2, "layers": [{"digest": "sha256:abcd"}]}),
            {"schemaVersion": 2, "layers": [{"digest": "sha256:abcd"}]},
        ),
    ],
)
async def test_get_image_manifest_successful(
    mock_auth_file: MagicMock,
    reference: str,
    manifest_data: str,
    expected_result: dict[str, Any],
) -> None:
    with patch(
        "mobster.oci.make_oci_auth_file", return_value=mock_auth_file
    ) as mock_make_auth:
        with patch(
            "mobster.oci.run_async_subprocess", new_callable=AsyncMock
        ) as mock_run:
            mock_run.return_value = (0, manifest_data.encode(), b"")

            result = await get_image_manifest(reference)
            assert result == expected_result
            mock_make_auth.assert_called_once_with(reference)
            mock_run.assert_called_once_with(
                [
                    "oras",
                    "manifest",
                    "fetch",
                    "--registry-config",
                    mock_auth_file.__enter__.return_value,
                    reference,
                ],
                retry_times=3,
            )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "reference",
    [
        ("example.com/repo:tag"),
        ("example.com/repo@sha256:1234"),
    ],
)
async def test_get_image_manifest_failure(
    mock_auth_file: MagicMock, reference: str
) -> None:
    with patch("mobster.oci.make_oci_auth_file", return_value=mock_auth_file):
        with patch(
            "mobster.oci.run_async_subprocess", new_callable=AsyncMock
        ) as mock_run:
            mock_run.return_value = (1, b"", b"")

            with pytest.raises(SBOMError):
                await get_image_manifest(reference)


class TestMakeOciAuth:
    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ["reference", "auth", "expected"],
        [
            pytest.param(
                "registry.redhat.io/test@sha256:deadbeef",
                json.dumps(
                    {
                        "auths": {
                            "registry.redhat.io": {"auth": "token"},
                            "docker.io": {"auth": "token"},
                        }
                    }
                ),
                {"auths": {"registry.redhat.io": {"auth": "token"}}},
                id="success",
            ),
            pytest.param(
                "registry.redhat.io/test@sha256:deadbeef",
                json.dumps(
                    {
                        "auths": {
                            "docker.io": {"auth": "token"},
                        }
                    }
                ),
                {"auths": {}},
                id="no-auth",
            ),
        ],
    )
    async def test_make_oci_auth_file_specified(
        self, reference: str, auth: str, expected: dict[str, Any]
    ) -> None:
        with tempfile.NamedTemporaryFile("+w") as tmpf:
            tmpf.write(auth)
            tmpf.flush()

            with make_oci_auth_file(reference, auth=Path(tmpf.name)) as new_auth_path:
                assert new_auth_path.name == "config.json"
                with open(new_auth_path) as fp:
                    new_auth = json.load(fp)

        assert new_auth == expected

    @pytest.mark.asyncio
    async def test_make_oci_auth_file_nonexistent_auth(self) -> None:
        with pytest.raises(ValueError):
            with make_oci_auth_file("", Path("/nonexistent")) as _:
                pass

    @pytest.mark.asyncio
    async def test_make_oci_auth_file_nonexistent_find_auth(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("mobster.oci._find_auth_file", lambda: None)
        with pytest.raises(ValueError):
            with make_oci_auth_file("") as _:
                pass

    @pytest.mark.asyncio
    async def test_make_oci_auth_file_registry_port(self) -> None:
        reference = "registry.redhat.io:5000/test@sha256:deadbeef"
        with pytest.raises(ValueError):
            with make_oci_auth_file(reference) as _:
                pass

    @pytest.mark.parametrize(
        ["linux", "env", "path_mapping", "expected"],
        [
            pytest.param(
                True,
                {
                    "HOME": "/home/user",
                    "XDG_RUNTIME_DIR": "/run/user/1000",
                    "REGISTRY_AUTH_FILE": "/home/user/config.json",
                },
                {Path("/home/user/config.json"): True},
                Path("/home/user/config.json"),
                id="REGISTRY_AUTH_FILE-specified-exist",
            ),
            pytest.param(
                True,
                {
                    "HOME": "/home/user",
                    "XDG_RUNTIME_DIR": "/run/user/1000",
                    "REGISTRY_AUTH_FILE": "/home/user/config.json",
                },
                {Path("/home/user/config.json"): False},
                None,
                id="REGISTRY_AUTH_FILE-specified-nonexist",
            ),
            pytest.param(
                True,
                {
                    "HOME": "/home/user",
                    "XDG_RUNTIME_DIR": "/run/user/1000",
                },
                {Path("/run/user/1000/containers/auth.json"): True},
                Path("/run/user/1000/containers/auth.json"),
                id="XDG_RUNTIME_DIR-specified-exist",
            ),
            pytest.param(
                True,
                {
                    "HOME": "/home/user",
                    "XDG_RUNTIME_DIR": "/run/user/1000",
                },
                {
                    Path("/run/user/1000/containers/auth.json"): False,
                    Path("/home/user/.docker/config.json"): True,
                },
                Path("/home/user/.docker/config.json"),
                id="XDG_RUNTIME_DIR-specified-nonexist-docker-exist",
            ),
            pytest.param(
                True,
                {
                    "HOME": "/home/user",
                    "XDG_RUNTIME_DIR": "/run/user/1000",
                },
                {
                    Path("/run/user/1000/containers/auth.json"): False,
                    Path("/home/user/.docker/config.json"): False,
                },
                None,
                id="XDG_RUNTIME_DIR-specified-nonexist-docker-nonexist",
            ),
            pytest.param(
                True,
                {
                    "HOME": "/home/user",
                },
                {
                    Path("/home/user/.docker/config.json"): True,
                },
                Path("/home/user/.docker/config.json"),
                id="XDG_RUNTIME_DIR-unspecified-docker-exist",
            ),
            pytest.param(
                True,
                {
                    "HOME": "/home/user",
                },
                {
                    Path("/home/user/.docker/config.json"): False,
                },
                None,
                id="XDG_RUNTIME_DIR-unspecified-docker-nonexist",
            ),
            pytest.param(
                False,
                {
                    "HOME": "/home/user",
                },
                {
                    Path("/home/user/.config/containers/auth.json"): True,
                },
                Path("/home/user/.config/containers/auth.json"),
                id="NONLINUX-exists",
            ),
            pytest.param(
                False,
                {
                    "HOME": "/home/user",
                },
                {
                    Path("/home/user/.config/containers/auth.json"): False,
                    Path("/home/user/.docker/config.json"): True,
                },
                Path("/home/user/.docker/config.json"),
                id="NONLINUX-nonexists-docker-exists",
            ),
        ],
    )
    def test_find_auth_file_linux(
        self,
        linux: bool,
        env: dict[str, str],
        path_mapping: dict[Path, bool],
        expected: Path | None,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        system = "Linux"
        if not linux:
            system = "Windows"
        monkeypatch.setattr("mobster.oci.platform.system", lambda: system)

        for name, val in env.items():
            monkeypatch.setenv(name, val)

        def fake_is_file(path: Path) -> bool:
            return path_mapping.get(path, False)

        monkeypatch.setattr("mobster.oci.Path.is_file", fake_is_file)

        assert _find_auth_file() == expected


def test_provenance_bad_predicate_type() -> None:
    payload = {
        "predicateType": "wrong",
    }
    raw = json.dumps(
        {"payload": base64.b64encode(json.dumps(payload).encode()).decode()}
    ).encode()

    with pytest.raises(ValueError):
        Provenance02.from_cosign_output(raw)


def test_provenance_no_sbom_blob_url(provenances_path: Path) -> None:
    prov = load_provenance(provenances_path, "sha256:aaaaaaaa")
    assert prov is not None

    prov.predicate["buildConfig"]["tasks"] = []
    with pytest.raises(SBOMError):
        img = Image("quay.io/repo", "sha256:deadbeef")
        prov.get_sbom_digest(img)


@pytest.mark.parametrize(
    ["doc"],
    [
        pytest.param(
            {},
            id="missing-data",
        ),
        pytest.param(
            {"bomFormat": "CycloneDX"},
            id="missing-specVersion",
        ),
        pytest.param(
            {"bomFormat": "CycloneDX", "specVersion": "1.7"},
            id="invalid-specVersion",
        ),
        pytest.param({"spdxVersion": "SPDX-2.4"}, id="invalid-spdxVersion"),
    ],
)
def test_sbom_bad_format(doc: dict[str, Any]) -> None:
    sbom = SBOM(doc, "", "")
    with pytest.raises(SBOMError):
        _ = sbom.format


class TestCosignClient:
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
    def client(self) -> CosignClient:
        return CosignClient(self.verification_key)

    @pytest.mark.asyncio
    async def test_fetch_latest_provenance(
        self,
        image: Image,
        client: CosignClient,
        monkeypatch: pytest.MonkeyPatch,
        make_provenance_raw: Callable[[datetime.datetime | None], bytes],
        make_provenance_predicate: Callable[[datetime.datetime | None], dict[str, Any]],
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
            "mobster.oci.cosign.run_async_subprocess", mock_run_async_subprocess
        )

        prov = await client.fetch_latest_provenance(image)
        assert prov.predicate == make_provenance_predicate(new_date)

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ["code"],
        [
            pytest.param(0, id="no-provenances"),
            pytest.param(1, id="exit-code"),
        ],
    )
    async def test_fetch_latest_provenance_failure(
        self,
        code: int,
        image: Image,
        client: CosignClient,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        async def mock_run_async_subprocess(
            cmd: Any, env: Any, retry_times: Any
        ) -> tuple[int, bytes, bytes]:
            return code, b"", b""

        monkeypatch.setattr(
            "mobster.oci.cosign.run_async_subprocess", mock_run_async_subprocess
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
        client: CosignClient,
        monkeypatch: pytest.MonkeyPatch,
        sbom_raw: bytes,
        sbom_doc: dict[str, Any],
    ) -> None:
        async def mock_run_async_subprocess(
            cmd: Any, env: Any, retry_times: Any
        ) -> tuple[int, bytes, bytes]:
            return 0, sbom_raw, b""

        monkeypatch.setattr(
            "mobster.oci.cosign.run_async_subprocess", mock_run_async_subprocess
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
        client: CosignClient,
        monkeypatch: pytest.MonkeyPatch,
        code: int,
    ) -> None:
        async def mock_run_async_subprocess(
            cmd: Any, env: Any, retry_times: Any
        ) -> tuple[int, bytes, bytes]:
            return code, b"", b""

        monkeypatch.setattr(
            "mobster.oci.cosign.run_async_subprocess", mock_run_async_subprocess
        )

        with pytest.raises(SBOMError):
            await client.fetch_sbom(image)
