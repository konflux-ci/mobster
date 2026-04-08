import base64
import json
import tempfile
from hashlib import sha256
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mobster.error import SBOMError
from mobster.image import Image
from mobster.oci import (
    _find_auth_file,
    get_image_manifest,
    get_objects_for_base_images,
    make_oci_auth_file,
)
from mobster.oci.artifact import SBOM, Provenance02
from tests.cmd.test_augment import load_provenance


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
                "localhost:8080/test@sha256:deadbeef",
                json.dumps(
                    {
                        "auths": {
                            "localhost:8080": {"auth": "token"},
                            "docker.io": {"auth": "token"},
                        }
                    }
                ),
                {"auths": {"localhost:8080": {"auth": "token"}}},
                id="success-port",
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
    @pytest.mark.parametrize(
        ["reference", "auth", "expected"],
        [
            pytest.param(
                "registry.redhat.io:5000/test@sha256:deadbeef",
                json.dumps(
                    {
                        "auths": {
                            "registry.redhat.io:5000": {"auth": "token"},
                        }
                    }
                ),
                {"auths": {"registry.redhat.io:5000": {"auth": "token"}}},
                id="registry-with-port",
            ),
            pytest.param(
                "localhost:5000/test@sha256:deadbeef",
                json.dumps(
                    {
                        "auths": {
                            "localhost:5000": {"auth": "token"},
                        }
                    }
                ),
                {"auths": {"localhost:5000": {"auth": "token"}}},
                id="localhost-with-port",
            ),
            pytest.param(
                "registry.redhat.io:5000/namespace/test@sha256:deadbeef",
                json.dumps(
                    {
                        "auths": {
                            "registry.redhat.io:5000/namespace": {"auth": "token"},
                        }
                    }
                ),
                {"auths": {"registry.redhat.io:5000": {"auth": "token"}}},
                id="registry-with-port-and-namespace",
            ),
        ],
    )
    async def test_make_oci_auth_file_registry_port(
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


@pytest.mark.asyncio
@pytest.mark.parametrize(
    [
        "base_images_refs",
        "expected_outcome",
        "oras_stderr",
    ],
    [
        (
            [
                "registry.access.redhat.com/ubi8/ubi:latest",
                "alpine:3.10",
                None,
                "registry.access.redhat.com/ubi8/ubi:latest",
            ],
            {
                "alpine:3.10": Image.from_image_index_url_and_digest(
                    "alpine:3.10",
                    "sha256:ef437a97b47a6c00ea884fa314df3e05d542e14ef999c344e394808c2b7035d9",
                ),
                "registry.access.redhat.com/ubi8/ubi"
                ":latest": Image.from_image_index_url_and_digest(
                    "registry.access.redhat.com/ubi8/ubi:latest",
                    "sha256:f75e57db5cbc53b37a8b33a0b0b084782ddae260220d9dd8cc968eab4d579062",
                ),
            },
            b"",
        ),
        (
            [
                "registry.access.redhat.com/ubi8/ubi:latest",
            ],
            {},
            b"Uh oh, error I guess.",
        ),
    ],
)
@patch("mobster.oci.run_async_subprocess")
@patch(
    "mobster.oci.make_oci_auth_file",
)
@patch("mobster.oci.logger")
async def test_get_objects_for_base_images(
    mock_logger: AsyncMock,
    mock_make_oci_auth_file: AsyncMock,
    mock_run_async_subprocess: AsyncMock,
    base_images_refs: list[str | None],
    expected_outcome: dict[str, Image],
    oras_stderr: bytes,
) -> None:
    def mocked_subprocess_calling(*args: Any, **_: Any) -> tuple[int, bytes, bytes]:
        digest = f"sha256:{sha256(args[0][-1].encode()).hexdigest()}\n".encode()
        return (
            (int(bool(oras_stderr))),
            digest,
            oras_stderr,
        )

    mock_run_async_subprocess.side_effect = mocked_subprocess_calling

    assert await get_objects_for_base_images(base_images_refs) == expected_outcome

    if oras_stderr:
        assert any(
            args[0].startswith("Problem getting digest of a base image")
            for args in mock_logger.warning.call_args
        )
