import base64
import datetime
import json
import tempfile
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mobster.error import SBOMError
from mobster.oci import (
    _find_auth_file,
    get_image_manifest,
    make_oci_auth_file,
)
from mobster.oci.artifact import SBOM, SLSAParsingError, SLSAProvenance


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


def _make_slsa_raw(statement: dict[str, Any]) -> bytes:
    """
    Wrap a statement dict into the payload format expected by SLSAProvenance.parse().
    """
    return json.dumps(
        {"payload": base64.b64encode(json.dumps(statement).encode()).decode()}
    ).encode()


class TestSLSAProvenance:
    def test_parse_missing_predicate_type(self) -> None:
        raw = _make_slsa_raw({"predicate": {}})
        with pytest.raises(SLSAParsingError, match="predicateType"):
            SLSAProvenance.parse(raw)

    def test_parse_unsupported_predicate_type(self) -> None:
        raw = _make_slsa_raw({"predicateType": "https://example.com/unknown/v9"})
        with pytest.raises(SLSAParsingError, match="Cannot parse"):
            SLSAProvenance.parse(raw)

    def test_v02_happy_path(self) -> None:
        raw = _make_slsa_raw(
            {
                "predicateType": "https://slsa.dev/provenance/v0.2",
                "predicate": {
                    "metadata": {"buildFinishedOn": "2024-06-15T10:30:00Z"},
                    "buildConfig": {
                        "tasks": [
                            {
                                "results": [
                                    {"name": "IMAGE_DIGEST", "value": "sha256:aaa"},
                                    {
                                        "name": "SBOM_BLOB_URL",
                                        "value": "registry.example.io/repo@sha256:bbb",
                                    },
                                ]
                            }
                        ]
                    },
                },
            }
        )

        prov = SLSAProvenance.parse(raw)

        assert prov.build_finished_on == datetime.datetime(
            2024, 6, 15, 10, 30, tzinfo=datetime.timezone.utc
        )
        assert prov.sbom_digest("sha256:aaa") == "sha256:bbb"

    def test_v02_missing_build_finished_on(self) -> None:
        raw = _make_slsa_raw(
            {
                "predicateType": "https://slsa.dev/provenance/v0.2",
                "predicate": {
                    "metadata": {},
                    "buildConfig": {"tasks": []},
                },
            }
        )

        prov = SLSAProvenance.parse(raw)

        assert prov.build_finished_on == datetime.datetime.min.replace(
            tzinfo=datetime.timezone.utc
        )

    def test_v02_task_missing_sbom_blob_url(self) -> None:
        raw = _make_slsa_raw(
            {
                "predicateType": "https://slsa.dev/provenance/v0.2",
                "predicate": {
                    "metadata": {"buildFinishedOn": "2024-01-01T00:00:00Z"},
                    "buildConfig": {
                        "tasks": [
                            {
                                "results": [
                                    {"name": "IMAGE_DIGEST", "value": "sha256:aaa"},
                                ]
                            }
                        ]
                    },
                },
            }
        )

        prov = SLSAProvenance.parse(raw)

        assert prov.sbom_digest("sha256:aaa") is None

    def test_v1_happy_path(self) -> None:
        image_digest = "sha256:" + "a" * 64
        sbom_digest = "sha256:" + "b" * 64
        raw = _make_slsa_raw(
            {
                "predicateType": "https://slsa.dev/provenance/v1",
                "predicate": {
                    "runDetails": {
                        "metadata": {"finishedOn": "2024-08-20T14:00:00Z"},
                        "byproducts": [
                            {"name": "taskRunResults/UNRELATED"},
                            {
                                "name": "taskRunResults/IMAGE_REF",
                                "content": base64.b64encode(
                                    json.dumps(
                                        f"registry.example.io/repo@{image_digest}"
                                    ).encode()
                                ).decode(),
                            },
                            {
                                "name": "taskRunResults/SBOM_BLOB_URL",
                                "content": base64.b64encode(
                                    json.dumps(
                                        f"registry.example.io/repo@{sbom_digest}"
                                    ).encode()
                                ).decode(),
                            },
                        ],
                    }
                },
            }
        )

        prov = SLSAProvenance.parse(raw)

        assert prov.build_finished_on == datetime.datetime(
            2024, 8, 20, 14, 0, tzinfo=datetime.timezone.utc
        )
        assert prov.sbom_digest(image_digest) == sbom_digest

    def test_v1_missing_finished_on(self) -> None:
        raw = _make_slsa_raw(
            {
                "predicateType": "https://slsa.dev/provenance/v1",
                "predicate": {
                    "runDetails": {
                        "metadata": {},
                        "byproducts": [],
                    }
                },
            }
        )

        prov = SLSAProvenance.parse(raw)

        assert prov.build_finished_on == datetime.datetime.min.replace(
            tzinfo=datetime.timezone.utc
        )

    def test_v1_bad_base64_in_byproduct(self) -> None:
        raw = _make_slsa_raw(
            {
                "predicateType": "https://slsa.dev/provenance/v1",
                "predicate": {
                    "runDetails": {
                        "metadata": {},
                        "byproducts": [
                            {
                                "name": "taskRunResults/IMAGE_REF",
                                "content": "!!!not-valid-base64!!!",
                            },
                        ],
                    }
                },
            }
        )

        with pytest.raises(SLSAParsingError):
            SLSAProvenance.parse(raw)

    def test_v1_non_string_byproduct_content(self) -> None:
        raw = _make_slsa_raw(
            {
                "predicateType": "https://slsa.dev/provenance/v1",
                "predicate": {
                    "runDetails": {
                        "metadata": {},
                        "byproducts": [
                            {
                                "name": "taskRunResults/IMAGE_REF",
                                "content": base64.b64encode(
                                    json.dumps({"not": "a string"}).encode()
                                ).decode(),
                            },
                        ],
                    }
                },
            }
        )

        with pytest.raises(SLSAParsingError, match="Expected string content"):
            SLSAProvenance.parse(raw)

    def test_v1_missing_content_field(self) -> None:
        raw = _make_slsa_raw(
            {
                "predicateType": "https://slsa.dev/provenance/v1",
                "predicate": {
                    "runDetails": {
                        "metadata": {},
                        "byproducts": [
                            {
                                "name": "taskRunResults/IMAGE_REF",
                            },
                        ],
                    }
                },
            }
        )

        with pytest.raises(SLSAParsingError, match='missing "content" field'):
            SLSAProvenance.parse(raw)

    def test_sbom_digest_unknown_image(self) -> None:
        raw = _make_slsa_raw(
            {
                "predicateType": "https://slsa.dev/provenance/v0.2",
                "predicate": {
                    "metadata": {"buildFinishedOn": "2024-01-01T00:00:00Z"},
                    "buildConfig": {
                        "tasks": [
                            {
                                "results": [
                                    {"name": "IMAGE_DIGEST", "value": "sha256:aaa"},
                                    {
                                        "name": "SBOM_BLOB_URL",
                                        "value": "registry.example.io/repo@sha256:bbb",
                                    },
                                ]
                            }
                        ]
                    },
                },
            }
        )

        prov = SLSAProvenance.parse(raw)

        assert prov.sbom_digest("sha256:unknown") is None
