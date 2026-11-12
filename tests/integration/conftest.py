import asyncio
import base64
import json
import subprocess
import tempfile
from collections.abc import AsyncGenerator, Generator, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Protocol

import pytest
import pytest_asyncio

from mobster.cmd.upload.tpa import TPAClient, get_tpa_default_client
from mobster.image import Image
from mobster.oci.cosign.static import StaticKeySigner
from mobster.sbom.detect import detect_sbom_format
from mobster.tekton.s3 import S3Client
from tests.integration.oci_client import ReferrersTagOCIClient
from tests.integration.utils import attest_sbom_bytes


class AttachBuildSBOMFunc(Protocol):
    """Attach a build SBOM and optionally reference a separate CBOM task result."""

    async def __call__(
        self,
        cosign_client: StaticKeySigner,
        image: Image,
        sbom: bytes,
        cbom_ref: str | None = None,
    ) -> None: ...


@pytest.fixture(scope="session")
def monkeysession() -> Generator[pytest.MonkeyPatch, None, None]:
    """
    Helper fixture to create a monkeypatch object with session scope.

    https://github.com/pytest-dev/pytest/issues/363#issuecomment-1335631998
    """
    with pytest.MonkeyPatch.context() as mp:
        yield mp


def pytest_addoption(parser: Any) -> None:
    # defaults work with compose.yaml
    parser.addoption("--registry-url", action="store", default="http://localhost:9000")
    parser.addoption("--tpa-base-url", action="store", default="http://localhost:8080")
    parser.addoption(
        "--s3-endpoint-url", action="store", default="http://localhost:9900"
    )


@pytest.fixture
def registry_url(request: Any) -> str:
    return request.config.getoption("--registry-url")  # type: ignore


@pytest.fixture(scope="session")
def tpa_base_url(request: Any) -> str:
    return request.config.getoption("--tpa-base-url")  # type: ignore


@pytest.fixture
def s3_endpoint_url(request: Any) -> str:
    return request.config.getoption("--s3-endpoint-url")  # type: ignore


@pytest_asyncio.fixture
async def oci_client(registry_url: str) -> AsyncGenerator[ReferrersTagOCIClient, None]:
    client = ReferrersTagOCIClient(registry_url)
    await client.cleanup()
    yield client


# WARNING: The concurrency settings MUST match production Tekton Task params.
# Mismatched values will make memory usage tests unreliable.
@pytest.fixture()
def augment_concurrency() -> int:
    return 8


@pytest.fixture()
def upload_concurrency() -> int:
    return 8


@pytest.fixture()
def product_concurrency() -> int:
    return 8


@pytest.fixture()
def attestation_concurrency() -> int:
    return 4


@pytest.fixture(scope="session")
def tpa_auth_env(monkeysession: pytest.MonkeyPatch) -> dict[str, str]:
    """Set up environment variables needed to disable TPA authentication."""
    vars = {
        "MOBSTER_TPA_SSO_TOKEN_URL": "dummy",
        "MOBSTER_TPA_SSO_ACCOUNT": "dummy",
        "MOBSTER_TPA_SSO_TOKEN": "dummy",
        "MOBSTER_TPA_AUTH_DISABLE": "true",
    }
    for key, val in vars.items():
        monkeysession.setenv(key, val)

    return vars


@pytest.fixture
def s3_auth_env(
    s3_endpoint_url: str, monkeysession: pytest.MonkeyPatch
) -> dict[str, str]:
    # these are set in compose.yaml (Garage --default-bucket)
    vars = {
        "AWS_ACCESS_KEY_ID": "GK0123456789abcdef01234567",
        "AWS_SECRET_ACCESS_KEY": (
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        ),
        "AWS_ENDPOINT_URL": s3_endpoint_url,
        "AWS_DEFAULT_REGION": "garage",
    }

    for key, val in vars.items():
        monkeysession.setenv(key, val)

    return vars


@pytest.fixture()
def s3_sbom_bucket() -> str:
    return "sboms"


@pytest_asyncio.fixture
async def s3_client(s3_auth_env: dict[str, str]) -> AsyncGenerator[S3Client, None]:
    # these are set in compose.yaml
    access_key = s3_auth_env["AWS_ACCESS_KEY_ID"]
    secret_key = s3_auth_env["AWS_SECRET_ACCESS_KEY"]
    endpoint_url = s3_auth_env["AWS_ENDPOINT_URL"]
    bucket = "sboms"

    client = S3Client(bucket, access_key, secret_key, endpoint_url=endpoint_url)

    yield client
    await client.clear_bucket()


@pytest_asyncio.fixture(scope="session")
async def tpa_client(
    tpa_base_url: str, tpa_auth_env: Any
) -> AsyncGenerator[TPAClient, None]:
    async with get_tpa_default_client(
        base_url=tpa_base_url,
    ) as client:

        async def delete_sbom(sem: asyncio.Semaphore, sbom_id: str) -> None:
            async with sem:
                await client.delete_sbom(sbom_id)

        async def cleanup() -> None:
            sboms = client.list_sboms(query="", sort="ingested")
            ids = []
            async for sbom in sboms:
                ids.append(sbom.id)

            sem = asyncio.Semaphore(16)
            await asyncio.gather(*[delete_sbom(sem, id) for id in ids])

        await cleanup()
        yield client


@pytest.fixture
def test_id(request: pytest.FixtureRequest) -> str:
    """
    Id uniquely identifying a test case. Used as an SBOM label in TPA tests,
    removing the need for clearing TPA after each test case.
    """
    return str(request.node.name)


@contextmanager
def _generate_cosign_keys() -> Iterator[tuple[str, str]]:
    """
    Generate a throwaway cosign key pair, deleted on exit.

    Yields:
        Paths to the private and the public key.
    """
    with tempfile.TemporaryDirectory() as temp_dir:
        with tempfile.NamedTemporaryFile() as password_tempfile:
            password_tempfile.write(b"")
            subprocess_return = subprocess.run(
                ["cosign", "generate-key-pair"],
                cwd=temp_dir,
                stdin=password_tempfile,
            )
            assert subprocess_return.returncode == 0, (
                f"{subprocess_return.stdout.decode()}, "
                f"{subprocess_return.stderr.decode()}"
            )
        temp_dir_path = Path(temp_dir)
        pub_key = temp_dir_path / "cosign.pub"
        assert pub_key.exists()
        priv_key = temp_dir_path / "cosign.key"
        assert priv_key.exists()
        yield str(priv_key), str(pub_key)


@pytest.fixture(scope="session")
def cosign_keys() -> Generator[tuple[str, str]]:
    with _generate_cosign_keys() as keys:
        yield keys


@pytest.fixture(scope="session")
def other_cosign_verify_key() -> Generator[str]:
    """
    Public key of a second key pair, which did not sign anything. Used to check
    that verification fails with a key that does not match the signature.
    """
    with _generate_cosign_keys() as (_, pub_key):
        yield pub_key


@pytest.fixture(scope="session")
def cosign_sign_key(cosign_keys: tuple[str, str]) -> str:
    return cosign_keys[0]


@pytest.fixture(scope="session")
def cosign_verify_key(cosign_keys: tuple[str, str]) -> str:
    return cosign_keys[1]


def _build_v02_predicate(
    sbom_ref: str, image: Image, cbom_ref: str | None = None
) -> dict[str, Any]:
    predicate: dict[str, Any] = {
        "builder": {"id": "https://konflux.dev"},
        "buildType": "https://mobyproject.org/buildkit@v1",
        "buildConfig": {
            "tasks": [
                {
                    "finishedOn": "1970-01-01T00:00:00Z",
                    "results": [
                        {"name": "SBOM_BLOB_URL", "value": sbom_ref},
                        {"name": "IMAGE_DIGEST", "value": image.digest},
                    ],
                }
            ]
        },
    }
    if cbom_ref is not None:
        predicate["buildConfig"]["tasks"].append(
            {
                "finishedOn": "1970-01-01T00:00:00Z",
                "results": [{"name": "CBOM_BLOB_URL", "value": cbom_ref}],
            }
        )
    return predicate


def _build_v1_predicate(
    sbom_ref: str, image: Image, cbom_ref: str | None = None
) -> dict[str, Any]:
    predicate: dict[str, Any] = {
        "buildDefinition": {
            "buildType": "https://mobyproject.org/buildkit@v1",
            "externalParameters": {},
            "internalParameters": {},
            "resolvedDependencies": [
                {
                    "uri": "build-task",
                    "name": "pipelineTask",
                    "digest": {"sha256": "a" * 64},
                    "content": base64.b64encode(
                        json.dumps(
                            {
                                "metadata": {"name": "pipelinerun1", "uid": "1"},
                                "spec": {"params": [{"name": "FOO", "value": "BAR"}]},
                                "status": {
                                    "results": [
                                        {
                                            "name": "IMAGE_REF",
                                            "type": "string",
                                            "value": image.reference,
                                        },
                                        {
                                            "name": "SBOM_BLOB_URL",
                                            "type": "string",
                                            "value": sbom_ref,
                                        },
                                        {
                                            "name": "IMAGE_DIGEST",
                                            "type": "string",
                                            "value": image.digest,
                                        },
                                    ]
                                },
                            }
                        ).encode()
                    ).decode(),
                }
            ],
        },
        "runDetails": {
            "builder": {"id": "https://konflux.dev"},
            "metadata": {"finishedOn": "1970-01-01T00:00:00Z"},
        },
    }
    if cbom_ref is not None:
        predicate["buildDefinition"]["resolvedDependencies"].append(
            {
                "uri": "crypto-scanner-task",
                "name": "pipelineTask",
                "digest": {"sha256": "b" * 64},
                "content": base64.b64encode(
                    json.dumps(
                        {
                            "metadata": {"name": "crypto-scanner", "uid": "2"},
                            "status": {
                                "results": [
                                    {
                                        "name": "CBOM_BLOB_URL",
                                        "type": "string",
                                        "value": cbom_ref,
                                    }
                                ]
                            },
                        }
                    ).encode()
                ).decode(),
            }
        )
    return predicate


@pytest.fixture(params=["provenance-v0.2", "provenance-v1", "attestation-only"])
def attach_build_sbom(
    request: pytest.FixtureRequest, oci_client: ReferrersTagOCIClient
) -> AttachBuildSBOMFunc:
    """
    Fixture factory returning an async callable that attaches a build-time SBOM
    to an image. Parametrized so every test using this fixture runs once per
    way of publishing the SBOM; tests can pick a subset with indirect
    parametrization:

    - "provenance-v0.2", "provenance-v1": legacy ``.sbom`` attachment
      referenced from a signed SLSA provenance of the given version,
    - "attestation-only": signed SBOM attestation only, with no ``.sbom``
      attachment and no provenance.

    ``cbom_ref`` adds a separate crypto-scanner task result to provenance.
    It is unsupported in attestation-only mode.
    """

    async def _attach(
        cosign_client: StaticKeySigner,
        image: Image,
        sbom: bytes,
        cbom_ref: str | None = None,
    ) -> None:
        sbom_format = detect_sbom_format(json.loads(sbom))
        if request.param == "attestation-only":
            if cbom_ref is not None:
                raise ValueError("CBOM task results require provenance")
            await attest_sbom_bytes(cosign_client, image, sbom, sbom_format)
            return

        sbom_ref = await oci_client.attach_sbom(
            image, "spdx" if sbom_format.is_spdx2() else "cyclonedx", sbom
        )
        if request.param == "provenance-v0.2":
            await cosign_client.attest_provenance(
                _build_v02_predicate(sbom_ref, image, cbom_ref),
                image.reference,
                "slsaprovenance02",
            )
        elif request.param == "provenance-v1":
            await cosign_client.attest_provenance(
                _build_v1_predicate(sbom_ref, image, cbom_ref),
                image.reference,
                "slsaprovenance1",
            )
        else:
            raise ValueError(f"Unknown attach_build_sbom mode: {request.param}")

    return _attach
