import asyncio
import base64
import json
import subprocess
import tempfile
from collections.abc import AsyncGenerator, Awaitable, Callable, Generator
from pathlib import Path
from typing import Any, Literal

import pytest
import pytest_asyncio

from mobster.cmd.upload.tpa import TPAClient, get_tpa_default_client
from mobster.image import Image
from mobster.oci.cosign.static import StaticKeySigner
from mobster.tekton.s3 import S3Client
from tests.integration.oci_client import ReferrersTagOCIClient

AddProvenanceFunc = Callable[[StaticKeySigner, str, Image], Awaitable[None]]


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
    # these are set in compose.yaml
    vars = {
        "AWS_ACCESS_KEY_ID": "minioAccessKey",
        "AWS_SECRET_ACCESS_KEY": "minioSecretKey",
        "AWS_ENDPOINT_URL": s3_endpoint_url,
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


@pytest.fixture(scope="session")
def cosign_keys() -> tuple[Path, Path]:  # type: ignore[misc]
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
        yield priv_key, pub_key


@pytest.fixture(scope="session")
def cosign_sign_key(cosign_keys: tuple[Path, Path]) -> Path:
    return cosign_keys[0]


@pytest.fixture(scope="session")
def cosign_verify_key(cosign_keys: tuple[Path, Path]) -> Path:
    return cosign_keys[1]


def _build_v02_predicate(sbom_ref: str, image: Image) -> dict[str, Any]:
    predicate = {
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
    return predicate


def _build_v1_predicate(sbom_ref: str, image: Image) -> dict[str, Any]:
    predicate = {
        "buildDefinition": {
            "buildType": "https://mobyproject.org/buildkit@v1",
            "externalParameters": {},
            "internalParameters": {},
            "resolvedDependencies": [],
        },
        "runDetails": {
            "builder": {"id": "https://konflux.dev"},
            "metadata": {"finishedOn": "1970-01-01T00:00:00Z"},
            "byproducts": [
                {
                    "name": "taskRunResults/IMAGE_REF",
                    "content": base64.b64encode(
                        json.dumps(image.reference).encode()
                    ).decode(),
                },
                {
                    "name": "taskRunResults/SBOM_BLOB_URL",
                    "content": base64.b64encode(json.dumps(sbom_ref).encode()).decode(),
                },
            ],
        },
    }
    return predicate


@pytest.fixture(params=["v0.2", "v1"])
def add_provenance_to_sbom(request: pytest.FixtureRequest) -> AddProvenanceFunc:
    """
    Fixture factory returning an async callable that attaches a signed
    provenance to an SBOM. Parametrized so every test using this fixture
    runs once per SLSA provenance version (v0.2 and v1).
    """
    build_fn = {
        "v0.2": _build_v02_predicate,
        "v1": _build_v1_predicate,
    }[request.param]

    async def _add_provenance(
        cosign_client: StaticKeySigner, sbom_ref: str, image: Image
    ) -> None:
        predicate = build_fn(sbom_ref, image)
        cosign_type: Literal["slsaprovenance02", "slsaprovenance1"] = (
            "slsaprovenance02" if request.param == "v0.2" else "slsaprovenance1"
        )
        await cosign_client.attest_provenance(predicate, image.reference, cosign_type)

    return _add_provenance
