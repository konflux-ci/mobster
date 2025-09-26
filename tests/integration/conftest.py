import asyncio
from collections.abc import AsyncGenerator, Generator
from typing import Any

import pytest
import pytest_asyncio

from mobster.cmd.upload.tpa import TPAClient, get_tpa_default_client
from mobster.tekton.s3 import S3Client
from tests.integration.oci_client import ReferrersTagOCIClient


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


@pytest.fixture
def oci_client(registry_url: str) -> ReferrersTagOCIClient:
    return ReferrersTagOCIClient(registry_url)


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
