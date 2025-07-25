from collections.abc import AsyncGenerator
from typing import Any

import pytest
import pytest_asyncio

from mobster.cmd.upload.tpa import TPAClient
from mobster.tekton.s3 import S3Client
from tests.integration.oci_client import ReferrersTagOCIClient


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


@pytest.fixture
def tpa_base_url(request: Any) -> str:
    return request.config.getoption("--tpa-base-url")  # type: ignore


@pytest.fixture
def s3_endpoint_url(request: Any) -> str:
    return request.config.getoption("--s3-endpoint-url")  # type: ignore


@pytest.fixture
def oci_client(registry_url: str) -> ReferrersTagOCIClient:
    return ReferrersTagOCIClient(registry_url)


@pytest.fixture
def tpa_auth_env(monkeypatch: pytest.MonkeyPatch) -> dict[str, str]:
    """Set up environment variables needed to disable TPA authentication."""
    vars = {
        "MOBSTER_TPA_SSO_TOKEN_URL": "dummy",
        "MOBSTER_TPA_SSO_ACCOUNT": "dummy",
        "MOBSTER_TPA_SSO_TOKEN": "dummy",
        "MOBSTER_TPA_AUTH_DISABLE": "true",
    }
    for key, val in vars.items():
        monkeypatch.setenv(key, val)

    return vars


@pytest.fixture
def s3_auth_env(
    s3_endpoint_url: str, monkeypatch: pytest.MonkeyPatch
) -> dict[str, str]:
    # these are set in compose.yaml
    vars = {
        "AWS_ACCESS_KEY_ID": "minioAccessKey",
        "AWS_SECRET_ACCESS_KEY": "minioSecretKey",
        "AWS_ENDPOINT_URL": s3_endpoint_url,
    }

    for key, val in vars.items():
        monkeypatch.setenv(key, val)

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


@pytest_asyncio.fixture
async def tpa_client(
    tpa_base_url: str, tpa_auth_env: Any
) -> AsyncGenerator[TPAClient, None]:
    client = TPAClient(
        base_url=tpa_base_url,
        auth=None,
    )

    async def cleanup() -> None:
        sboms = client.list_sboms(query="", sort="ingested")
        async for sbom in sboms:
            await client.delete_sbom(sbom.id)

    # Run cleanup before providing the client
    await cleanup()

    yield client

    # Run cleanup after test completes
    await cleanup()
