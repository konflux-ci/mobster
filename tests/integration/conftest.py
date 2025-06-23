import pytest

from tests.integration.oci_client import ReferrersTagOCIClient


def pytest_addoption(parser):
    parser.addoption("--registry-url", action="store", default="http://localhost:9000")


@pytest.fixture
def registry_url(request):
    return request.config.getoption("--registry-url")


@pytest.fixture
def oci_client(registry_url: str) -> ReferrersTagOCIClient:
    return ReferrersTagOCIClient(registry_url)
