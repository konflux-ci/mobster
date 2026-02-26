from pathlib import Path

import pytest


@pytest.fixture
def testdata_path() -> Path:
    return Path(__file__).parent.parent.joinpath("data/component")


@pytest.fixture
def sboms_path(testdata_path: Path) -> Path:
    return testdata_path.joinpath("sboms")


@pytest.fixture
def provenances_path(testdata_path: Path) -> Path:
    return testdata_path.joinpath("provenances")
