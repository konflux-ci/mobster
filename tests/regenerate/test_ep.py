# File: tests/test_ep.py

from unittest.mock import MagicMock, patch

import pytest

from mobster.regenerate.base import SbomType
from mobster.regenerate.component import main as component_main
from mobster.regenerate.product import main as product_main


@pytest.fixture
def dummy_args() -> list[str]:
    """Fixture to simulate command line arguments."""
    return [
        "--tpa-base-url",
        "https://tpa.url",
        "--s3-bucket-url",
        "https://s3.url/bucket",
        "--mobster-versions",
        "0.1.2,3.4.5",
        "--concurrency",
        "500",
        "--tpa-retries",
        "300",
        "--tpa-page-size",
        "1500",
        "--dry-run",
        "--non-fail-fast",
        "--ignore-missing-releaseid",
        "--verbose",
    ]


@patch("mobster.regenerate.product.setup_logging")
@patch("mobster.regenerate.product.parse_args")
@patch("mobster.regenerate.product.SbomRegenerator")
@patch("mobster.regenerate.product.asyncio.run")
def test_product_main(  # type: ignore[no-untyped-def]
    mock_asyncio_run,
    mock_sbom_regenerator_cls,
    mock_parse_args,
    mock_setup_logging,
) -> None:
    mock_setup_logging.return_value = None
    mock_args = MagicMock()
    mock_parse_args.return_value = mock_args
    mock_regen_instance = MagicMock()
    mock_sbom_regenerator_cls.return_value = mock_regen_instance

    product_main()

    mock_setup_logging.assert_called_once_with(verbose=True)
    mock_parse_args.assert_called_once_with()
    mock_sbom_regenerator_cls.assert_called_once_with(mock_args, SbomType.PRODUCT)
    mock_asyncio_run.assert_called_once_with(mock_regen_instance.regenerate_sboms())


@patch("mobster.regenerate.component.setup_logging")
@patch("mobster.regenerate.component.parse_args")
@patch("mobster.regenerate.component.SbomRegenerator")
@patch("mobster.regenerate.component.asyncio.run")
def test_component_main(  # type: ignore[no-untyped-def]
    mock_asyncio_run,
    mock_sbom_regenerator_cls,
    mock_parse_args,
    mock_setup_logging,
) -> None:
    mock_setup_logging.return_value = None
    mock_args = MagicMock()
    mock_parse_args.return_value = mock_args
    mock_regen_instance = MagicMock()
    mock_sbom_regenerator_cls.return_value = mock_regen_instance

    component_main()

    mock_setup_logging.assert_called_once_with(verbose=True)
    mock_parse_args.assert_called_once_with()
    mock_sbom_regenerator_cls.assert_called_once_with(mock_args, SbomType.COMPONENT)
    mock_asyncio_run.assert_called_once_with(mock_regen_instance.regenerate_sboms())
