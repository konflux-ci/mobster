"""Unit tests for mobster.regenerate entrypoint scripts"""

from unittest.mock import MagicMock, patch

from mobster.regenerate.base import SbomType
from mobster.regenerate.component import main as component_main
from mobster.regenerate.product import main as product_main


@patch("mobster.regenerate.product.run")
def test_product_main(mock_run: MagicMock) -> None:
    """Test product entrypoint main function"""
    product_main()

    mock_run.assert_called_once_with(SbomType.PRODUCT)


@patch("mobster.regenerate.component.run")
def test_component_main(mock_run: MagicMock) -> None:
    """Test component entrypoint main function"""
    component_main()

    mock_run.assert_called_once_with(SbomType.COMPONENT)
