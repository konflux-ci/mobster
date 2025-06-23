import argparse

import pytest

from mobster.cli import parse_concurrency, setup_arg_parser


def test_setup_arg_parser() -> None:
    # Test the setup_arg_parser function
    parser = setup_arg_parser()
    assert parser is not None
    assert parser.description == "Mobster CLI"


@pytest.mark.parametrize(
    ["value", "expected"],
    [
        ("1", 1),
        ("0", argparse.ArgumentTypeError),
        ("-1", argparse.ArgumentTypeError),
        ("not_a_number", ValueError),
    ],
)
def test_parse_concurrency(value: str, expected: int | type) -> None:
    if isinstance(expected, type):
        with pytest.raises(expected):
            parse_concurrency(value)
    else:
        assert parse_concurrency(value) == expected
