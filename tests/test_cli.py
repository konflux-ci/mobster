import argparse
from argparse import ArgumentParser

import pytest

from mobster.cli import generate_oci_image_parser, parse_concurrency, setup_arg_parser


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


@pytest.mark.parametrize(
    ["command", "success"],
    [
        (["generate", "oci-image"], False),
        (
            [
                "generate",
                "oci-image",
                "--from-syft",
                "foo",
                "--from-hermeto",
                "bar",
                "--image-pullspec",
                "quay.io/foo/bar:spam",
                "--image-digest",
                "sha256:1234567890123456789012345678901212345678901234567890123456789012",
                "--parsed-dockerfile-path",
                "ham",
                "--additional-base-image",
                "quay.io/foobar:latest@sha256:1111111111111111111111111111111111111111111111111111111111111111",
                "--contextualize",
            ],
            True,
        ),
    ],
)
def test_generate_oci_image_parser(command: list[str], success: bool) -> None:
    main_parser = ArgumentParser("mobster")
    generate_parser = main_parser.add_subparsers(dest="command", required=True)
    generate_subparser = generate_parser.add_parser("generate")
    oci_image_parser = generate_subparser.add_subparsers(dest="type")

    generate_oci_image_parser(oci_image_parser)

    if success:
        main_parser.parse_args(command)
    else:
        with pytest.raises(SystemExit):
            main_parser.parse_args(command)
