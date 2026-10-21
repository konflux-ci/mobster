import argparse
from argparse import ArgumentParser

import pytest

from mobster.cli import (
    attest_command_parser,
    generate_oci_image_parser,
    parse_concurrency,
    parse_tpa_labels,
    setup_arg_parser,
)


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
                "--metadata-path",
                "asdf.yaml",
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


@pytest.mark.parametrize(
    ["image_ref", "success"],
    [
        ("quay.io/foo/bar@sha256:" + "a" * 64, True),
        ("quay.io/foo/bar:latest", False),
        ("not an url", False),
    ],
)
def test_attest_command_parser(image_ref: str, success: bool) -> None:
    main_parser = ArgumentParser("mobster")
    subparsers = main_parser.add_subparsers(dest="command", required=True)
    attest_command_parser(subparsers)

    command = [
        "attest",
        "--image-ref",
        image_ref,
        "--sbom-path",
        "sbom.json",
        "--rekor-url",
        "https://rekor.example.com",
        "--fulcio-url",
        "https://fulcio.example.com",
        "--oidc-issuer-url",
        "https://oidc.example.com",
        "--oidc-token-path",
        "token",
    ]

    if success:
        args = main_parser.parse_args(command)
        assert args.image_ref == image_ref
    else:
        with pytest.raises(SystemExit):
            main_parser.parse_args(command)


@pytest.mark.parametrize(
    ["arg", "expected"],
    [
        ("key1=value1", {"key1": "value1"}),
        ("key1=value1,key2=value2", {"key1": "value1", "key2": "value2"}),
        ("foo=bar,baz=qux,spam=ham", {"foo": "bar", "baz": "qux", "spam": "ham"}),
    ],
)
def test_parse_tpa_labels_valid(arg: str, expected: dict[str, str]) -> None:
    """
    Test parse_tpa_labels with valid inputs.
    """
    result = parse_tpa_labels(arg)
    assert result == expected


@pytest.mark.parametrize(
    "arg",
    [
        "",
        "key_without_value",
        "key=value,invalid",
        "=value",
        "key==value",
        "special=value=with=equals",
        "key1=value1,key2",
        "key1=value1,=",
        "key1=value1,,key2=value2",
        "empty=",
    ],
)
def test_parse_tpa_labels_invalid(arg: str) -> None:
    """
    Test parse_tpa_labels with invalid inputs.
    """
    with pytest.raises(argparse.ArgumentTypeError):
        parse_tpa_labels(arg)
