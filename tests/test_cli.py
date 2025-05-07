from mobster.cli import setup_arg_parser


def test_setup_arg_parser() -> None:
    # Test the setup_arg_parser function
    parser = setup_arg_parser()
    assert parser is not None
    assert parser.description == "Mobster CLI"
