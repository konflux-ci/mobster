from mobster import utils


def test_normalize_file_name() -> None:
    """
    Test the normalize_file_name function.
    """
    assert utils.normalize_file_name("valid_filename.txt") == "valid_filename.txt"
    assert utils.normalize_file_name("invalid|filename.txt") == "invalid_filename.txt"
    assert (
        utils.normalize_file_name("another:invalid?name.txt")
        == "another_invalid_name.txt"
    )
    assert utils.normalize_file_name("quay.io/foo/bar:1") == "quay.io_foo_bar_1"
    assert utils.normalize_file_name("file*name<>.txt") == "file_name__.txt"
    assert (
        utils.normalize_file_name("file/name\\with\\slashes.txt")
        == "file_name_with_slashes.txt"
    )
    assert utils.normalize_file_name("") == ""
