"""Unit tests for mobster.regenerate.cli module"""

from pathlib import Path
from unittest.mock import patch

from mobster.regenerate.by_release_id import (
    RegenerateReleaseArgs,
)
from mobster.regenerate.cli import (
    parse_args,
)
from mobster.regenerate.outage import RegenerateOutageArgs


def test_parse_args_outage(tmp_path: Path) -> None:
    """Test parse_args returns RegenerateOutageArgs for outage command"""
    release_file = tmp_path / "releases.txt"
    release_file.write_text("test-id\n")

    with patch(
        "sys.argv",
        [
            "script",
            "--output-dir",
            str(tmp_path),
            "--tpa-base-url",
            "https://tpa.url",
            "--s3-bucket-url",
            "https://s3.url",
            "--concurrency",
            "5",
            "--tpa-retries",
            "3",
            "outage",
            "--since",
            "2025-01-01T00:00:00Z",
            "--until",
            "2025-01-02T00:00:00Z",
        ],
    ):
        args = parse_args()

        assert isinstance(args, RegenerateOutageArgs)
        assert args.since is not None
        assert args.until is not None


def test_parse_args_release(tmp_path: Path) -> None:
    """Test parse_args returns RegenerateReleaseArgs for release command"""
    release_file = tmp_path / "releases.txt"
    release_id_1 = "13231699-2e25-410e-9885-93aa49e5904b"
    release_id_2 = "82d1143c-5ea5-44dd-92a2-a89ddb2c0148"
    release_file.write_text(f"{release_id_1}\n{release_id_2}\n")

    with patch(
        "sys.argv",
        [
            "script",
            "--output-dir",
            str(tmp_path),
            "--tpa-base-url",
            "https://tpa.url",
            "--s3-bucket-url",
            "https://s3.url",
            "--concurrency",
            "5",
            "--tpa-retries",
            "3",
            "release",
            "--release-id-file",
            str(release_file),
        ],
    ):
        args = parse_args()

        assert isinstance(args, RegenerateReleaseArgs)
        assert len(args.release_ids) == 2
        assert str(args.release_ids[0]) == release_id_1
        assert str(args.release_ids[1]) == release_id_2
