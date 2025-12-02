"""Unit tests for mobster.regenerate.cli module"""

import argparse
from pathlib import Path
from unittest.mock import patch

from mobster.regenerate.by_release_id import (
    RegenerateReleaseArgs,
)
from mobster.regenerate.cli import (
    _add_invalid_regeneration_args,
    _add_outage_args,
    _add_release_args,
    add_args,
    parse_args,
    prepare_output_paths,
)
from mobster.regenerate.outage import RegenerateOutageArgs


def test_add_args() -> None:
    """Test add_args adds all required arguments"""
    parser = argparse.ArgumentParser()
    add_args(parser)

    # Check that arguments can be parsed
    args = parser.parse_args(
        [
            "--output-dir",
            "/tmp",
            "--tpa-base-url",
            "https://tpa.url",
            "--s3-bucket-url",
            "https://s3.url",
            "--concurrency",
            "10",
            "--tpa-retries",
            "5",
            "--tpa-page-size",
            "100",
            "--dry-run",
            "--non-fail-fast",
            "--verbose",
            "invalid",
            "--mobster-versions",
            "1.2.3",
        ]
    )

    assert args.output_dir == "/tmp"
    assert args.tpa_base_url == "https://tpa.url"
    assert args.s3_bucket_url == "https://s3.url"
    assert args.concurrency == 10
    assert args.tpa_retries == 5
    assert args.tpa_page_size == 100
    assert args.dry_run is True
    assert args.non_fail_fast is True
    assert args.verbose is True
    assert args.command == "invalid"


def test_add_outage_args() -> None:
    """Test _add_outage_args adds outage-specific arguments"""
    parser = argparse.ArgumentParser()
    _add_outage_args(parser)

    # Check that arguments can be parsed
    args = parser.parse_args(
        [
            "--since",
            "2025-01-01T00:00:00Z",
            "--until",
            "2025-01-02T00:00:00Z",
        ]
    )

    assert args.since is not None
    assert args.until is not None


def test_add_invalid_regeneration_args() -> None:
    """Test _add_invalid_regeneration_args adds invalid-specific arguments"""
    parser = argparse.ArgumentParser()
    _add_invalid_regeneration_args(parser)

    # Check that arguments can be parsed
    args = parser.parse_args(
        [
            "--mobster-versions",
            "1.2.3,4.5.6",
            "--ignore-missing-releaseid",
        ]
    )

    assert args.mobster_versions == "1.2.3,4.5.6"
    assert args.ignore_missing_releaseid is True


def test_add_release_args(tmp_path: Path) -> None:
    """Test _add_release_args adds release-specific arguments"""
    parser = argparse.ArgumentParser()
    _add_release_args(parser)

    release_file = tmp_path / "releases.txt"
    release_file.touch()

    # Check that arguments can be parsed
    args = parser.parse_args(
        [
            "--release-id-file",
            str(release_file),
        ]
    )

    assert args.release_id_file == release_file


def test_prepare_output_paths_with_none() -> None:
    """Test prepare_output_paths creates temp dir when output_dir is None"""
    with (
        patch("mobster.regenerate.cli.tempfile.mkdtemp") as mock_mkdtemp,
        patch("mobster.regenerate.cli.atexit.register") as mock_atexit,
        patch("mobster.regenerate.cli.shutil.rmtree") as mock_rmtree,
    ):
        mock_mkdtemp.return_value = "/tmp/test123"
        result = prepare_output_paths("")

        assert result == Path("/tmp/test123")
        mock_mkdtemp.assert_called_once()
        mock_atexit.assert_called_once()
        # Verify the cleanup function was registered
        cleanup_func = mock_atexit.call_args[0][0]
        cleanup_func()
        mock_rmtree.assert_called_once_with("/tmp/test123")


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
