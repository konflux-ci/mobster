import os
import subprocess
from argparse import ArgumentParser
from dataclasses import dataclass
from pathlib import Path

from mobster.tekton.s3 import S3Client


class AtlasTransientError(Exception):
    """"""


class AtlasUploadError(Exception):
    """"""


@dataclass
class CommonArgs:
    data_dir: Path
    snapshot_spec: Path
    atlas_api_url: str
    retry_s3_bucket: str


def add_common_args(parser: ArgumentParser) -> None:
    parser.add_argument("--data-dir", type=Path, required=True)
    parser.add_argument("--snapshot-spec", type=Path, required=True)
    parser.add_argument("--atlas-api-url", type=str)
    parser.add_argument("--retry-s3-bucket", type=str)


async def upload_sboms(dir: Path, atlas_url: str, retry_s3_bucket: str | None):
    if not atlas_credentials_exist():
        raise ValueError("Missing Atlas authentication.")

    try:
        upload_to_atlas(dir, atlas_url)
    except AtlasTransientError as e:
        if retry_s3_bucket:
            if not s3_credentials_exist():
                raise ValueError("Missing AWS authentication.") from e
            await upload_to_s3(dir, retry_s3_bucket)


def upload_to_atlas(dir: Path, atlas_url: str):
    res = subprocess.run(
        [
            "mobster",
            "--verbose",
            "upload",
            "tpa",
            "--tpa-base-url",
            atlas_url,
            "--from-dir",
            dir,
            "--report",
        ]
    )
    if res.returncode == 2:
        raise AtlasTransientError()

    if res.returncode != 0:
        raise AtlasUploadError(res.stderr)


async def upload_to_s3(dir: Path, bucket: str):
    client = S3Client(
        bucket=bucket,
        access_key=os.environ["AWS_ACCESS_KEY_ID"],
        secret_key=os.environ["AWS_SECRET_ACCESS_KEY"],
        endpoint_url=os.environ.get(
            "AWS_ENDPOINT_URL"
        ),  # configurable for testing purposes
    )

    await client.upload_dir(dir)


def atlas_credentials_exist():
    return (
        "MOBSTER_TPA_SSO_ACCOUNT" in os.environ
        and "MOBSTER_TPA_SSO_TOKEN" in os.environ
        and "MOBSTER_TPA_SSO_TOKEN_URL" in os.environ
    )


def s3_credentials_exist():
    return "AWS_ACCESS_KEY_ID" in os.environ and "AWS_SECRET_ACCESS_KEY" in os.environ
