from hashlib import sha256
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest

from mobster.cmd.generate.oci_image.base_image_utils import (
    get_images_and_their_annotations,
    get_objects_for_base_images,
)
from mobster.image import Image


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ["base_images_refs", "base_images", "expected_output"],
    [
        pytest.param(
            ["alpine:3.10", None, "foobar:v1"],
            {
                "alpine:3.10": Image.from_image_index_url_and_digest(
                    "alpine:3.10", "sha256:1"
                ),
                "foobar:v1": Image.from_image_index_url_and_digest(
                    "foobar:v1", "sha256:2"
                ),
            },
            [
                (
                    Image.from_image_index_url_and_digest("alpine:3.10", "sha256:1"),
                    [
                        {
                            "name": "konflux:container:is_builder_image:for_stage",
                            "value": "0",
                        }
                    ],
                ),
                (
                    Image.from_image_index_url_and_digest("foobar:v1", "sha256:2"),
                    [{"name": "konflux:container:is_base_image", "value": "true"}],
                ),
            ],
            id="3 Stages, Stage 1 is FROM SCRATCH",
        ),
        pytest.param(
            ["alpine:3.10", None, "foobar:v1", "alpine:3.10"],
            {
                "alpine:3.10": Image.from_image_index_url_and_digest(
                    "alpine:3.10", "sha256:1"
                ),
                "foobar:v1": Image.from_image_index_url_and_digest(
                    "foobar:v1", "sha256:2"
                ),
            },
            [
                (
                    Image.from_image_index_url_and_digest("foobar:v1", "sha256:2"),
                    [
                        {
                            "name": "konflux:container:is_builder_image:for_stage",
                            "value": "2",  # Stage 1 is FROM SCRATCH,
                            # this value is correct.
                        },
                    ],
                ),
                (
                    Image.from_image_index_url_and_digest("alpine:3.10", "sha256:1"),
                    [
                        {
                            "name": "konflux:container:is_builder_image:for_stage",
                            "value": "0",
                        },
                        {"name": "konflux:container:is_base_image", "value": "true"},
                    ],
                ),
            ],
            id="4 Stages, Stage 1 is FROM SCRATCH and 4th Stage is the same as Stage 0",
        ),
    ],
)
async def test_get_images_and_their_annotations(
    base_images_refs: list[str | None],
    base_images: dict[str, Image],
    expected_output: list[tuple[Image, list[dict[str, str]]]],
) -> None:
    assert (
        await get_images_and_their_annotations(base_images_refs, base_images)
        == expected_output
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    [
        "base_images_refs",
        "expected_outcome",
        "oras_stderr",
    ],
    [
        (
            [
                "registry.access.redhat.com/ubi8/ubi:latest",
                "alpine:3.10",
                None,
                "registry.access.redhat.com/ubi8/ubi:latest",
            ],
            {
                "alpine:3.10": Image.from_image_index_url_and_digest(
                    "alpine:3.10",
                    "sha256:ef437a97b47a6c00ea884fa314df3e05d542e14ef999c344e394808c2b7035d9",
                ),
                "registry.access.redhat.com/ubi8/ubi"
                ":latest": Image.from_image_index_url_and_digest(
                    "registry.access.redhat.com/ubi8/ubi:latest",
                    "sha256:f75e57db5cbc53b37a8b33a0b0b084782ddae260220d9dd8cc968eab4d579062",
                ),
            },
            b"",
        ),
        (
            [
                "registry.access.redhat.com/ubi8/ubi:latest",
            ],
            {},
            b"Uh oh, error I guess.",
        ),
    ],
)
@patch("mobster.cmd.generate.oci_image.base_image_utils.run_async_subprocess")
@patch("mobster.cmd.generate.oci_image.base_image_utils.make_oci_auth_file")
@patch("mobster.cmd.generate.oci_image.base_image_utils.LOGGER")
async def test_get_objects_for_base_images(
    mock_logger: AsyncMock,
    mock_make_oci_auth_file: AsyncMock,
    mock_run_async_subprocess: AsyncMock,
    base_images_refs: list[str | None],
    expected_outcome: dict[str, Image],
    oras_stderr: bytes,
) -> None:
    def mocked_subprocess_calling(*args: Any, **_: Any) -> tuple[int, bytes, bytes]:
        digest = f"sha256:{sha256(args[0][-1].encode()).hexdigest()}\n".encode()
        return (
            (int(bool(oras_stderr))),
            digest,
            oras_stderr,
        )

    mock_run_async_subprocess.side_effect = mocked_subprocess_calling

    assert await get_objects_for_base_images(base_images_refs) == expected_outcome

    if oras_stderr:
        assert any(
            args[0].startswith("Problem getting digest of a base image")
            for args in mock_logger.warning.call_args
        )
