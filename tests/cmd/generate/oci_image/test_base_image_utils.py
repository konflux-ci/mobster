import pytest

from mobster.cmd.generate.oci_image.base_image_utils import (
    get_images_and_their_annotations,
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
