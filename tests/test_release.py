import json
from pathlib import Path
from typing import Any
from unittest.mock import mock_open, patch

import pytest

from mobster.image import Image, IndexImage
from mobster.release import Component, ComponentModel, Snapshot, make_snapshot


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ["index_manifest"],
    [
        pytest.param(
            {"mediaType": "application/vnd.oci.image.index.v1+json"}, id="oci-index"
        ),
        pytest.param(
            {"mediaType": "application/vnd.docker.distribution.manifest.list.v2+json"},
            id="docker-manifest-list",
        ),
    ],
)
async def test_make_snapshot(index_manifest: dict[str, str]) -> None:
    snapshot_raw = json.dumps(
        {
            "components": [
                {
                    "name": "comp-1",
                    "containerImage": "quay.io/repo1@sha256:deadbeef",
                    "rh-registry-repo": "registry.redhat.io/repo1",
                    "repository": "quay.io/repo1",
                    "tags": ["1.0"],
                },
                {
                    "name": "comp-2",
                    "containerImage": "quay.io/repo2@sha256:ffffffff",
                    "rh-registry-repo": "registry.redhat.io/repo2",
                    "repository": "quay.io/repo2",
                    "tags": ["2.0", "latest"],
                },
            ]
        }
    )

    expected_snapshot = Snapshot(
        components=[
            Component(
                name="comp-1",
                image=IndexImage(
                    "quay.io/repo1",
                    "sha256:deadbeef",
                    children=[Image("quay.io/repo1", "sha256:aaaaffff")],
                ),
                tags=["1.0"],
                repository="registry.redhat.io/repo1",
            ),
            Component(
                name="comp-2",
                image=IndexImage(
                    "quay.io/repo2",
                    "sha256:ffffffff",
                    children=[Image("quay.io/repo2", "sha256:bbbbffff")],
                ),
                tags=["2.0", "latest"],
                repository="registry.redhat.io/repo2",
            ),
        ],
    )

    def fake_get_image_manifest(reference: str) -> dict[str, Any]:
        if "quay.io/repo1" in reference:
            child_digest = "sha256:aaaaffff"

            return {
                **index_manifest,
                "manifests": [{"digest": child_digest}],
            }

        child_digest = "sha256:bbbbffff"
        return {
            **index_manifest,
            "manifests": [{"digest": child_digest}],
        }

    with patch("mobster.image.get_image_manifest", side_effect=fake_get_image_manifest):
        with patch("builtins.open", mock_open(read_data=snapshot_raw)):
            snapshot = await make_snapshot(Path(""))
            assert snapshot == expected_snapshot


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ["index_manifest"],
    [
        pytest.param(
            {"mediaType": "application/vnd.oci.image.index.v1+json"}, id="oci-index"
        ),
        pytest.param(
            {"mediaType": "application/vnd.docker.distribution.manifest.list.v2+json"},
            id="docker-manifest-list",
        ),
    ],
)
@pytest.mark.parametrize(
    ["specific_digest"],
    [
        pytest.param("sha256:deadbeef"),
        pytest.param(None),
    ],
)
async def test_make_snapshot_specific(
    specific_digest: str | None, index_manifest: dict[str, str]
) -> None:
    snapshot_raw = json.dumps(
        {
            "components": [
                {
                    "name": "comp-1",
                    "containerImage": "quay.io/repo1@sha256:deadbeef",
                    "rh-registry-repo": "registry.redhat.io/repo1",
                    "repository": "quay.io/repo1",
                    "tags": ["1.0"],
                },
                {
                    "name": "comp-2",
                    "containerImage": "quay.io/repo2@sha256:ffffffff",
                    "rh-registry-repo": "registry.redhat.io/repo2",
                    "repository": "quay.io/repo2",
                    "tags": ["2.0", "latest"],
                },
            ]
        }
    )

    expected_snapshot = Snapshot(
        components=[
            Component(
                name="comp-1",
                image=IndexImage(
                    "quay.io/repo1",
                    "sha256:deadbeef",
                    children=[Image("quay.io/repo1", "sha256:aaaaffff")],
                ),
                tags=["1.0"],
                repository="registry.redhat.io/repo1",
            ),
        ],
    )

    if specific_digest is None:
        expected_snapshot.components.append(
            Component(
                name="comp-2",
                image=IndexImage(
                    "quay.io/repo2",
                    "sha256:ffffffff",
                    children=[Image("quay.io/repo2", "sha256:bbbbffff")],
                ),
                tags=["2.0", "latest"],
                repository="registry.redhat.io/repo2",
            )
        )

    def fake_get_image_manifest(reference: str) -> dict[str, Any]:
        if "quay.io/repo1" in reference:
            child_digest = "sha256:aaaaffff"

            return {
                **index_manifest,
                "manifests": [{"digest": child_digest}],
            }

        child_digest = "sha256:bbbbffff"
        return {
            **index_manifest,
            "manifests": [{"digest": child_digest}],
        }

    with patch("mobster.image.get_image_manifest", side_effect=fake_get_image_manifest):
        with patch("builtins.open", mock_open(read_data=snapshot_raw)):
            snapshot = await make_snapshot(Path(""), specific_digest)
            assert snapshot == expected_snapshot


@pytest.mark.parametrize(
    ["reference", "expected_digest"],
    [
        pytest.param(
            "quay.io/repo@sha256:f1d71ba64b07ce65b60967c6ed0b2c628e63b34a16b6d6f4a5c9539fd096309d",
            "sha256:f1d71ba64b07ce65b60967c6ed0b2c628e63b34a16b6d6f4a5c9539fd096309d",
        ),
        pytest.param(
            "quay.io/org/repo@sha256:f1d71ba64b07ce65b60967c6ed0b2c628e63b34a16b6d6f4a5c9539fd096309d",
            "sha256:f1d71ba64b07ce65b60967c6ed0b2c628e63b34a16b6d6f4a5c9539fd096309d",
        ),
    ],
)
def test_is_valid_digest_reference_valid(reference: str, expected_digest: str) -> None:
    assert expected_digest == ComponentModel.is_valid_digest_reference(reference)


@pytest.mark.parametrize(
    ["reference"],
    [
        pytest.param(
            "quay.io/repo:5000@sha256:f1d71ba64b07ce65b60967c6ed0b2c628e63b34a16b6d6f4a5c9539fd096309d",
        ),
        pytest.param(
            "quay.io/repo@sha128:f1d71ba64b07ce65b60967c6ed0b2c62",
        ),
        pytest.param(
            "quay.io/repo:latest",
        ),
    ],
)
def test_is_valid_digest_reference_invalid(reference: str) -> None:
    with pytest.raises(ValueError):
        ComponentModel.is_valid_digest_reference(reference)
