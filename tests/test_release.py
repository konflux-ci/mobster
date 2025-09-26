import json
from pathlib import Path
from typing import Any
from unittest.mock import mock_open, patch

import pytest

from mobster.image import Image, IndexImage
from mobster.release import (
    Component,
    ComponentModel,
    ReleaseRepository,
    Snapshot,
    make_snapshot,
)
from tests.conftest import random_digest


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
    digest1 = random_digest()
    digest2 = random_digest()
    child_digest1 = random_digest()
    child_digest2 = random_digest()

    snapshot_raw = json.dumps(
        {
            "components": [
                {
                    "name": "comp-1",
                    "containerImage": f"quay.io/repo1@{digest1}",
                    "rh-registry-repo": "registry.redhat.io/repo1",
                    "tags": ["1.0"],
                    "repositories": [
                        {
                            "rh-registry-repo": "registry.redhat.io/repo1",
                            "tags": ["1.0"],
                            "url": "quay.io/repo1",
                            "irrelevant_field": "irrelevant value",
                        },
                        {
                            "rh-registry-repo": "registry.redhat.io/oper1",
                            "url": "quay.io/oper1",
                            "tags": ["1.0", "latest"],
                        },
                    ],
                },
                {
                    "name": "comp-2",
                    "containerImage": f"quay.io/repo2@{digest2}",
                    "repositories": [
                        {
                            "rh-registry-repo": "registry.redhat.io/repo2",
                            "tags": ["2.0", "latest"],
                            "irrelevant_field": "irrelevant value",
                            "url": "quay.io/repo2",
                        },
                    ],
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
                    digest1,
                    children=[Image("quay.io/repo1", child_digest1)],
                ),
                # Make sure "repo1" is not replicated even if present in both fields
                release_repositories=[
                    ReleaseRepository(
                        public_repo_url="registry.redhat.io/repo1",
                        tags=["1.0"],
                        internal_repo_url="quay.io/repo1",
                    ),
                    ReleaseRepository(
                        public_repo_url="registry.redhat.io/oper1",
                        tags=["1.0", "latest"],
                        internal_repo_url="quay.io/oper1",
                    ),
                ],
            ),
            Component(
                name="comp-2",
                image=IndexImage(
                    "quay.io/repo2",
                    digest2,
                    children=[Image("quay.io/repo2", child_digest2)],
                ),
                release_repositories=[
                    ReleaseRepository(
                        public_repo_url="registry.redhat.io/repo2",
                        tags=["2.0", "latest"],
                        internal_repo_url="quay.io/repo2",
                    )
                ],
            ),
        ],
    )

    def fake_get_image_manifest(reference: str) -> dict[str, Any]:
        if "quay.io/repo1" in reference:
            return {
                **index_manifest,
                "manifests": [{"digest": child_digest1}],
            }

        return {
            **index_manifest,
            "manifests": [{"digest": child_digest2}],
        }

    with patch("mobster.image.get_image_manifest", side_effect=fake_get_image_manifest):
        with patch("builtins.open", mock_open(read_data=snapshot_raw)):
            snapshot = await make_snapshot(Path(""))
            assert snapshot == expected_snapshot


@pytest.mark.asyncio
async def test_make_snapshot_backwards_compatible() -> None:
    """Verify backwards compatibility of a Snapshot schema."""
    snapshot_raw = json.dumps(
        {
            "components": [
                {
                    "name": "comp-1",
                    "containerImage": f"quay.io/repo1@sha256:{'a' * 128}",
                    "rh-registry-repo": "registry.redhat.io/repo1",
                    "repository": "quay.io/repo1",
                    "tags": ["1.0"],
                },
            ]
        }
    )
    fake_manifest = {
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": [{"digest": "sha256:" + "b" * 128}],
    }
    with patch("mobster.image.get_image_manifest", return_value=fake_manifest):
        with patch("builtins.open", mock_open(read_data=snapshot_raw)):
            snapshot = await make_snapshot(Path(""))
            assert snapshot == Snapshot(
                components=[
                    Component(
                        name="comp-1",
                        image=IndexImage(
                            "quay.io/repo1",
                            f"sha256:{'a' * 128}",
                            children=[Image("quay.io/repo1", f"sha256:{'b' * 128}")],
                        ),
                        release_repositories=[
                            ReleaseRepository(
                                public_repo_url="registry.redhat.io/repo1",
                                tags=["1.0"],
                                internal_repo_url="quay.io/repo1",
                            ),
                        ],
                    ),
                ],
            )


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
        pytest.param(
            "sha256:e2801b239ed5708c62b70968d2589d84fffbba45a3e553ded40968440950eff3"
        ),
        pytest.param(None),
    ],
)
async def test_make_snapshot_specific(
    specific_digest: str | None, index_manifest: dict[str, str]
) -> None:
    if specific_digest is not None:
        digest1 = specific_digest
    else:
        digest1 = random_digest()

    digest2 = random_digest()
    child_digest1 = random_digest()
    child_digest2 = random_digest()

    snapshot_raw = json.dumps(
        {
            "components": [
                {
                    "name": "comp-1",
                    "containerImage": f"quay.io/repo1@{digest1}",
                    "rh-registry-repo": "registry.redhat.io/repo1",
                    "repository": "quay.io/repo1",
                    "tags": ["1.0"],
                },
                {
                    "name": "comp-2",
                    "containerImage": f"quay.io/repo2@{digest2}",
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
                    digest1,
                    children=[Image("quay.io/repo1", child_digest1)],
                ),
                release_repositories=[
                    ReleaseRepository(
                        "registry.redhat.io/repo1",
                        tags=["1.0"],
                        internal_repo_url="quay.io/repo1",
                    )
                ],
            ),
        ],
    )

    if specific_digest is None:
        expected_snapshot.components.append(
            Component(
                name="comp-2",
                image=IndexImage(
                    "quay.io/repo2",
                    digest2,
                    children=[Image("quay.io/repo2", child_digest2)],
                ),
                release_repositories=[
                    ReleaseRepository(
                        public_repo_url="registry.redhat.io/repo2",
                        tags=["2.0", "latest"],
                        internal_repo_url="quay.io/repo2",
                    )
                ],
            )
        )

    def fake_get_image_manifest(reference: str) -> dict[str, Any]:
        if "quay.io/repo1" in reference:
            return {
                **index_manifest,
                "manifests": [{"digest": child_digest1}],
            }

        return {
            **index_manifest,
            "manifests": [{"digest": child_digest2}],
        }

    with patch("mobster.image.get_image_manifest", side_effect=fake_get_image_manifest):
        with patch("builtins.open", mock_open(read_data=snapshot_raw)):
            snapshot = await make_snapshot(Path(""), specific_digest)
            assert snapshot == expected_snapshot


@pytest.mark.parametrize(
    ["reference"],
    [
        pytest.param(
            "quay.io/repo@sha256:f1d71ba64b07ce65b60967c6ed0b2c628e63b34a16b6d6f4a5c9539fd096309d",
        ),
        pytest.param(
            "quay.io/namespace/repo@sha256:f1d71ba64b07ce65b60967c6ed0b2c628e63b34a16b6d6f4a5c9539fd096309d",
        ),
        pytest.param(
            "localhost:8000/repo@sha256:f1d71ba64b07ce65b60967c6ed0b2c628e63b34a16b6d6f4a5c9539fd096309d",
        ),
    ],
)
def test_is_valid_digest_reference_valid(reference: str) -> None:
    assert reference == ComponentModel.is_valid_digest_reference(reference)


@pytest.mark.parametrize(
    ["reference"],
    [
        pytest.param(
            "quay.io/repo@sha128:f1d71ba64b07ce65b60967c6ed0b2c62",
        ),
        pytest.param(
            "quay.io/repo@sha512:f1d71ba64b07ce65b60967c6ed0b2c62",
        ),
        pytest.param(
            "quay.io/repo:latest",
        ),
    ],
)
def test_is_valid_digest_reference_invalid(reference: str) -> None:
    with pytest.raises(ValueError):
        ComponentModel.is_valid_digest_reference(reference)
