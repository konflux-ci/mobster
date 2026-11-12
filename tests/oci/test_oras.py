"""Unit tests for fetching CBOM blobs with ORAS."""

import hashlib
import json
from contextlib import nullcontext
from pathlib import Path
from unittest.mock import patch

import pytest

from mobster.image import Image
from mobster.oci.oras import CBOMFetchError, OrasClient


@pytest.mark.asyncio
async def test_fetch_cbom(tmp_path: Path) -> None:
    image = Image("quay.io/example/image", "sha256:" + "a" * 64)
    blob_url = "quay.io/example/cbom@sha256:" + "b" * 64
    authfile = tmp_path / "config.json"
    doc = {"bomFormat": "CycloneDX", "specVersion": "1.6"}
    raw = json.dumps(doc).encode()

    async def fetch(cmd: list[str], retry_times: int) -> tuple[int, bytes, bytes]:
        assert cmd[:5] == ["oras", "blob", "fetch", blob_url, "--output"]
        assert cmd[6:] == ["--registry-config", str(authfile)]
        assert retry_times == 3
        Path(cmd[5]).write_bytes(raw)
        return 0, b"", b""

    with (
        patch(
            "mobster.oci.oras.make_oci_auth_file", return_value=nullcontext(authfile)
        ) as make_auth,
        patch("mobster.oci.oras.run_async_subprocess", side_effect=fetch),
    ):
        cbom = await OrasClient.fetch_cbom(blob_url, image)

    make_auth.assert_called_once_with(blob_url)
    assert cbom.doc == doc
    assert cbom.digest == f"sha256:{hashlib.sha256(raw).hexdigest()}"
    assert cbom.image == image


@pytest.mark.asyncio
async def test_fetch_cbom_failure(tmp_path: Path) -> None:
    image = Image("quay.io/example/image", "sha256:" + "a" * 64)
    with (
        patch(
            "mobster.oci.oras.make_oci_auth_file",
            return_value=nullcontext(tmp_path / "config.json"),
        ),
        patch(
            "mobster.oci.oras.run_async_subprocess",
            return_value=(1, b"blob unavailable", b"access denied"),
        ),
        pytest.raises(CBOMFetchError, match="blob unavailable, access denied"),
    ):
        await OrasClient.fetch_cbom("quay.io/example/cbom@sha256:abc", image)
