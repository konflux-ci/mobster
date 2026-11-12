"""End-to-end coverage of CBOM processing in the release Tekton workflow."""

import hashlib
import json
import sys
import uuid
from pathlib import Path
from typing import Any

import pytest
from packageurl import PackageURL

from mobster.cmd.upload.tpa import TPAClient
from mobster.image import Image
from mobster.oci import make_oci_auth_file
from mobster.oci.cosign import SignConfig, StaticSignConfig
from mobster.oci.cosign.static import StaticKeySigner
from mobster.release import ReleaseId
from mobster.tekton.artifact import (
    COMPONENT_ARTIFACT_NAME,
    ComponentArtifact,
    SBOMArtifact,
)
from mobster.tekton.s3 import S3Client
from mobster.utils import run_async_subprocess
from tests.integration.conftest import AttachBuildSBOMFunc
from tests.integration.oci_client import ReferrersTagOCIClient

TESTDATA_PATH = Path(__file__).parents[1] / "data"


async def attach_cbom(image: Image, tmp_path: Path) -> str:
    """Attach raw CBOM JSON as the crypto-scanner task does; return its blob URL."""
    fixture = TESTDATA_PATH / "integration/cbom.cyclonedx.json"
    doc = json.loads(fixture.read_text())
    doc["metadata"]["component"]["purl"] = image.purl_str()
    raw = json.dumps(doc).encode()
    (tmp_path / "cbom.json").write_bytes(raw)
    with make_oci_auth_file(image.reference) as authfile:
        code, _, stderr = await run_async_subprocess(
            [
                "oras",
                "attach",
                "--no-tty",
                "--plain-http",
                "--registry-config",
                str(authfile.absolute()),
                "--artifact-type",
                "application/json",
                image.reference,
                "cbom.json:application/json",
            ],
            cwd=tmp_path,
        )
    assert code == 0, stderr.decode()
    return f"{image.repository}@sha256:{hashlib.sha256(raw).hexdigest()}"


async def registry_state(
    client: ReferrersTagOCIClient, image: Image
) -> tuple[dict[str, str], Any]:
    """Capture both legacy tagged attestations and OCI referrers."""
    repo = image.repository.removeprefix(f"{client.registry}/")
    manifests = {
        tag: await client.fetch_manifest(repo, tag)
        for tag in await client.list_tags(repo)
    }
    code, stdout, stderr = await run_async_subprocess(
        ["oras", "discover", "--plain-http", "--format", "json", image.reference]
    )
    assert code == 0, stderr.decode()
    return manifests, json.loads(stdout)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "attach_build_sbom", ["provenance-v0.2", "provenance-v1"], indirect=True
)
@pytest.mark.parametrize("is_index", [False, True], ids=["singlearch", "index"])
@pytest.mark.parametrize("has_cbom", [True, False], ids=["cbom", "no-cbom-url"])
async def test_process_component_cbom(
    is_index: bool,
    has_cbom: bool,
    test_id: str,
    tmp_path: Path,
    oci_client: ReferrersTagOCIClient,
    attach_build_sbom: AttachBuildSBOMFunc,
    cosign_sign_key: str,
    cosign_verify_key: str,
    tpa_client: TPAClient,
    tpa_base_url: str,
    s3_client: S3Client,
    s3_sbom_bucket: str,
) -> None:
    """Upload only the component CBOM to TPA, without creating attestations."""
    source_repo = f"cbom-{uuid.uuid4().hex}"
    image = await oci_client.create_image(source_repo, "latest")
    if is_index:
        image = await oci_client.create_image_index(source_repo, "index", [image])

    # Include the usual SBOM task result alongside the separate CBOM task result.
    raw_sbom = (TESTDATA_PATH / "component/sboms/sha256:aaaaaaaa").read_text()
    raw_sbom = raw_sbom.replace("aaaaaaaa", image.digest.removeprefix("sha256:"))
    cbom_ref = await attach_cbom(image, tmp_path) if has_cbom else None
    build_purl = image.purl_str()
    if has_cbom:
        input_cbom = json.loads((tmp_path / "cbom.json").read_text())
        assert input_cbom["metadata"]["component"]["purl"] == build_purl
    signer = StaticKeySigner(
        SignConfig(static_sign_config=StaticSignConfig(sign_key=cosign_sign_key))
    )
    await attach_build_sbom(signer, image, raw_sbom.encode(), cbom_ref)

    repositories = []
    destinations = []
    for name in ("stable", "preview"):
        target = f"{oci_client.registry}/{source_repo}-{name}"
        await oci_client.copy_image(image.reference, f"{target}:1.0")
        destinations.append(Image(target, image.digest))
        repositories.append(
            {
                "url": target,
                "rh-registry-repo": f"registry.redhat.io/{source_repo}-{name}",
                "tags": ["1.0"],
            }
        )
    before = [await registry_state(oci_client, dest) for dest in destinations]

    snapshot = tmp_path / "snapshot.json"
    snapshot.write_text(
        json.dumps(
            {
                "components": [
                    {
                        "name": "crypto-component",
                        "containerImage": image.reference,
                        "repositories": repositories,
                    }
                ]
            }
        )
    )
    release_data = tmp_path / "data.json"
    release_data.write_text(
        json.dumps(
            {
                "releaseNotes": {
                    "product_name": "CBOM test",
                    "product_version": "1.0",
                    "cpe": [
                        "cpe:/a:acme:product:1.0:update1",
                        "cpe:/a:acme:product:1.0:update2",
                    ],
                }
            }
        )
    )
    results_dir = tmp_path / "results"
    results_dir.mkdir()
    release_id = ReleaseId.new()
    code, stdout, stderr = await run_async_subprocess(
        [
            str(Path(sys.executable).with_name("process_component_cbom")),
            "--data-dir",
            str(tmp_path),
            "--result-dir",
            str(results_dir),
            "--snapshot-spec",
            str(snapshot),
            "--release-data",
            str(release_data),
            "--release-id",
            str(release_id),
            "--atlas-api-url",
            tpa_base_url,
            "--retry-s3-bucket",
            s3_sbom_bucket,
            "--verify-key",
            cosign_verify_key,
            "--labels",
            f"test_id={test_id}",
        ]
    )
    assert code == 0, f"{stdout.decode()}\n{stderr.decode()}"

    artifact = SBOMArtifact.model_validate_json(
        (results_dir / COMPONENT_ARTIFACT_NAME).read_text()
    )
    assert isinstance(artifact.sboms, ComponentArtifact)
    uploaded_cboms = [
        cbom
        async for cbom in tpa_client.list_sboms(
            query=f"labels:test_id={test_id}", sort="ingested"
        )
    ]
    # There are 2 release registries, so 2 released component CBOMs
    assert len(uploaded_cboms) == (2 if has_cbom else 0)
    assert {url.rsplit("/", 1)[1] for url in artifact.sboms.component} == {
        cbom.id for cbom in uploaded_cboms
    }
    expected_components = json.loads(
        (TESTDATA_PATH / "integration/cbom.cyclonedx.json").read_text()
    )["components"]
    for cbom in uploaded_cboms:
        downloaded = tmp_path / f"{cbom.id}.json"
        await tpa_client.download_sbom(cbom.id, downloaded)
        doc = json.loads(downloaded.read_text())
        assert doc["bomFormat"] == "CycloneDX"
        assert doc["specVersion"] == "1.6"
        component = doc["metadata"]["component"]
        assert component["cpe"] == "cpe:/a:acme:product:1.0:update1"
        assert component["evidence"]["identity"] == [
            {"field": "cpe", "concludedValue": "cpe:/a:acme:product:1.0:update2"}
        ]
        # Components (crypto algorithms) remain unchanged
        assert doc["components"] == expected_components
        assert {"name": "release_id", "value": str(release_id)} in doc["properties"]
        release_purl = doc["metadata"]["component"]["purl"]
        assert release_purl != build_purl
        purl = PackageURL.from_string(release_purl)
        assert purl.version == image.digest
        assert isinstance(purl.qualifiers, dict)
        assert purl.qualifiers["tag"] == "1.0"
    # Check the CBOM was not attested
    assert [await registry_state(oci_client, dest) for dest in destinations] == before
    assert await s3_client.snapshot_exists(release_id)
    assert await s3_client.is_prefix_empty("/")
