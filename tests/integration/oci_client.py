import hashlib
import json
import tempfile
from dataclasses import dataclass
from typing import Any, Literal

import httpx

from mobster.image import Image
from mobster.utils import run_async_subprocess


@dataclass
class Layer:
    media_type: str
    digest: str
    size: int

    def asdict(self) -> Any:
        """
        Convert the layer to a dictionary representation.

        Returns:
            dict: Dictionary representation of the layer.
        """
        return {
            "mediaType": self.media_type,
            "digest": self.digest,
            "size": self.size,
        }


class ReferrersTagOCIClient:
    """
    OCI client for integration tests using referrers tag approach.
    """

    def __init__(self, registry_url: str) -> None:
        """
        Initialize the OCI client.

        Args:
            registry_url: The URL of the OCI registry.
        """
        self.registry_url = registry_url

    @property
    def registry(self) -> str:
        """
        Get the registry hostname without protocol prefix.

        Returns:
            str: The registry hostname.
        """
        for prefix in ["http://", "https://"]:
            if self.registry_url.startswith(prefix):
                return self.registry_url.removeprefix(prefix)
        return self.registry_url

    def _get_digest_from_manifest(self, manifest: str) -> str:
        """
        Calculate the digest from the manifest string.

        Args:
            manifest: The manifest string.

        Returns:
            str: The extracted sha256 digest.
        """
        m = hashlib.sha256()
        m.update(manifest.encode("utf-8"))
        return f"sha256:{m.hexdigest()}"

    async def create_image(self, name: str, tag: str) -> Image:
        """
        Create a minimal OCI image in the registry.

        Args:
            name: The image name.
            tag: The image tag.

        Returns:
            Image: The created image object.
        """
        image_pullspec = f"{self.registry}/{name}:{tag}"

        cmd = [
            "oras",
            "push",
            image_pullspec,
            "--config",
            # These are just dummy values that registry requires, but they
            # don't contain any real data.
            "tests/data/integration/config.json:application/vnd.oci.image.config.v1+json",
            "tests/data/integration/layer.tar.gz:application/vnd.oci.image.layer.v1.tar+gzip",
        ]
        code, _, stderr = await run_async_subprocess(cmd)
        if code != 0:
            raise RuntimeError(
                f"Failed to create image {image_pullspec} in registry."
                f"Error: {stderr.decode()}"
            )

        manifest = await self.fetch_manifest(name, tag)
        return Image(
            repository=f"{self.registry}/{name}",
            digest=self._get_digest_from_manifest(manifest),
            tag=tag,
            manifest=manifest,
        )

    async def create_image_index(
        self, name: str, tag: str, images: list[Image]
    ) -> Image:
        """
        Create an OCI image index in the registry.

        Args:
            name: The index name.
            tag: The index tag.
            images: List of images to include in the index.

        Returns:
            Image: The created image index object.
        """
        index_body = {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "manifests": [
                {
                    "mediaType": "application/vnd.oci.image.manifest.v1+json",
                    "digest": image.digest,
                    "size": len(image.manifest or ""),
                    "platform": {
                        "architecture": image.arch or "amd64",
                        "os": "linux",
                    },
                }
                for image in images
            ],
        }
        with tempfile.NamedTemporaryFile(
            mode="w", delete=False, suffix=".json"
        ) as index_file_tmp:
            with open(index_file_tmp.name, "w", encoding="utf-8") as index_file:
                json.dump(index_body, index_file)
            index_manifest_path = index_file_tmp.name

            image_pullspec = f"{self.registry}/{name}:{tag}"
            cmd = [
                "oras",
                "manifest",
                "push",
                "--media-type",
                "application/vnd.oci.image.index.v1+json",
                image_pullspec,
                index_manifest_path,
            ]

            code, _, stderr = await run_async_subprocess(cmd)
            if code != 0:
                raise RuntimeError(
                    f"Failed to push image index {image_pullspec} to registry."
                    f"Error: {stderr.decode()}"
                )
            manifest = await self.fetch_manifest(name, tag)
            return Image(
                repository=f"{self.registry}/{name}",
                digest=self._get_digest_from_manifest(manifest),
                tag=tag,
                manifest=manifest,
            )

    async def fetch_manifest(self, name: str, tag: str) -> str:
        """
        Fetch the manifest of an image from the registry.

        Args:
            name (str): A repository name.
            tag (str): An image tag.

        Returns:
            str: Image manigest.
        """
        image_pullspec = f"{self.registry}/{name}:{tag}"
        cmd = ["oras", "manifest", "fetch", image_pullspec]
        code, stdout, stderr = await run_async_subprocess(cmd)
        if code != 0:
            raise RuntimeError(
                f"Failed to fetch manifest {image_pullspec} to registry. "
                f"Error: {stderr.decode()}"
            )

        return stdout.decode().strip()

    async def attach_sbom(
        self, image: Image, format: Literal["spdx", "cyclonedx"], sbom: bytes
    ) -> None:
        """
        Attach an SBOM to an image as a referrer.

        Args:
            image: The image to attach the SBOM to.
            format: The SBOM format (spdx or cyclonedx).
            sbom: The SBOM content as bytes.
        """
        derived_tag = image.digest.replace(":", "-") + ".sbom"

        sbom_length = len(sbom)
        sbom_blob_digest = await self._push_blob(image.name, sbom)

        if format == "spdx":
            media_type = "text/spdx+json"
        else:
            media_type = "text/cyclonedx+json"

        layers = [
            Layer(
                media_type=media_type,
                digest=sbom_blob_digest,
                size=sbom_length,
            )
        ]
        # the config is not used in any way but must be specified to conform
        # with spec
        config_digest = await self._push_blob(image.name, b"")
        await self._push_manifest(image.name, derived_tag, config_digest, layers)

    async def _push_blob(self, name: str, blob: bytes) -> str:
        """
        Push a blob to the registry.
        https://github.com/opencontainers/distribution-spec/blob/main/spec.md#pushing-blobs

        Args:
            name: The repository name.
            blob: The blob content.

        Returns:
            str: The digest of the pushed blob.
        """
        digest = hashlib.sha256(blob).hexdigest()

        length = str(len(blob))
        headers = httpx.Headers(
            {"Content-Length": length, "Content-Type": "application/octet-stream"}
        )

        url = f"{self.registry_url}/v2/{name}/blobs/uploads/"

        async with httpx.AsyncClient() as client:
            resp = await client.post(url)
            resp.raise_for_status()
            upload_url = resp.headers["Location"]

            resp = await client.put(
                f"{self.registry_url}{upload_url}?digest=sha256:{digest}",
                content=blob,
                headers=headers,
            )
            resp.raise_for_status()

        return f"sha256:{digest}"

    async def _push_manifest(
        self, name: str, tag: str, config_digest: str, layers: list[Layer] | None = None
    ) -> str:
        """
        Push a manifest to the registry.
        https://github.com/opencontainers/distribution-spec/blob/main/spec.md#pushing-blobs

        Args:
            name: The repository name.
            tag: The tag for the manifest.
            config_digest: The digest of the config blob.
            layers: List of layers to include in the manifest.

        Returns:
            str: The digest of the pushed manifest.
        """
        if layers is None:
            layers = []

        url = f"{self.registry_url}/v2/{name}/manifests/{tag}"

        headers = httpx.Headers(
            {"Content-Type": "application/vnd.oci.image.manifest.v1+json"}
        )

        content = json.dumps(
            {
                "schemaVersion": 2,
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "config": {
                    "mediaType": "application/vnd.oci.image.config.v1+json",
                    "size": 0,
                    "digest": config_digest,
                },
                "layers": [layer.asdict() for layer in layers],
            }
        )

        async with httpx.AsyncClient() as client:
            resp = await client.put(url, content=content, headers=headers)
            resp.raise_for_status()
            digest = resp.headers["location"].split("/")[-1]
            return digest
