import hashlib
import json
from dataclasses import dataclass
from typing import Any, Literal

import httpx

from mobster.image import Image


@dataclass
class Layer:
    media_type: str
    digest: str
    size: int

    def asdict(self) -> Any:
        return {
            "mediaType": self.media_type,
            "digest": self.digest,
            "size": self.size,
        }


class ReferrersTagOCIClient:
    def __init__(self, registry_url: str) -> None:
        self.registry_url = registry_url

    @property
    def registry(self) -> str:
        for prefix in ["http://", "https://"]:
            if self.registry_url.startswith(prefix):
                return self.registry_url.removeprefix(prefix)
        return self.registry_url

    async def create_image(self, name: str, tag: str) -> Image:
        config_digest = await self._push_blob(name, b"")
        digest = await self._push_manifest(name, tag, config_digest)
        repo = f"{self.registry}/{name}"
        return Image(repository=repo, digest=digest, tag=tag)

    async def attach_sbom(
        self, image: Image, format: Literal["spdx", "cyclonedx"], sbom: bytes
    ) -> str:
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

        config_digest = await self._push_blob(image.name, b"")
        await self._push_manifest(image.name, derived_tag, config_digest, layers)

        return f"{self.registry}/{image.name}@{image.digest}"

    async def _push_blob(self, name: str, blob: bytes) -> str:
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
