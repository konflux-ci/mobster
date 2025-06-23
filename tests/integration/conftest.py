import hashlib
import json
from dataclasses import dataclass
from typing import Any, Literal

import httpx


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

    async def prepare_sbom(
        self, name: str, tag: str, format: Literal["spdx", "cyclonedx"], sbom: bytes
    ) -> str:
        config_digest = await self._push_blob(name, b"")
        # pushing manifest of "main" image, the image SBOMs will attach to
        main_digest = await self._push_manifest(name, tag, config_digest)

        derived_tag = main_digest.replace(":", "-") + ".sbom"

        sbom_length = len(sbom)
        sbom_blob_digest = await self._push_blob(name, sbom)

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

        await self._push_manifest(name, derived_tag, config_digest, layers)

        return f"{self.registry}/{name}@{main_digest}"

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
