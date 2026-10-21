# Attaching signed SBOM attestations with Mobster

The `mobster attest` command attaches an SBOM to an image as a signed, keyless
attestation. It is a thin wrapper around `cosign attest` that is intended to
replace a direct `cosign attest` invocation (for example in the Konflux buildah
task).

On top of `cosign attest`, the command:

- detects the attestation type (`cyclonedx` or `spdxjson`) from the input SBOM
  file, so the type does not have to be specified manually,
- retries the upload on transient failures,
- passes pre-selected registry authentication credentials to cosign, scoped to
  the target image reference.

## Prerequisites

Keyless signing relies on `cosign` having been initialized with a TUF context
(`cosign initialize`) on the host, and on registry credentials being available
in one of the standard locations (`REGISTRY_AUTH_FILE`,
`$XDG_RUNTIME_DIR/containers/auth.json`, or `~/.docker/config.json`).

## Usage

```shell
mobster attest \
    --image-ref registry.example.com/org/repo@sha256:<digest> \
    --sbom-path ./sbom.json \
    --rekor-url https://rekor.sigstore.dev \
    --fulcio-url https://fulcio.sigstore.dev \
    --oidc-issuer-url https://oidc.example.com \
    --oidc-token-path ./oidc-token
```

| Argument | Description |
| --- | --- |
| `--image-ref` | Digested reference of the image to attest (`<registry>/<repository>@sha256:<digest>`). |
| `--sbom-path` | Path to the SBOM file to attach as an attestation. |
| `--rekor-url` | URL of the Rekor transparency log service. |
| `--fulcio-url` | URL of the Fulcio certificate authority service. |
| `--oidc-issuer-url` | URL of the OIDC issuer that issued the identity token. |
| `--oidc-token-path` | Path to the file containing the OIDC identity token. |

> The service URLs are required for now. They are expected to become optional in
> the future once cosign v3 is adopted.
