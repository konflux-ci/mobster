# Generate CBOM for OCI Images

This command allows adding identifiable metadata to CycloneDX CBOMs generated
by crypto scanner tools. It is compatible with the CycloneDX output of
[crypto-finder][1].

## Usage

```bash
mobster generate \
    --output /tmp/output.json \
    oci-cbom \
    --image-pullspec quay.io/example/base:v1 \
    --image-digest sha256:087dc7896b97911a582702b45ff1d41ffa3e142d0b000b0fbb11058188293cfc \
    --cbom-path /tmp/input.json
```

**List of arguments:**

- `--image-pullspec IMAGE_PULLSPEC`
  - Image pullspec for the OCI image in the format <registry>/<repository>:<tag>
- `--image-digest IMAGE_DIGEST`
  - Image digest for the OCI image in the format sha256:<digest>
- `--cbom-path`
  - Input file, must contain CycloneDX CBOM
- `--arch`
  - Optional argument, the architecture of the CPU, for which the image was built.
  - Will be added to identifying information if provided.

[1]: https://github.com/rh-pvsec/crypto-finder-image
