# Uploading SBOMs with Mobster

The Mobster tool is capable of uploading SBOMs to multiple locations.

## Red Hat Trusted Profile Analyzer (TPA)

To upload an SBOM to TPA, use the `mobster upload tpa` command. In order to authenticate to TPA,
you need to set the following environment variables with OIDC, as in the example below

```
MOBSTER_TPA_SSO_TOKEN_URL="https://example.com/auth/realms/ExampleRealm/protocol/openid-connect/token"
MOBSTER_TPA_SSO_ACCOUNT=example-account
MOBSTER_TPA_SSO_TOKEN=example-account-token
```

After that you can either upload a single SBOM:
```shell
mobster upload tpa \
    --tpa-base-url https://your-tpa-instance.com \
    --file /path/to/your/sbom.json
```

Or multiple SBOM files from a directory with an option to set a number of parallel workers:
```shell
mobster upload tpa \
    --tpa-base-url https://your-tpa-instance.com \
    --from-dir /path/to/sbom_directory \
    --workers 4
```
