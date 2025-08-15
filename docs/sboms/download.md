# Downloading SBOMs with Mobster

The Mobster tool is capable of downloading SBOMs to multiple locations.

## Red Hat Trusted Profile Analyzer (TPA)

To download an SBOM from TPA, use the `mobster download tpa` command. In order to authenticate to TPA,
you need to set the following environment variables with OIDC, as in the example below

```
MOBSTER_TPA_SSO_TOKEN_URL="https://example.com/auth/realms/ExampleRealm/protocol/openid-connect/token"
MOBSTER_TPA_SSO_ACCOUNT=example-account
MOBSTER_TPA_SSO_TOKEN=example-account-token
```

After that you can either download a single SBOM:
```shell
mobster download tpa \
    --tpa-base-url https://your-tpa-instance.com \
    --uuid {SBOM UIID} \
    --output /path/to/your/directory/
```

Or multiple SBOM files using a generic query:
```shell
mobster download tpa \
    --tpa-base-url https://your-tpa-instance.com \
    --query "authors~mobster" \
    --output /path/to/your/directory/
```
