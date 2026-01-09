# Deleting SBOMs with Mobster

The Mobster tool is capable of deleting SBOMs from multiple locations.

## Red Hat Trusted Profile Analyzer (TPA)

To delete an SBOM from TPA, use the `mobster delete tpa` command. In order to authenticate to TPA,
you need to set the following environment variables with OIDC, as in the example below

```
MOBSTER_TPA_SSO_TOKEN_URL="https://example.com/auth/realms/ExampleRealm/protocol/openid-connect/token"
MOBSTER_TPA_SSO_ACCOUNT=example-account
MOBSTER_TPA_SSO_TOKEN=example-account-token
```

After that you can either delete a single SBOM:
```shell
mobster delete tpa \
    --tpa-base-url https://your-tpa-instance.com \
    --uuid {SBOM UIID}
```

Or multiple SBOMs using a generic query:
```shell
mobster delete tpa \
    --tpa-base-url https://your-tpa-instance.com \
    --query "authors~mobster"
```

Or multiple SBOMs based on a ingestion time range:
```shell
mobster delete tpa \
    --tpa-base-url https://your-tpa-instance.com \
    --query "ingested<3 months ago"
