# augment-component-sboms-ta

Update component-level SBOMs with release-time information, optionally upload them to Atlas and S3.

## Parameters

| Parameter                 | Type   | Default                     | Description                                                                                                                         |
|---------------------------|--------|-----------------------------|-------------------------------------------------------------------------------------------------------------------------------------|
| `ociStorage`              | string | `"empty"`                   | The OCI repository where the Trusted Artifacts are stored.                                                                          |
| `ociArtifactExpiresAfter` | string | `"1d"`                      | Expiration date for the trusted artifacts created in the OCI repository. An empty string means the artifacts do not expire.         |
| `trustedArtifactsDebug`   | string | `""`                        | Flag to enable debug logging in trusted artifacts. Set to a non-empty string to enable.                                             |
| `orasOptions`             | string | `""`                        | oras options to pass to Trusted Artifacts calls                                                                                     |
| `sourceDataArtifact`      | string | `""`                        | Location of trusted artifacts to be used to populate data directory                                                                 |
| `dataDir`                 | string | `$(workspaces.data.path)`   | The location where data will be stored                                                                                              |
| `taskGitUrl`              | string |                             | The url to the git repo where the trusted artifact stepactions to be used are stored                                                |
| `taskGitRevision`         | string |                             | The revision in the taskGitUrl repo to be used for trusted artifact stepactions                                                     |
| `snapshotSpec`            | string |                             | Path to the mapped snapshot spec.                                                                                                   |
| `atlasSecretName`         | string |                             | The name of the K8s secret containing the 'sso_account' and 'sso_token' keys used for Atlas OIDC authentication.                    |
| `retryAWSSecretName`      | string |                             | The name of the K8s secret containing the 'atlas-aws-access-key-id' and 'atlas-aws-secret-access-key' keys used for AWS S3 access.  |
| `retryS3bucket`           | string | `""`                        | The name of the S3 bucket used to store data for the retry mechanism.                                                               |
| `atlasApiUrl`             | string | `""`                        | URL of the Atlas API host.                                                                                                          |
| `ssoTokenUrl`             | string | `""`                        | URL of the SSO token issuer.                                                                                                        |

## Secrets
The augment-component-sboms-ta Task optionally depends on two secrets. If they
don't exist, their respective actions are skipped.

### Atlas Authentication Secret (`atlasSecretName`)

Required keys:
- `sso_account`: SSO account for Atlas authentication
- `sso_token`: SSO token for Atlas authentication

### AWS S3 Access Secret (`retryAWSSecretName`)

Required keys:
- `atlas-aws-access-key-id`: AWS Access Key ID for S3 access
- `atlas-aws-secret-access-key`: AWS Secret Access Key for S3 access

## Steps

1. **skip-trusted-artifact-operations** - Skip trusted artifact operations if needed
2. **use-trusted-artifact** - Use trusted artifacts to populate the data directory
3. **augment-sboms** - Update component-level SBOMs with release-time information
4. **upload-sboms-to-atlas** - Upload SBOMs to Atlas (skipped if `MOBSTER_TPA_SSO_ACCOUNT`, `MOBSTER_TPA_SSO_TOKEN`, or `MOBSTER_TPA_SSO_TOKEN_URL` are empty)
5. **upload-sboms-to-s3** - Upload SBOMs to S3 (skipped if `AWS_ACCESS_KEY_ID` or `AWS_SECRET_ACCESS_KEY` are empty)
6. **create-trusted-artifact** - Create trusted artifacts from the processed data
7. **patch-source-data-artifact-result** - Patch the source data artifact result
