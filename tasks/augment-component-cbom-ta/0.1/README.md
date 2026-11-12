# augment-component-cbom-ta

Update component-level CBOM with release-time information, upload
them to TPA or fall back to pushing them to S3.

Callers must configure either attestationPubKey or complete keyless
verification settings. Leaving both unset causes failure.

## Parameters

| Parameter                 | Type   | Default                           | Description                                                                                                                                                               |
| ------------------------- | ------ | --------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `ociStorage`              | string | `"empty"`                         | The OCI repository where the Trusted Artifacts are stored.                                                                                                                |
| `ociArtifactExpiresAfter` | string | `"1d"`                            | Expiration date for the trusted artifacts created in the OCI repository. An empty string means the artifacts do not expire.                                               |
| `trustedArtifactsDebug`   | string | `""`                              | Flag to enable debug logging in trusted artifacts. Set to a non-empty string to enable.                                                                                   |
| `orasOptions`             | string | `""`                              | oras options to pass to Trusted Artifacts calls                                                                                                                           |
| `sourceDataArtifact`      | string | `""`                              | Location of trusted artifacts to be used to populate data directory                                                                                                       |
| `dataDir`                 | string | `"/var/workdir/release"`          | The location where data will be stored                                                                                                                                    |
| `taskGitUrl`              | string | Required                          | The url to the git repo where the trusted artifact stepactions to be used are stored                                                                                      |
| `taskGitRevision`         | string | Required                          | The revision in the taskGitUrl repo to be used for trusted artifact stepactions                                                                                           |
| `snapshotSpec`            | string | Required                          | Path to the mapped snapshot spec.                                                                                                                                         |
| `atlasSecretName`         | string | Required                          | The name of the K8s secret containing the 'sso_account' and 'sso_token' keys used for Atlas OIDC authentication.                                                          |
| `retryAWSSecretName`      | string | Required                          | The name of the K8s secret containing the 'atlas-aws-access-key-id' and 'atlas-aws-secret-access-key' keys used for AWS S3 access.                                        |
| `retryS3Bucket`           | string | `""`                              | The name of the S3 bucket used to store data for the retry mechanism.                                                                                                     |
| `atlasApiUrl`             | string | Required                          | URL of the Atlas API host.                                                                                                                                                |
| `ssoTokenUrl`             | string | Required                          | URL of the Atlas SSO token issuer.                                                                                                                                        |
| `caPath`                  | string | `""`                              | Path to the certificate authority bundle to set up TPA requests.                                                                                                          |
| `augmentConcurrency`      | string | `"8"`                             | Maximum number of SBOMs that will be augmented concurrently. Higher limit will speed up execution for larger snapshots, but will have higher memory requirements.         |
| `uploadConcurrency`       | string | `"8"`                             | Maximum number of SBOMs that will be uploaded to Atlas concurrently. Higher limit will speed up execution for larger snapshots, but will have higher memory requirements. |
| `resultsDirPath`          | string | Required                          | Path to directory in the dataDir to store JSON task results to.                                                                                                           |
| `attestationPubKey`       | string | `""`                              | K8s reference to a secret containing a key for verifying provenance attestations                                                                                          |
| `releaseData`             | string | Required                          | Path to the merged data file from collect-data in the dataDir.                                                                                                            |
| `defaultOIDCIssuer`       | string | `""`                              | Expected OIDC issuer URL for verifying build-time provenance attestations.                                                                                                |
| `rekorExternalUrl`        | string | `""`                              | The external URL of the Rekor transparency log.                                                                                                                           |
| `rekorInternalUrl`        | string | `""`                              | The internal URL of the Rekor transparency log.                                                                                                                           |
| `fulcioExternalUrl`       | string | `""`                              | The external URL of the Fulcio certificate authority.                                                                                                                     |
| `fulcioInternalUrl`       | string | `""`                              | The internal URL of the Fulcio certificate authority.                                                                                                                     |
| `tufExternalUrl`          | string | `""`                              | The external URL of the TUF repository.                                                                                                                                   |
| `tufInternalUrl`          | string | `""`                              | The internal URL of the TUF repository.                                                                                                                                   |
| `buildIdentityRegexp`     | string | `""`                              | A regular expression to verify keyless-attested build-time artifacts, if applicable.                                                                                      |
| `caTrustConfigMapName`    | string | `"trusted-ca"`                    | The name of the ConfigMap to read CA bundle data from                                                                                                                     |
| `caTrustConfigMapKey`     | string | `"ca-bundle.crt"`                 | The name of the key in the ConfigMap that contains the CA bundle data                                                                                                     |
| `caCertPath`              | string | `"/mnt/trusted-ca/ca-bundle.crt"` | Path to CA certificate bundle for TLS verification with self-signed certificates                                                                                          |

## Secrets
The augment-component-cbom-ta task requires both secrets below and all listed keys.

### Atlas Authentication Secret (`atlasSecretName`)

Required keys:
- `sso_account`: SSO account for Atlas authentication
- `sso_token`: SSO token for Atlas authentication

### AWS S3 Access Secret (`retryAWSSecretName`)

Required keys:
- `atlas-aws-access-key-id`: AWS Access Key ID for S3 access
- `atlas-aws-secret-access-key`: AWS Secret Access Key for S3 access

## Steps

1. **use-trusted-artifact** - Use the trusted artifact repository.
2. **process-component-cboms** - Augment and upload the CBOMs to TPA.
3. **create-trusted-artifact** - Publish the resulting trusted artifact.
