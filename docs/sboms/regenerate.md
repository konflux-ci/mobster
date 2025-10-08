# SBOM Regeneration

Mobster's SBOM regeneration script allows SBOM regeneration for cases where 
product or component SBOMs were generated incorrectly or with errors.

```sh
$ regenerate_component_sboms \
    --tpa-base-url https://atlas.url \
    --mobster-versions 0.1.1,0.1.2 \
    --concurrency 10 \
    --s3-bucket-url https://bucket.url \
    --dry-run
```

Note: inclusion of the `--dry-run` argument means the regenerated data 
will not be pushed to TPA or to the S3 bucket.
This argument should always be used for testing/validation.

The required `--tpa-base-url <url>` argument indicates the base url for 
the relevant TPA instance with SBOMs in need of regeneration.

The required `--mobster-versions <comma,separated,list>`argument indicates which 
mobster version(s) originally generated the problem SBOMs.

The optional `--concurrency <int>` argument sets the number of concurrent threads 
which will be used during regeneration processing (default: 8).

The required `--s3-bucket-url` argument indicates the url for the relevant S3 
bucket which stores SBOM snapshot and release data.

The optional `--output-dir <path>` argument may be included in cases where a 
predetermined static path is preferred.  Otherwise, the script creates and 
uses a temporary directory. 


