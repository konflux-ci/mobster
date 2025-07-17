#!/usr/bin/env bash
# Utility testing script designed to mimick the process the
# create-product-sbom-ta Tekton task uses. Uses the real stage S3 bucket
# for now.
#
# Requirements:
#   - TPA is running locally on port 8080.
#   - AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY env vars are set with the
#       credentials to the stage bucket
#   - A "snapshot.json" file exists in the data_dir. The snapshot spec should
#       then point to an image with SBOMs to be augmented.
#   - A "data.json" merged release data file exists in the data_dir.
set -eux

data_dir="."
snapshot_spec="snapshot.json"
release_data="data.json"
atlas_api_url="http://localhost:8080"
retry_s3_bucket="mpp-e1-preprod-sbom-29093454-2ea7-4fd0-b4cf-dc69a7529ee0"

export MOBSTER_TPA_SSO_ACCOUNT="dummy"
export MOBSTER_TPA_SSO_TOKEN="dummy"
export MOBSTER_TPA_SSO_TOKEN_URL="dummy"
export MOBSTER_TPA_AUTH_DISABLE="true"

process_product_sbom \
    --data-dir "$data_dir" \
    --snapshot-spec "$snapshot_spec" \
    --release-data "$release_data" \
    --atlas-api-url "$atlas_api_url" \
    --retry-s3-bucket "$retry_s3_bucket"
