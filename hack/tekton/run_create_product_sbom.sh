#!/usr/bin/env bash
# Utility testing script designed to mimick the process the
# create-product-sbom-ta Tekton task uses.
#
# Requirements:
#   - TPA is running locally on port 8080.
#   - MinIO is running locally on port 9900.
#   - A "snapshot.json" file exists in the data_dir. The snapshot spec should
#       then point to an image with SBOMs to be augmented.
#   - A "data.json" merged release data file exists in the data_dir.
set -eux

data_dir="."
snapshot_spec="snapshot.json"
release_data="data.json"
atlas_api_url="http://localhost:8080"
retry_s3_bucket="sboms"
release_id=$(python3 -c "from uuid import uuid4; print(uuid4())")
echo "release_id=$release_id"

export MOBSTER_TPA_SSO_ACCOUNT="dummy"
export MOBSTER_TPA_SSO_TOKEN="dummy"
export MOBSTER_TPA_SSO_TOKEN_URL="dummy"
export MOBSTER_TPA_AUTH_DISABLE="true"

export AWS_ACCESS_KEY_ID="minioAccessKey"
export AWS_SECRET_ACCESS_KEY="minioSecretKey"
export AWS_ENDPOINT_URL="http://localhost:9900"

process_product_sbom \
    --data-dir "$data_dir" \
    --snapshot-spec "$snapshot_spec" \
    --release-data "$release_data" \
    --atlas-api-url "$atlas_api_url" \
    --retry-s3-bucket "$retry_s3_bucket" \
    --release-id "$release_id"
