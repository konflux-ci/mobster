"""Constants for OCI image SBOM generation."""

IS_BASE_IMAGE_ANNOTATION = {
    "name": "konflux:container:is_base_image",
    "value": "true",
}

BUILDER_IMAGE_PROPERTY = {
    "name": "konflux:container:is_builder_image:additional_builder_image",
    "value": "script-runner-image",
}
