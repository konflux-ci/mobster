"""Package with static definitions related to oci-image."""

from enum import Enum


class ContentType(Enum):
    """Enum for content types."""

    COMPONENT = "COMPONENT CONTENT"
    COMPONENT_ONLY = "COMPONENT-ONLY CONTENT"
    PARENT = "PARENT CONTENT"
    BUILDER = "BUILDER CONTENT"
    EXTERNAL = "EXTERNAL CONTENT"


IS_BASE_IMAGE_ANNOTATION = {
    "name": "konflux:container:is_base_image",
    "value": "true",
}

BUILDER_IMAGE_PROPERTY = {
    "name": "konflux:container:is_builder_image:additional_builder_image",
    "value": "script-runner-image",
}
