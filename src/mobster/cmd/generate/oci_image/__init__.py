"""A module for generating SBOM documents for OCI images."""

__all__ = ["GenerateOciImageCommand"]

import json
import logging
from argparse import ArgumentError
from pathlib import Path
from typing import Any

from cyclonedx.exception import CycloneDxException
from spdx_tools.spdx.jsonschema.document_converter import DocumentConverter
from spdx_tools.spdx.model.document import Document
from spdx_tools.spdx.validation.document_validator import validate_full_spdx_document
from spdx_tools.spdx.writer.write_utils import convert

import mobster.utils
from mobster.cmd.generate.base import GenerateCommandWithOutputTypeSelector
from mobster.cmd.generate.oci_image.add_image import extend_sbom_with_image_reference
from mobster.cmd.generate.oci_image.base_images_dockerfile import (
    extend_sbom_with_base_images_from_dockerfile,
    get_base_images_refs_from_dockerfile,
    get_digest_for_image_ref,
    get_image_objects_from_file,
)
from mobster.cmd.generate.oci_image.contextual_parent_content import (
    adjust_parent_image_relationship_in_legacy_sbom,
    adjust_parent_image_spdx_element_ids,
    calculate_component_only_content,
    create_contextual_sbom,
    download_parent_image_sbom,
    get_used_parent_image_from_legacy_sbom,
    remove_parent_image_builder_records,
)
from mobster.cmd.generate.oci_image.cyclonedx_wrapper import CycloneDX1BomWrapper
from mobster.cmd.generate.oci_image.spdx_utils import (
    normalize_and_load_sbom,
)
from mobster.image import Image
from mobster.sbom.merge import merge_sboms
from mobster.utils import identify_arch, load_sbom_from_json

logging.captureWarnings(True)  # CDX validation uses `warn()`
LOGGER = logging.getLogger(__name__)


class GenerateOciImageCommand(GenerateCommandWithOutputTypeSelector):
    """
    Command to generate an SBOM document for an OCI image.
    """

    # Change this once Contextual SBOM is ready.
    # We should then look at the cli argument passed instead
    _contextualize: bool = False

    @staticmethod
    async def dump_sbom_to_dict(
        sbom: Document | CycloneDX1BomWrapper,
    ) -> dict[str, Any]:
        """
        Dumps an SBOM object representation to a dictionary
        Args:
            sbom (spdx_tools.spdx.model.document.Document | CycloneDX1BomWrapper):
                the SBOM object to dump
        Returns:
            dict[str, Any]: The SBOM dumped to a dictionary
        """
        if isinstance(sbom, Document):
            return convert(sbom, DocumentConverter())  # type: ignore[no-untyped-call]
        return sbom.to_dict()

    async def _soft_validate_content(self) -> None:
        """
        Validate the SBOM created and log the result as a warning.
        Does not fail the workflow.
        Returns:
            None: Nothing is returned, information is logged.
        """
        if isinstance(self._content, Document):
            messages = validate_full_spdx_document(self._content)
            if messages:
                for message in messages:
                    LOGGER.warning(message)
        if isinstance(self._content, CycloneDX1BomWrapper):
            try:
                self._content.sbom.validate()
            except CycloneDxException as e:
                LOGGER.warning("\n".join(e.args))

    async def _handle_bom_inputs(
        self,
    ) -> dict[str, Any]:
        """
        Handles the input SBOM files, merging them if necessary.
        Returns:
            dict[str, Any]: Merged/loaded SBOM dictionary.
        Raises:
            ArgumentError: If neither Syft nor Hermeto SBOMs are provided.
        """
        if self.cli_args.from_hermeto is None and self.cli_args.from_syft is None:
            raise ArgumentError(
                None,
                "At least one of --from-syft or --from-hermeto must be provided",
            )

        if self.cli_args.from_syft is not None:
            # Merging Syft & Hermeto SBOMs
            if len(self.cli_args.from_syft) > 1 or self.cli_args.from_hermeto:
                return await merge_sboms(
                    self.cli_args.from_syft, self.cli_args.from_hermeto
                )
            return await load_sbom_from_json(self.cli_args.from_syft[0])

        return await load_sbom_from_json(self.cli_args.from_hermeto)

    async def _execute_contextual_workflow(
        self,
        component_sbom_doc: Document,
        parent_image_ref: Image,
        arch: str,
    ) -> Document | None:
        """
        Run all steps from the contextual workflow.
        Args:
            component_sbom_doc:
                The component SBOM created for this image.
            parent_image_ref: Reference to the parent image.
            arch: CPU architecture of this image.

        Returns:
            spdx_tools.spdx.model.document.Document | None:
                The contextual SBOM if the workflow was successful.
                None otherwise.
        """

        parent_image_sbom = await download_parent_image_sbom(parent_image_ref, arch)
        if not parent_image_sbom:
            return None
        parent_sbom_doc = await normalize_and_load_sbom(
            parent_image_sbom, append_mobster=False
        )

        component_only_sbom_doc = await calculate_component_only_content(
            parent_sbom_doc, component_sbom_doc
        )
        grandparent_spdx_id = await get_used_parent_image_from_legacy_sbom(
            parent_sbom_doc
        )
        parent_sbom_doc = await adjust_parent_image_relationship_in_legacy_sbom(
            parent_sbom_doc, grandparent_spdx_id
        )
        parent_sbom_doc = await adjust_parent_image_spdx_element_ids(
            parent_sbom_doc, component_sbom_doc, grandparent_spdx_id
        )
        parent_sbom_doc = await remove_parent_image_builder_records(parent_sbom_doc)

        return await create_contextual_sbom(parent_sbom_doc, component_only_sbom_doc)

    async def _assess_and_dispatch_contextual_workflow(
        self,
        component_sbom_doc: Document | CycloneDX1BomWrapper,
        base_images_refs: list[str | None],
        base_images: dict[str, Image],
        image_arch: str,
    ) -> Document | None:
        """
        Check if the contextual Workflow should be attempted
        and try to run it. Catches all errors.
        Args:
            component_sbom_doc: The component SBOM created for this image.
            base_images_refs: List of references from the parsed Dockerfile.
            image_arch: CPU architecture of this image.

        Returns:
            spdx_tools.spdx.model.document.Document | None:
                The contextual SBOM if the workflow was successful.
                None otherwise.
        """
        if (
            self._contextualize
            and isinstance(component_sbom_doc, Document)
            and base_images_refs
            and (parent_image_ref := base_images_refs[-1])
        ):
            try:
                parent_image_obj = base_images[parent_image_ref]
                return await self._execute_contextual_workflow(
                    component_sbom_doc, parent_image_obj, image_arch
                )
            except Exception:  # pylint: disable=broad-exception-caught
                LOGGER.exception("Could not create contextual SBOM!")
        return None

    async def execute(self) -> Any:
        """
        Generate an SBOM document for OCI image.
        """
        LOGGER.debug("Generating SBOM document for OCI image")

        merged_sbom_dict = await self._handle_bom_inputs()
        sbom: Document | CycloneDX1BomWrapper
        image_arch = identify_arch()

        # Parsing into objects
        if merged_sbom_dict.get("bomFormat") == "CycloneDX":
            sbom = CycloneDX1BomWrapper.from_dict(merged_sbom_dict)
        elif "spdxVersion" in merged_sbom_dict:
            sbom = await normalize_and_load_sbom(merged_sbom_dict)
        else:
            raise ValueError("Unknown SBOM Format!")

        # Extending with image reference
        if self.cli_args.image_pullspec:
            if not self.cli_args.image_digest:
                LOGGER.info(
                    "Provided pullspec but not digest."
                    " Resolving the digest using oras..."
                )
                self.cli_args.image_digest = await get_digest_for_image_ref(
                    self.cli_args.image_pullspec
                )
            if not self.cli_args.image_digest:
                raise ValueError(
                    "No value for image digest was provided "
                    "and the image is not visible to oras!"
                )
            image_arch = mobster.utils.identify_arch()
            image = Image.from_image_index_url_and_digest(
                self.cli_args.image_pullspec,
                self.cli_args.image_digest,
                arch=image_arch,
            )
            await extend_sbom_with_image_reference(sbom, image, False)
        elif self.cli_args.image_digest:
            LOGGER.warning(
                "Provided image digest but no pullspec. The digest value is ignored."
            )

        base_images_refs = []
        base_images_map: dict[str, Image] = {}

        # Extending with base images references from a dockerfile
        if self.cli_args.parsed_dockerfile_path:
            with open(
                self.cli_args.parsed_dockerfile_path, encoding="utf-8"
            ) as parsed_dockerfile_io:
                parsed_dockerfile = json.load(parsed_dockerfile_io)

            base_images_refs = await get_base_images_refs_from_dockerfile(
                parsed_dockerfile, self.cli_args.dockerfile_target
            )

            if self.cli_args.base_image_digest_file:
                LOGGER.debug(
                    "Supplied pre-parsed image digest file, will operate offline."
                )
                base_images_map = await get_image_objects_from_file(
                    self.cli_args.base_image_digest_file
                )
            await extend_sbom_with_base_images_from_dockerfile(
                sbom, base_images_refs, base_images_map
            )

        # Extending with additional base images
        for image_ref in self.cli_args.additional_base_image:
            image_object = Image.from_oci_artifact_reference(image_ref)
            await extend_sbom_with_image_reference(
                sbom, image_object, is_builder_image=True
            )

        contextual_sbom = await self._assess_and_dispatch_contextual_workflow(
            sbom, base_images_refs, base_images_map, image_arch
        )
        sbom = contextual_sbom or sbom
        self._content = sbom
        await self._soft_validate_content()
        return self._content

    async def save(self) -> None:
        """
        Saves the output of the command either to STDOUT
        or to a specified file.
        Returns:
            bool: Was the save operation successful?
        """
        output_dict = await self.dump_sbom_to_dict(self._content)
        output_file: Path = self.cli_args.output
        if output_file is None:
            print(json.dumps(output_dict))
        else:
            with open(output_file, "w", encoding="utf-8") as write_stram:
                json.dump(output_dict, write_stram)
