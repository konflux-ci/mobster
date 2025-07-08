"""A module for generating SBOM documents for OCI images."""

__all__ = ["GenerateOciImageCommand"]

import json
import logging
from pathlib import Path
from typing import Any

from cyclonedx.exception import CycloneDxException
from spdx_tools.spdx.jsonschema.document_converter import DocumentConverter
from spdx_tools.spdx.model.document import Document
from spdx_tools.spdx.parser.jsonlikedict.json_like_dict_parser import JsonLikeDictParser
from spdx_tools.spdx.validation.document_validator import validate_full_spdx_document
from spdx_tools.spdx.writer.write_utils import convert

from mobster.cmd.generate.base import GenerateCommandWithOutputTypeSelector
from mobster.cmd.generate.oci_image.add_image import extend_sbom_with_image_reference
from mobster.cmd.generate.oci_image.base_images_dockerfile import (
    extend_sbom_with_base_images_from_dockerfile,
    get_digest_for_image_ref,
    get_image_objects_from_file,
)
from mobster.cmd.generate.oci_image.cyclonedx_wrapper import CycloneDX1BomWrapper
from mobster.cmd.generate.oci_image.spdx_utils import normalize_sbom
from mobster.image import Image
from mobster.sbom.merge import merge_sboms

logging.captureWarnings(True)  # CDX validation uses `warn()`
LOGGER = logging.getLogger(__name__)


class GenerateOciImageCommand(GenerateCommandWithOutputTypeSelector):
    """
    Command to generate an SBOM document for an OCI image.
    """

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

    async def execute(self) -> Any:
        """
        Generate an SBOM document for OCI image.
        """
        # pylint: disable=too-many-locals
        LOGGER.debug("Generating SBOM document for OCI image")
        # Argument parsing
        syft_boms: list[Path] = self.cli_args.from_syft
        hermeto_bom: Path | None = self.cli_args.from_hermeto
        image_pullspec: str | None = self.cli_args.image_pullspec
        image_digest: str | None = self.cli_args.image_digest
        parsed_dockerfile_path: Path | None = self.cli_args.parsed_dockerfile_path
        dockerfile_target_stage: str | None = self.cli_args.dockerfile_target
        additional_base_images: list[str] = self.cli_args.additional_base_image
        base_image_digest_file: Path | None = self.cli_args.base_image_digest_file
        # contextualize: bool = self.cli_args.contextualize
        # TODO add contextual SBOM utilities    # pylint: disable=fixme

        # Merging Syft & Hermeto SBOMs
        if len(syft_boms) > 1 or hermeto_bom:
            merged_sbom_dict = merge_sboms(syft_boms, hermeto_bom)
        else:
            # Just one image provided, nothing to merge
            with open(syft_boms[0], encoding="utf8") as sbom_file:
                merged_sbom_dict = json.load(sbom_file)
        sbom: Document | CycloneDX1BomWrapper

        # Parsing into objects
        if merged_sbom_dict.get("bomFormat") == "CycloneDX":
            sbom = CycloneDX1BomWrapper.from_dict(merged_sbom_dict)
        elif "spdxVersion" in merged_sbom_dict:
            await normalize_sbom(merged_sbom_dict)
            sbom = JsonLikeDictParser().parse(merged_sbom_dict)  # type: ignore[no-untyped-call]
        else:
            raise ValueError("Unknown SBOM Format!")

        # Extending with image reference
        if image_pullspec:
            if not image_digest:
                LOGGER.info(
                    "Provided pullspec but not digest."
                    " Resolving the digest using oras..."
                )
                image_digest = await get_digest_for_image_ref(image_pullspec)
            if not image_digest:
                raise ValueError(
                    "No value for image digest was provided "
                    "and the image is not visible to oras!"
                )
            image = Image.from_image_index_url_and_digest(image_pullspec, image_digest)
            await extend_sbom_with_image_reference(sbom, image, False)
        elif image_digest:
            LOGGER.warning(
                "Provided image digest but no pullspec. The digest value is ignored."
            )

        # Extending with base images references from a dockerfile
        if parsed_dockerfile_path:
            with open(parsed_dockerfile_path, encoding="utf-8") as parsed_dockerfile_io:
                parsed_dockerfile = json.load(parsed_dockerfile_io)

            base_images_map = None
            if base_image_digest_file:
                LOGGER.debug(
                    "Supplied pre-parsed image digest file, will operate offline."
                )
                base_images_map = await get_image_objects_from_file(
                    base_image_digest_file
                )
            await extend_sbom_with_base_images_from_dockerfile(
                sbom, parsed_dockerfile, base_images_map, dockerfile_target_stage
            )

        # Extending with additional base images
        for image_ref in additional_base_images:
            image_object = Image.from_oci_artifact_reference(image_ref)
            await extend_sbom_with_image_reference(
                sbom, image_object, is_builder_image=True
            )

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
