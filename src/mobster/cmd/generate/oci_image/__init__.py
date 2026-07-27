"""A module for generating SBOM documents for OCI images."""

__all__ = ["GenerateOciImageCommand"]

import json
import logging
from argparse import ArgumentError
from copy import deepcopy
from pathlib import Path
from typing import Any

import yaml
from cyclonedx.exception import CycloneDxException
from spdx_tools.spdx.jsonschema.document_converter import DocumentConverter
from spdx_tools.spdx.model.document import Document
from spdx_tools.spdx.validation.document_validator import validate_full_spdx_document
from spdx_tools.spdx.writer.write_utils import convert

import mobster.utils
from mobster import syft
from mobster.cmd.cyclonedx_wrapper import CycloneDX1BomWrapper
from mobster.cmd.generate.base import GenerateCommandWithOutputTypeSelector
from mobster.cmd.generate.oci_image.add_image import extend_sbom_with_image_reference
from mobster.cmd.generate.oci_image.contextual_sbom.builder import (
    BuilderContextualizationError,
    BuilderContextualizer,
    BuilderPkgMetadata,
)
from mobster.cmd.generate.oci_image.contextual_sbom.contextualize import (
    ParentContextualizationError,
    download_parent_image_sbom,
    get_descendant_of_items_from_used_parent,
    get_parent_spdx_id_from_component,
    map_parent_to_component_and_modify_component,
)
from mobster.cmd.generate.oci_image.hermeto_sbom_filter import (
    filter_hermeto_sbom_by_arch,
)
from mobster.cmd.generate.oci_image.metadata import SBOMMetadata
from mobster.cmd.generate.oci_image.sbom_utils import (
    extend_sbom_with_base_images,
    get_base_images_refs_from_dockerfile,
    get_digest_for_image_ref,
    get_image_objects_from_file,
)
from mobster.cmd.generate.oci_image.spdx_utils import (
    ContextualWorkflowError,
    DocumentIndexOCI,
    normalize_and_load_sbom,
)
from mobster.error import SBOMError
from mobster.image import Image
from mobster.log import log_elapsed
from mobster.sbom.merge import merge_sboms
from mobster.utils import load_sbom_from_json

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

    async def _load_and_filter_hermeto_sbom(self) -> dict[str, Any]:
        hermeto_sbom = await load_sbom_from_json(self.cli_args.from_hermeto)

        arch = self.cli_args.arch or mobster.utils.identify_arch()
        return filter_hermeto_sbom_by_arch(hermeto_sbom, arch)

    def _load_metadata(self) -> None:
        """
        Load a metadata file from the --metadata-path argument into
        self._metadata. If the file cannot be loaded (e.g. buildprobe failed),
        self._metadata remains unset.
        """
        try:
            with open(self.cli_args.metadata_path, encoding="utf-8") as metadata_file:
                raw_metadata = yaml.safe_load(metadata_file)
                if raw_metadata is None:
                    raise ValueError("metadata file is empty")
                self._metadata = SBOMMetadata.model_validate(raw_metadata)
        except (
            FileNotFoundError,
            ValueError,
            yaml.YAMLError,
        ) as exc:
            LOGGER.warning(
                "Cannot load metadata file %s (%s), "
                "falling back to deprecated dockerfile-json path",
                self.cli_args.metadata_path,
                exc,
            )

    @staticmethod
    def _load_builder_metadata(
        build_metadata_path: Path,
    ) -> BuilderPkgMetadata | None:
        """
        Load builder content metadata from the --build-metadata-path argument.
        Returns None if the file cannot be loaded.
        """
        try:
            with open(build_metadata_path, encoding="utf-8") as fp:
                return BuilderPkgMetadata.model_validate_json(fp.read())
        except (FileNotFoundError, ValueError) as exc:
            LOGGER.warning(
                "Cannot load builder metadata file %s (%s)", build_metadata_path, exc
            )
            return None

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
        if (
            self.cli_args.from_hermeto is None
            and self.cli_args.from_syft is None
            and self.cli_args.image_pullspec is None
            and self.cli_args.metadata_path is None
        ):
            raise ArgumentError(
                None,
                "At least one of --from-syft, --from-hermeto, --image-pullspec, "
                "or --metadata-path must be provided",
            )

        if self.cli_args.metadata_path is not None:
            self._load_metadata()
            # if we don't have an sbom provided to us, use syft to generate it
            if self.cli_args.from_syft is None and self.cli_args.from_hermeto is None:
                return await syft.scan_image(self._metadata.image.pullspec)
        if self.cli_args.from_syft is not None:
            # Merging Syft & Hermeto SBOMs
            if len(self.cli_args.from_syft) > 1 or self.cli_args.from_hermeto:
                syft_sboms = []

                for path in self.cli_args.from_syft:
                    syft_sboms.append(await load_sbom_from_json(path))

                hermeto_sbom = None
                if self.cli_args.from_hermeto:
                    hermeto_sbom = await self._load_and_filter_hermeto_sbom()

                return merge_sboms(syft_sboms, hermeto_sbom)
            return await load_sbom_from_json(self.cli_args.from_syft[0])
        if self.cli_args.from_hermeto is not None:
            return await self._load_and_filter_hermeto_sbom()

        return await syft.scan_image(self.cli_args.image_pullspec)

    @staticmethod
    async def execute_parent_contextualization(
        parent_image_ref: Image, arch: str, component_sbom_doc: Document
    ) -> Document:
        """
        Finds and downloads used parent image SBOM (if exists), maps packages
        from parent to component and modifies relationships in
        component, expressing which packages came to component
        from used parent or grandparents.
        """
        LOGGER.debug("Running parent content contextualization...")
        parent_image_sbom = await download_parent_image_sbom(parent_image_ref, arch)
        if not parent_image_sbom:
            raise ParentContextualizationError(
                "Parent image SBOM could not be found skipping "
                "contextualization, non-contextual SBOM will be produced"
            )
        parent_sbom_doc = await normalize_and_load_sbom(
            parent_image_sbom, append_mobster=False
        )
        parent_spdx_id_from_component = get_parent_spdx_id_from_component(
            component_sbom_doc
        )
        descendant_of_items_from_used_parent = get_descendant_of_items_from_used_parent(
            parent_sbom_doc, parent_spdx_id_from_component
        )
        contextual_sbom = await map_parent_to_component_and_modify_component(
            parent_sbom_doc,
            component_sbom_doc,
            parent_spdx_id_from_component,
            descendant_of_items_from_used_parent,
        )
        LOGGER.debug("Parent content contextualization complete.")
        return contextual_sbom

    @staticmethod
    def execute_builder_contextualization(
        parent_contextualized_sbom: Document, builder_metadata: BuilderPkgMetadata
    ) -> Document:
        """
        Matches capo's builder metadata packages to parent contextualized SBOM
        and reparents matched packages to builder base images / intermediate images
        """
        LOGGER.debug("Running builder content contextualization...")
        builder_ctx_sbom = deepcopy(parent_contextualized_sbom)
        index = DocumentIndexOCI(builder_ctx_sbom)

        builder = BuilderContextualizer()
        contextual_sbom = builder.contextualize(index, builder_metadata)
        LOGGER.debug("Builder content contextualization complete.")
        return contextual_sbom

    async def _execute_contextual_workflow(
        self,
        component_sbom_doc: Document,
        parent_image_ref: Image,
        arch: str,
        build_metadata_path: Path | None,
    ) -> Document:
        """
        Run all steps from the contextual workflow.

        - if user specifies --build-metadata-path, function attempts to load file.
            - if builder metadata file is missing or malformed (i.e. capo failed)
              ContextualWorkflowError is raised resulting in non-contextual SBOM
              later on.
            - if builder metadata is present but packages are empty ( {"packages": []} )
              and buildprobe metadata contain no extra or builder base images
              image is evaluated as single stage, builder contextualization is
              skipped and parent contextualized SBOM is returned
        - if user omits --build-metadata-path, function executes
          parent contextualization but checks buildprobe output
          and if extra of builder base images are present
          warns user that build was multistage, and contextualization
          is very likely to be incomplete.

        If any error during parent or builder contextualization
        occurs, mobster will produce non-contextual SBOM.

        User is also warned when capo and buildprobe inputs seem
        to be conflicting - i.e. build appears to be multistage,
        but capo did not detect any packages.

        Args:
            component_sbom_doc:
                The component SBOM created for this image.
                Warning: component SBOM is intentionally
                modified by this workflow.
            parent_image_ref: Reference to the parent image.
            arch: CPU architecture of this image.
            build_metadata_path: Path to build metadata output from Capo

        Returns:
            Contextual SBOM document — either parent-only contextualized
            (when builder content is not applicable) or fully contextualized
            (parent + builder).

        Raises:
            ContextualWorkflowError: When capo metadata cannot be loaded,
                parent contextualization fails, or builder contextualization
                fails. Caller is expected to fall back to non-contextual SBOM.
        """
        if build_metadata_path:
            builder_metadata = GenerateOciImageCommand._load_builder_metadata(
                build_metadata_path
            )
            if builder_metadata is None:
                raise ContextualWorkflowError(
                    "Cannot load builder metadata file "
                    f"from capo {build_metadata_path}, "
                    "skipping entire contextualization (parent, builder)"
                )

        try:
            parent_contextualized_sbom = (
                await GenerateOciImageCommand.execute_parent_contextualization(
                    parent_image_ref, arch, component_sbom_doc
                )
            )
        except (ParentContextualizationError, SBOMError) as exc:
            raise ContextualWorkflowError(
                "Failed to contextualize parent content. "
                "Non-contextual SBOM will be generated."
            ) from exc

        build_is_multistage = (
            self._metadata.extra_images or self._metadata.builder_base_images
        )
        if not build_metadata_path:
            if build_is_multistage:
                LOGGER.warning(
                    "Build of the processed image was "
                    "multistage but no --build-metadata-path provided, "
                    "cannot execute builder content contextualization. "
                    "Provided buildprobe contains "
                    "extra images: %d, builder base images: %d. "
                    "This means that contextualization is very likely INCOMPLETE "
                    "reflecting parent but not builder content.",
                    len(self._metadata.extra_images),
                    len(self._metadata.builder_base_images),
                )
            # else: single-stage build - build metadata are not needed
            return parent_contextualized_sbom

        assert builder_metadata is not None
        if not builder_metadata.packages:
            if build_is_multistage:
                LOGGER.warning(
                    "Detected multistage build but no builder packages in capo "
                    "metadata. Possible reasons: "
                    "no content might be copied from extra images or stages. "
                    "If this is not the case: "
                    "check correctness of the capo/buildprobe mobster inputs "
                    "with respect to original Containerfile, "
                    "check capo unsupported features or scan feature."
                )
            # else: single-stage build - packages are not expected
            return parent_contextualized_sbom

        try:
            parent_builder_contextualized_sbom = (
                GenerateOciImageCommand.execute_builder_contextualization(
                    parent_contextualized_sbom, builder_metadata
                )
            )
        except BuilderContextualizationError as exc:
            raise ContextualWorkflowError(
                "Failed to contextualize builder content. Rollback-ing "
                "parent content contextualization to prevent incomplete "
                "contextualization. Non-contextual SBOM will be generated."
            ) from exc

        return parent_builder_contextualized_sbom

    async def _assess_and_dispatch_contextual_workflow(
        self,
        component_sbom_doc: Document | CycloneDX1BomWrapper,
        base_images_refs: list[str | None],
        base_images: dict[str, Image],
        image_arch: str,
    ) -> Document | None:
        """
        Check if the Contextual workflow should be attempted
        and try to run it. Contextual workflow modifies
        mobster-produced component SBOM in place. Before
        workflow a deep copy is created from this SBOM.
        When any error during contextual SBOM workflow
        emerges function returns None and original
        (non-modified) SBOM is furtherly processed by mobster.
        Args:
            component_sbom_doc: The component SBOM created for this image.
            base_images_refs: List of references from the build.
            image_arch: CPU architecture of this image.

        Returns:
            spdx_tools.spdx.model.document.Document | None:
                The contextual SBOM if the workflow was successful.
                None otherwise.
        """
        if (
            self.cli_args.contextualize
            and isinstance(component_sbom_doc, Document)
            and base_images_refs
            and (parent_image_ref := base_images_refs[-1])
        ):
            try:
                parent_image_obj = base_images[parent_image_ref]
                copied_component_sbom_doc = deepcopy(component_sbom_doc)
                contextual_sbom = await self._execute_contextual_workflow(
                    copied_component_sbom_doc,
                    parent_image_obj,
                    image_arch,
                    self.cli_args.build_metadata_path,
                )
                LOGGER.info("Contextual SBOM workflow finished successfully.")
                return contextual_sbom
            except Exception as exc:  # pylint: disable=broad-exception-caught
                LOGGER.exception("Contextual SBOM workflow failed: %s", exc)
        LOGGER.info("Could not create contextual SBOM.")
        return None

    async def execute(self) -> Any:  # pylint: disable=too-many-locals,too-many-branches,too-many-statements
        """
        Generate an SBOM document for OCI image.
        """
        LOGGER.debug("Generating SBOM document for OCI image")

        # Get/merge the raw SBOM
        merged_sbom_dict = await self._handle_bom_inputs()
        sbom: Document | CycloneDX1BomWrapper
        image_arch = self.cli_args.arch or mobster.utils.identify_arch()

        # Parse into objects
        if merged_sbom_dict.get("bomFormat") == "CycloneDX":
            if self.cli_args.contextualize:
                raise ArgumentError(
                    None, "--contextualize is only allowed when processing SPDX format"
                )
            sbom = CycloneDX1BomWrapper.from_dict(merged_sbom_dict)
        elif "spdxVersion" in merged_sbom_dict:
            sbom = await normalize_and_load_sbom(merged_sbom_dict)
        else:
            raise ValueError("Unknown SBOM Format!")

        base_images_refs = []
        base_images_map: dict[str, Image] = {}

        # Use buildprobe metadata if loaded successfully, otherwise fall back to
        # deprecated dockerfile-json path
        # Buildprobe metadata path supports full contextualization parent / builder
        # dockerfile-json path supports non-contextualized SBOM only
        if self._metadata is not None:
            image = self._metadata.image.to_image(image_arch)
            await extend_sbom_with_image_reference(sbom, image, is_builder_image=False)
            for base_image_data in self._metadata.base_images:
                base_image = base_image_data.to_image()
                base_images_refs.append(base_image_data.pullspec)
                base_images_map[base_image_data.pullspec] = base_image
            await extend_sbom_with_base_images(sbom, base_images_refs, base_images_map)
            for extra_image_data in self._metadata.extra_images:
                extra_image = extra_image_data.to_image()
                await extend_sbom_with_image_reference(sbom, extra_image, True)
            with log_elapsed("Contextual workflow", logging.INFO):
                contextual_sbom = await self._assess_and_dispatch_contextual_workflow(
                    sbom, base_images_refs, base_images_map, image_arch
                )
            sbom = contextual_sbom or sbom
        elif self.cli_args.image_pullspec:
            if not self.cli_args.image_digest:
                LOGGER.info(
                    "Provided pullspec but not digest."
                    " Resolving the digest using oras..."
                )
                self.cli_args.image_digest = await get_digest_for_image_ref(
                    self.cli_args.image_pullspec, image_arch
                )
            if not self.cli_args.image_digest:
                raise ValueError(
                    "No value for image digest was provided "
                    "and the image is not visible to oras!"
                )

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

        # Deprecated fallback if buildprobe metadata are not available:
        # dockerfile-json input, enrich SBOM for image packages,
        # but do not contextualize content.
        if not self._metadata:
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
                await extend_sbom_with_base_images(
                    sbom, base_images_refs, base_images_map
                )

            # Extending with additional base images
            for image_ref in self.cli_args.additional_base_image:
                image_object = Image.from_oci_artifact_reference(image_ref)
                await extend_sbom_with_image_reference(
                    sbom, image_object, is_builder_image=True
                )

        self._content = sbom
        if not self.cli_args.skip_validation:
            with log_elapsed("Validation of final SBOM", logging.INFO):
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
            with open(output_file, "w", encoding="utf-8") as write_stream:
                json.dump(output_dict, write_stream)
