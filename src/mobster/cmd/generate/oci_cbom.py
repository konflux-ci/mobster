"""
Module for handling OCI CBOM generation.
"""

import json
from argparse import Namespace
from dataclasses import dataclass
from pathlib import Path

from cyclonedx.model.dependency import Dependency

from mobster.cmd.generate.base import GenerateCommand
from mobster.image import Image
from mobster.sbom.cyclonedx import get_component
from mobster.sbom.cyclonedx_wrapper import CycloneDX1BomWrapper
from mobster.sbom.load import load_file_to_sbom


@dataclass
class OciCBOMArgs:
    """
    Command arguments for oci_cbom.
    """

    image_pullspec: str
    image_digest: str
    cbom_path: Path
    arch: str | None = None

    @staticmethod
    def from_cli_args(cli_args: Namespace) -> "OciCBOMArgs":
        """
        Get OciCBOMArgs from argparse namespace.
        Args:
            cli_args: the namespace parsed from the command line.

        Returns:
            The OciCBOMArgs object.
        """
        return OciCBOMArgs(
            cli_args.image_pullspec,
            cli_args.image_digest,
            cli_args.cbom_path,
            cli_args.arch,
        )


class GenerateOciCBOMCommand(GenerateCommand):
    """
    Command to generate CBOMs. Adds identifying metadata to CBOMs generated
    by crypto scanners. Only works with CycloneDX v1.x at this moment.
    """

    @staticmethod
    def _update_dependencies(document: CycloneDX1BomWrapper) -> None:
        """
        Makes sure all algorithms are mapped to the root component.
        Must be run only after the root component is initialized.
        """
        assert document.sbom.metadata.component, "metadata.component is required"
        root_ref = document.sbom.metadata.component.bom_ref
        dep_refs = [
            component.bom_ref
            for component in document.sbom.components
            if component.bom_ref != root_ref
        ]
        root_dependency = Dependency(root_ref)
        root_dependency.dependencies = [Dependency(ref) for ref in dep_refs]
        document.sbom.dependencies.add(root_dependency)

    async def execute(self) -> CycloneDX1BomWrapper:
        """
        Run the command to generate the CBOM.
        Returns:
            The updated CBOM object.
        """
        args = OciCBOMArgs.from_cli_args(self.cli_args)
        loaded_cbom = load_file_to_sbom(args.cbom_path, True)
        assert isinstance(loaded_cbom, CycloneDX1BomWrapper), (
            "Mobster cannot process CBOMs in different formats than CycloneDX1."
        )
        image = Image.from_image_index_url_and_digest(
            args.image_pullspec, args.image_digest, args.arch
        )
        component = get_component(image)
        loaded_cbom.sbom.metadata.component = component
        self._update_dependencies(loaded_cbom)
        self._content = loaded_cbom.to_dict()
        return loaded_cbom

    async def save(self) -> None:
        """
        Saves the output of the command either to STDOUT
        or to a specified file.
        Returns:
            bool: Was the save operation successful?
        """
        output_file: Path | None = self.cli_args.output
        if output_file is None:
            print(json.dumps(self._content))
        else:
            with open(output_file, "w", encoding="utf-8") as write_stream:
                json.dump(self._content, write_stream)
