"""This module contains the real Cosign implementation using static signing keys."""

import hashlib
import json
import logging
import os
import tempfile
import typing
from base64 import b64decode
from pathlib import Path
from typing import Literal

from mobster.error import SBOMError
from mobster.image import Image
from mobster.oci import make_oci_auth_file
from mobster.oci.artifact import SBOM, Provenance02, SBOMFormat
from mobster.oci.cosign.attestation_utils import get_cosign_attestation_type
from mobster.oci.cosign.config import (
    SignConfig,
    VerifyConfig,
)
from mobster.oci.cosign.protocol import SupportsFetch, SupportsSign
from mobster.utils import run_async_subprocess

logger = logging.getLogger(__name__)


class CosignSBOMFetcher(SupportsFetch):
    """
    Client used to get OCI artifacts using Cosign.

    Attributes:
        verify_key: verification (public) key path
        rekor_config: TLOG configuration
    """

    def __init__(
        self,
        cosign_config: VerifyConfig,
    ) -> None:
        """
        Args:
            cosign_config: The configuration for this client instance
        """
        self.verify_key = cosign_config.static_verify_key
        self.rekor_config = cosign_config.rekor_config
        # Some cosign operations are extremely heavy, requiring a mutex mechanism
        # to not get OOM killed within the pipeline

    async def _verify_attestation(
        self,
        image: Image,
        attestation_type: typing.Literal["slsaprovenance02", "spdxjson", "cyclonedx"],
    ) -> list[bytes]:
        with make_oci_auth_file(image.reference) as authfile:
            # We ignore the transparency log, because as of now, Konflux releases
            # don't publish to Rekor.
            cmd = [
                "cosign",
                "verify-attestation",
                f"--key={self.verify_key}",
                f"--type={attestation_type}",
                "--insecure-ignore-tlog=true",
                image.reference,
            ]
            logger.debug("Executing for %s command '%s'", image, " ".join(cmd))
            code, stdout, stderr = await run_async_subprocess(
                cmd,
                env={"DOCKER_CONFIG": str(authfile.parent)},
                retry_times=3,
            )

        if code != 0:
            raise SBOMError(
                f"Failed to fetch attestation for {image}: {stderr.decode()}."
            )

        return stdout.splitlines()

    async def fetch_latest_provenance(self, image: Image) -> Provenance02:
        """
        Fetch the latest provenance based on the supplied image based on the
        time the image build finished.

        Args:
            image (Image): Image to fetch the provenances of.
        """

        provenances: list[Provenance02] = []
        for raw_attestation in await self._verify_attestation(
            image, "slsaprovenance02"
        ):
            prov = Provenance02.from_cosign_output(raw_attestation)
            provenances.append(prov)

        if len(provenances) == 0:
            raise SBOMError(f"No provenances parsed for image {image}.")

        return sorted(provenances, key=lambda x: x.build_finished_on, reverse=True)[0]

    async def fetch_attested_sbom(
        self, image: Image, sbom_format: SBOMFormat
    ) -> SBOM | None:
        """
        Fetch attested SBOM.
        Args:
            image: The image this attestation (and the SBOM) belongs to
            sbom_format: The expected SBOM format. This function only cares if the type
                is SPDX or CDX, specific version does not matter

        Returns:
            The initialized SBOM object
        """
        attestation_type = get_cosign_attestation_type(sbom_format)
        attestations = await self._verify_attestation(image, attestation_type)
        if attestations:
            last_attestation = attestations[-1]
            return SBOM(
                json.loads(b64decode(json.loads(last_attestation)["payload"]))[
                    "predicate"
                ],
                hashlib.sha256(last_attestation).hexdigest(),
                image.reference,
            )
        return None

    async def fetch_sbom(self, image: Image) -> SBOM:
        """
        Fetch and parse the SBOM for the supplied image.

        Args:
            image (Image): Image to fetch the SBOM of.
        """
        with make_oci_auth_file(image.reference) as authfile:
            code, stdout, stderr = await run_async_subprocess(
                ["cosign", "download", "sbom", image.reference],
                env={"DOCKER_CONFIG": str(authfile.parent)},
                retry_times=3,
            )

        if code != 0:
            raise SBOMError(f"Failed to fetch SBOM {image}: {stderr.decode()}")

        return SBOM.from_cosign_output(stdout, image.reference)


class CosignSigner(SupportsSign):
    """
    Cosign signing client using static keys
    """

    def __init__(self, config: SignConfig):
        if config.static_sign_config is None or not config.static_sign_config.sign_key:
            raise SBOMError("Cannot attest SBOM, no signing key was provided.")
        self.rekor_config = config.rekor_config
        self.sign_config = config.static_sign_config

    async def _attest_anything(
        self,
        file_path: Path,
        push_reference: str,
        data_format: Literal[
            "slsaprovenance",
            "slsaprovenance02",
            "slsaprovenance1",
            "link",
            "spdx",
            "spdxjson",
            "cyclonedx",
            "vuln",
            "openvex",
            "custom",
        ],
    ) -> None:
        """
        Sign & attach an arbitrary file as OCI attestation to an image
        with the supplied reference.
        Args:
            file_path: Path of the data to be attested
            push_reference: Reference of the image that this attestation
                will be attached to
            data_format: Cosign-dependent attestation format

        Returns:
            None
        """

        # Translate SPDX format to a cosign-supported version. See
        # https://github.com/sigstore/cosign/blob/main/doc/cosign_attest.md#options
        cosign_command = [
            "cosign",
            "attest",
            "--yes",
            "--key",
            str(self.sign_config.sign_key),
            "--type",
            data_format,
            "--predicate",
            str(file_path),
            push_reference,
        ]
        with make_oci_auth_file(push_reference) as authfile:
            cosign_env = {"DOCKER_CONFIG": str(authfile.parent)}
            for env_var_name in (
                "AWS_DEFAULT_REGION",
                "AWS_ACCESS_KEY_ID",
                "AWS_SECRET_ACCESS_KEY",
            ):
                if env_var_value := os.environ.get(f"COSIGN_{env_var_name}"):
                    cosign_env[env_var_name] = str(env_var_value)
            if not self.rekor_config:
                logger.debug("[Cosign] TLog won't be used for sbom attestation.")
                cosign_command.insert(-1, "--tlog-upload=false")
            else:
                cosign_command.insert(-1, f"--rekor-url={self.rekor_config.rekor_url}")
                cosign_env["SIGSTORE_REKOR_PUBLIC_KEY"] = str(
                    self.rekor_config.rekor_key
                )
            with tempfile.NamedTemporaryFile() as sign_key_passwd_file:
                sign_key_passwd_file.write(self.sign_config.sign_password)
                code, _, stderr = await run_async_subprocess(
                    cosign_command,
                    env=cosign_env,
                    retry_times=3,
                    stdin=sign_key_passwd_file,
                )
        if code:
            raise SBOMError(
                f"Could not attest SBOM ({' '.join(cosign_command)}) "
                f"failed with code {code}, STDERR: {stderr.decode()}",
            )

    async def attest_provenance(
        self, provenance: Provenance02, image_ref: str
    ) -> None:  # pragma: nocover
        """
        Attach a SLSA Provenance v2 to an image. For test purposes only.
        Args:
            provenance: Provenance object to attach
            image_ref: reference of image to attach to
        """
        # Used in integration tests only, unit-testing won't add any benefit
        # as this is just a wrapper for another function which is covered by
        # testing self.attest_sbom
        with tempfile.NamedTemporaryFile() as temp_provenance:
            with open(temp_provenance.name, "w", encoding="utf-8") as write_file:
                json.dump(provenance.predicate, write_file)
            await self._attest_anything(
                Path(temp_provenance.name), image_ref, "slsaprovenance02"
            )

    async def attest_sbom(
        self,
        sbom_path: Path,
        image_ref: str,
        sbom_format: SBOMFormat,
    ) -> None:
        await self._attest_anything(
            sbom_path,
            image_ref,
            get_cosign_attestation_type(sbom_format),
        )

    async def clean(
        self,
        image_ref: str,
        blob_type: Literal["all", "signature", "attestation", "sbom"] = "all",
    ) -> None:
        """
        Clean OCI registry using cosign.
        Args:
            image_ref: The image which should be cleaned
            blob_type: What type of attachments should be cleaned
        Returns:
            None
        """
        with make_oci_auth_file(image_ref) as authfile:
            cmd = ["cosign", "clean", "--force=true", f"--type={blob_type}", image_ref]
            code, _, stderr = await run_async_subprocess(
                cmd, env={"DOCKER_CONFIG": str(authfile.parent)}
            )
            if code:
                raise SBOMError(
                    f"Could not clean '{blob_type}' from image {image_ref}. "
                    f"STDERR: {stderr.decode()}"
                )

    async def sign_image(self, image_ref: str) -> None:
        """
        Sign an image in the registry using cosign.

        Args:
            image_ref: The image to sign.
        """
        if self.sign_config is None:
            raise SBOMError("Cannot sign image without a signing config")
        cosign_command = [
            "cosign",
            "sign",
            "--key",
            str(self.sign_config.sign_key),
            image_ref,
        ]
        with make_oci_auth_file(image_ref) as authfile:
            cosign_env = {"DOCKER_CONFIG": str(authfile.parent)}

            if not self.rekor_config:
                logger.debug("[Cosign] TLog won't be used for sbom attestation.")
                cosign_command.insert(-1, "--tlog-upload=false")
            else:
                cosign_command.insert(-1, f"--rekor-url={self.rekor_config.rekor_url}")
                cosign_env["SIGSTORE_REKOR_PUBLIC_KEY"] = str(
                    self.rekor_config.rekor_key
                )

            with tempfile.NamedTemporaryFile() as sign_key_passwd_file:
                sign_key_passwd_file.write(self.sign_config.sign_password)
                code, _, stderr = await run_async_subprocess(
                    cosign_command,
                    env=cosign_env,
                    retry_times=3,
                    stdin=sign_key_passwd_file,
                )
            if code != 0:
                raise RuntimeError(
                    f"Failed to sign image {image_ref} in registry.\n"
                    f"CMD: {' '.join(cosign_command)}\n"
                    f"Error: {stderr.decode()}"
                )
        return None
