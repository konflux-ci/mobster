"""Configuration for Cosign clients"""

import os
import re
import tempfile
from collections.abc import Generator
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, Any, Literal

from pydantic import BeforeValidator, Field, PlainSerializer, TypeAdapter
from pydantic.dataclasses import dataclass as pdc_dataclass


def _serialize_datetime(value: datetime) -> str:
    """
    The time format is specified to contain milliseconds, whereas Python
    only allows dumping microseconds. 3 digits are stripped.
    Z specifies the UTC timezone.
    """
    return value.strftime("%FT%H:%M:%S.%f")[:-3] + "Z"


def _validate_config_selector(value: str) -> str:
    if value in {"ANY", "ALL"} or re.match(r"EXACT:\d+", value):
        return value
    raise ValueError(
        f"Invalid config selector: {value}, "
        f"see `cosign config create --help` for possible values."
    )


@pdc_dataclass
class ValidFor:
    """
    Type for specifying validity of a URL.
    Currently only supports the minimal field: start.
    """

    start: Annotated[datetime, PlainSerializer(_serialize_datetime)] = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )


@pdc_dataclass
class URL:
    """
    Type for specifying a URL.
    """

    url: str
    major_api_version: int = Field(default=1, serialization_alias="majorApiVersion")
    valid_for: ValidFor = Field(
        default_factory=ValidFor, serialization_alias="validFor"
    )
    operator: str = Field(default="sigstore.dev")

    def __eq__(self, other: Any) -> bool:
        """
        Omits validity from comparison. Comparison is used just in
        tests at this point in time.
        """
        if not isinstance(other, self.__class__):
            return False
        return (
            self.url == other.url and self.major_api_version == other.major_api_version
        )


@pdc_dataclass
class ServiceConfig:
    """
    Type for specifying a Sigstore service configuration about
    matching the specified URLs.
    """

    selector: Annotated[str, BeforeValidator(_validate_config_selector)]


def _get_urls(*urls: str) -> list[URL]:
    result_urls = []
    for url in urls:
        if isinstance(url, str):
            result_urls.append(URL(url=url))
    return result_urls


@pdc_dataclass
class URLSigningConfig:
    """
    Signing Configuration for Cosign CLI.
    See https://raw.githubusercontent.com/sigstore/
    root-signing/refs/heads/main/targets/signing_config.v0.2.json

    This class implements the builder pattern to easily populate its fields.
    """

    media_type: Literal["application/vnd.dev.sigstore.signingconfig.v0.2+json"] = Field(
        serialization_alias="mediaType",
        default="application/vnd.dev.sigstore.signingconfig.v0.2+json",
    )
    ca_urls: list[URL] = Field(serialization_alias="caUrls", default_factory=list)
    oidc_urls: list[URL] = Field(serialization_alias="oidcUrls", default_factory=list)
    rekor_tlog_urls: list[URL] = Field(
        serialization_alias="rekorTlogUrls", default_factory=list
    )
    tsa_urls: list[URL] = Field(serialization_alias="tsaUrls", default_factory=list)
    rekor_tlog_config: ServiceConfig = Field(
        serialization_alias="rekorTlogConfig",
        default_factory=lambda: ServiceConfig("ANY"),
    )
    tsa_config: ServiceConfig = Field(
        serialization_alias="tsaConfig", default_factory=lambda: ServiceConfig("ANY")
    )

    def set_tlog_url(self, *urls: str) -> "URLSigningConfig":
        """
        Builder pattern method for setting the TLog (Rekor) URLs.
        Args:
            *urls: Any number of URL strings.

        Returns:
            Self (the edited object).
        """
        self.rekor_tlog_urls = _get_urls(*urls)
        return self

    def set_fulcio_url(self, *urls: str) -> "URLSigningConfig":
        """
        Builder pattern method for setting the Fulcio (CA) URLs.
        Args:
            *urls: Any number of URL strings.

        Returns:
            Self (the edited object).
        """
        self.ca_urls = _get_urls(*urls)
        return self

    def set_issuer_url(self, *urls: str) -> "URLSigningConfig":
        """
        Builder pattern method for setting the issuer URLs.
        Args:
            *urls: Any number of URL strings.

        Returns:
            Self (the edited object).
        """
        self.oidc_urls = _get_urls(*urls)
        return self

    @contextmanager
    def file(self) -> Generator[Path, None, None]:
        """
        Context manager for creating a temporary Cosign Signing Config file.
        Yields:
            The path to the Cosign Signing Config file.
        """
        tempdir = tempfile.TemporaryDirectory()
        try:
            sign_config_path = Path(tempdir.name).joinpath("signing_config.json")
            with open(sign_config_path, "wb") as f:
                f.write(TypeAdapter(type(self)).dump_json(self, by_alias=True))
            yield sign_config_path
        finally:
            tempdir.cleanup()

    def is_keyless_ready(self) -> bool:
        """
        Does this config contain information needed for keyless signing?
        Returns:
            True if the config contains information needed for keyless
            signing, False otherwise.
        """
        return (
            self.rekor_tlog_urls != [] and self.oidc_urls != [] and self.ca_urls != []
        )


@pdc_dataclass
class StaticSignConfig:
    """
    Static (using keys) cosign configuration.

    Attributes:
        sign_key:
            Path or URL to the signing key for SBOM attesting
        sign_password:
            Password used for encrypting the signing key
    """

    sign_key: os.PathLike[str]
    sign_password: bytes = b""


@pdc_dataclass
class KeylessVerifyConfig:
    """
    Class holding information needed to verify a Cosign Signing Config.

    Attributes:
        identity_pattern:
            Expected signee identity regex pattern
        oidc_issuer:
            Expected signee identity (actual URL and not regex)
    """

    identity_pattern: str
    oidc_issuer: str


@pdc_dataclass
class SignConfig:
    """
    Configuration of Cosign keys for signing.

    Attributes:
        url_config:
            configuration of Sigstore services
        static_sign_config:
            Configuration for static signing
        keyless_token_file:
            Token file used for keyless signing
    """

    url_config: URLSigningConfig = Field(default_factory=URLSigningConfig)
    static_sign_config: StaticSignConfig | None = Field(default=None)
    keyless_token_file: Path | None = Field(default=None)


@pdc_dataclass
class VerifyConfig:
    """
    Configuration of Cosign keys for verification.

    Attributes:
        static_verify_key:
            Verification static key path
        keyless_verify_config:
            Configuration for keyless verification

    """

    static_verify_key: os.PathLike[str] | None = Field(default=None)
    keyless_verify_config: KeylessVerifyConfig | None = Field(default=None)
