import pytest
import pytest_asyncio
from pytest_lazy_fixtures import lf

from mobster.error import SBOMError, SBOMVerificationError
from mobster.image import Image
from mobster.oci.cosign import (
    AnonymousFetcher,
    SignConfig,
    StaticSignConfig,
    VerifyConfig,
)
from mobster.oci.cosign.static import StaticKeyFetcher, StaticKeySigner
from mobster.sbom.detect import SBOMFormat
from tests.integration.oci_client import ReferrersTagOCIClient
from tests.integration.utils import attest_sbom_bytes


@pytest_asyncio.fixture()
async def image_with_empty_sbom(oci_client: ReferrersTagOCIClient) -> Image:
    sbom = b"{}"
    image = await oci_client.create_image("empty-sbom", "tag")
    await oci_client.attach_sbom(image, "spdx", sbom)
    return image


@pytest_asyncio.fixture()
async def image_with_empty_cdx_attested_sbom(
    cosign_sign_key: str, oci_client: ReferrersTagOCIClient
) -> Image:
    image = await oci_client.create_image("empty-sbom-attestation", "tag")
    signer = StaticKeySigner(
        SignConfig(static_sign_config=StaticSignConfig(sign_key=cosign_sign_key))
    )
    await attest_sbom_bytes(signer, image, b"{}", SBOMFormat.CDX_V1_5)
    return image


@pytest_asyncio.fixture()
async def image_with_empty_spdx_attested_sbom(
    cosign_sign_key: str, oci_client: ReferrersTagOCIClient
) -> Image:
    image = await oci_client.create_image("empty-spdx-sbom-attestation", "tag")
    signer = StaticKeySigner(
        SignConfig(static_sign_config=StaticSignConfig(sign_key=cosign_sign_key))
    )
    await attest_sbom_bytes(signer, image, b"{}", SBOMFormat.SPDX_2_3)
    return image


@pytest_asyncio.fixture()
async def image_with_no_sbom(oci_client: ReferrersTagOCIClient) -> Image:
    return await oci_client.create_image("no-sbom", "tag")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ["image", "verify_key", "expected_verified"],
    [
        # fetch_sbom does not verify .sbom attachments, with or without a key.
        # Verification against provenance happens later in the flow, if enabled.
        pytest.param(lf("image_with_empty_sbom"), None, False, id="attachment-no-key"),
        pytest.param(
            lf("image_with_empty_sbom"),
            lf("cosign_verify_key"),
            False,
            id="attachment-with-key",
        ),
        # stored as an OCI 1.1 referrer (sigstore bundle)
        pytest.param(
            lf("image_with_empty_spdx_attested_sbom"),
            lf("cosign_verify_key"),
            True,
            id="spdx-attestation",
        ),
        # CycloneDX fallback when no SPDX attestation is present.
        pytest.param(
            lf("image_with_empty_cdx_attested_sbom"),
            lf("cosign_verify_key"),
            True,
            id="cdx-attestation",
        ),
    ],
)
async def test_cosign_fetch_sbom(
    image: Image, verify_key: str | None, expected_verified: bool
) -> None:
    """
    Test fetching an SBOM from an image that has one, either attached or
    attested. Only the attested SBOMs are signature-verified.

    Args:
        image: Image fixture with an empty SBOM.
        verify_key: Verification key passed to the fetcher.
        expected_verified: Whether the SBOM is expected to be signature-verified.
    """
    cosign = StaticKeyFetcher(VerifyConfig(static_verify_key=verify_key))
    sbom = await cosign.fetch_sbom(image)
    assert sbom.doc == {}
    assert sbom.signature_verified is expected_verified


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ["image", "verify_key", "error", "match"],
    [
        # attestation signed by a different key than the one passed
        pytest.param(
            lf("image_with_empty_spdx_attested_sbom"),
            lf("other_cosign_verify_key"),
            SBOMVerificationError,
            "matches the key",
            id="attestation-wrong-key",
        ),
        # cosign reports a missing SBOM the same way as a wrong key
        pytest.param(
            lf("image_with_no_sbom"),
            lf("cosign_verify_key"),
            SBOMVerificationError,
            "matches the key",
            id="no-sbom-with-key",
        ),
    ],
)
async def test_cosign_fetch_sbom_key_errors(
    image: Image, verify_key: str | None, error: type[SBOMError], match: str
) -> None:
    """
    Test that an SBOM attestation is used only when it verifies with the
    configured key. Together with test_cosign_fetch_sbom, this shows the
    configured key is what decides the result.

    Args:
        image: Image fixture.
        verify_key: Verification key passed to the fetcher.
        error: Expected exception type. SBOMVerificationError subclasses
            SBOMError, so match is needed to tell the cases apart.
        match: Regex expected in the exception message.
    """
    cosign = StaticKeyFetcher(VerifyConfig(static_verify_key=verify_key))
    with pytest.raises(error, match=match):
        await cosign.fetch_sbom(image)


@pytest.mark.asyncio
async def test_cosign_fetch_sbom_no_image() -> None:
    """
    Test fetching an SBOM from a non-existent image.
    """
    cosign = StaticKeyFetcher(VerifyConfig())
    image = Image(repository="no-repo", digest="sha256:deadbeef")
    with pytest.raises(SBOMError):
        await cosign.fetch_sbom(image)


@pytest.mark.asyncio
async def test_fetch_anonymous_attached(image_with_empty_sbom: Image) -> None:
    cosign = AnonymousFetcher()
    sbom = await cosign.fetch_sbom(image_with_empty_sbom)
    assert sbom.doc == {}


@pytest.mark.asyncio
async def test_fetch_anonymous_attested(
    image_with_empty_cdx_attested_sbom: Image,
) -> None:
    cosign = AnonymousFetcher()
    sbom = await cosign.fetch_sbom(image_with_empty_cdx_attested_sbom)
    assert sbom.doc == {}
