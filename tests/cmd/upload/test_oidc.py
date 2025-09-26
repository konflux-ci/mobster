from collections.abc import AsyncGenerator
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
import pytest_asyncio
from pytest_httpx import HTTPXMock, IteratorStream

from mobster.cmd.upload import oidc
from mobster.cmd.upload.oidc import OIDCClientCredentialsClient, RetryExhaustedException

AUTHORIZATION_HEADER = {"Authorization": "Bearer asdfghjkl"}

BASE_URL = "https://api.example.com/v1/"


@pytest_asyncio.fixture
async def oidc_client() -> AsyncGenerator[oidc.OIDCClientCredentialsClient, None]:
    token_url = "https://auth.example.com/oidc/token"
    proxy = "http://proxy.example.com:3128"
    auth = oidc.OIDCClientCredentials(
        token_url=token_url, client_id="abc", client_secret="xyz"
    )
    async with oidc.OIDCClientCredentialsClient(BASE_URL, auth, proxy=proxy) as client:
        yield client


@pytest.mark.asyncio
async def test__fetch_token_success(
    httpx_mock: HTTPXMock, oidc_client: OIDCClientCredentialsClient
) -> None:
    form_encoded_content_type = {"Content-Type": "application/x-www-form-urlencoded"}
    token_url = "https://auth.example.com/oidc/token"
    token_response = {"access_token": "asdfghjkl", "expires_in": 600}

    httpx_mock.add_response(
        url=token_url,
        method="post",
        headers=form_encoded_content_type,
        json=token_response,
    )

    await oidc_client._fetch_token()
    assert oidc_client._token == "asdfghjkl"
    assert oidc_client._token_expiration > 0


@pytest.mark.asyncio
@patch("mobster.cmd.upload.oidc.LOGGER")
@patch("httpx.AsyncClient.post")
async def test__fetch_token_unable(
    mock_post: AsyncMock,
    mock_logger: MagicMock,
    oidc_client: OIDCClientCredentialsClient,
) -> None:
    request = httpx.Request("POST", "foo")
    mock_post.return_value = httpx.Response(500, request=request)

    with pytest.raises(httpx.HTTPStatusError):
        await oidc_client._fetch_token()

    mock_logger.error.assert_called_once_with(
        "Unable to fetch auth token. [%s] %s", 500, ""
    )


@pytest.mark.asyncio
async def test__fetch_token_failed_unauthorized(
    httpx_mock: HTTPXMock, oidc_client: OIDCClientCredentialsClient
) -> None:
    form_encoded_content_type = {"Content-Type": "application/x-www-form-urlencoded"}
    token_error_url = "https://auth.example.com/oidc/fail/token"
    token_error_response = {
        "error": "unauthorized_client",
        "error_description": "Invalid client secret",
    }

    httpx_mock.add_response(
        url=token_error_url,
        method="post",
        headers=form_encoded_content_type,
        json=token_error_response,
    )
    # error response
    auth = oidc.OIDCClientCredentials(
        token_url=token_error_url, client_id="abc", client_secret="xyz"
    )
    oidc_client._auth = auth

    with pytest.raises(oidc.OIDCAuthenticationError) as exc:
        await oidc_client._fetch_token()
    assert "unauthorized_client" in str(exc.value)


@pytest.mark.asyncio
async def test__fetch_token_failed_invalid(
    httpx_mock: HTTPXMock, oidc_client: OIDCClientCredentialsClient
) -> None:
    form_encoded_content_type = {"Content-Type": "application/x-www-form-urlencoded"}
    token_invalid_url = "https://auth.example.com/oidc/invalid/token"
    token_invalid_response = {"something": "else"}

    httpx_mock.add_response(
        url=token_invalid_url,
        method="post",
        headers=form_encoded_content_type,
        json=token_invalid_response,
    )
    # invalid response
    auth = oidc.OIDCClientCredentials(
        token_url=token_invalid_url, client_id="abc", client_secret="xyz"
    )
    oidc_client._auth = auth
    with pytest.raises(oidc.OIDCAuthenticationError) as exc:
        await oidc_client._fetch_token()
    assert "Authentication server did not provide a token" in str(exc.value)


@pytest.mark.asyncio
@patch("mobster.cmd.upload.oidc.OIDCClientCredentialsClient._fetch_token")
async def test__request(
    mock_fetch_token: AsyncMock,
    httpx_mock: HTTPXMock,
    oidc_client: OIDCClientCredentialsClient,
) -> None:
    httpx_mock.add_response(
        url=f"{BASE_URL}hello",
        method="put",
        headers=AUTHORIZATION_HEADER,
        status_code=200,
        text="Hello, world!",
    )

    resp = await oidc_client._request(
        "put",
        "hello",
        headers={"header": "test"},
        content='{"file": ""}',
        params=None,
    )
    assert resp is not None
    assert resp.text == "Hello, world!"
    mock_fetch_token.assert_awaited_once()


@pytest.mark.asyncio
@patch("mobster.cmd.upload.oidc.OIDCClientCredentialsClient._fetch_token")
async def test__request_not_on_force_list(
    mock_fetch_token: AsyncMock,
    httpx_mock: HTTPXMock,
    oidc_client: OIDCClientCredentialsClient,
) -> None:
    httpx_mock.add_response(
        url=f"{BASE_URL}hello",
        method="put",
        headers=AUTHORIZATION_HEADER,
        status_code=403,
    )
    resp = await oidc_client._request(
        "put",
        "hello",
        headers={"header": "test"},
        content='{"file": ""}',
        params=None,
    )
    mock_fetch_token.assert_awaited_once()
    assert resp is not None
    assert resp.status_code == 403
    assert len(httpx_mock.get_requests()) == 1


@pytest.mark.asyncio
@patch("mobster.cmd.upload.oidc.OIDCClientCredentialsClient._fetch_token")
async def test__request_fail_with_retry_on_status(
    mock_fetch_token: AsyncMock,
    httpx_mock: HTTPXMock,
    oidc_client: OIDCClientCredentialsClient,
) -> None:
    retries = 2
    for _ in range(retries):
        httpx_mock.add_response(
            url=f"{BASE_URL}hello",
            method="put",
            headers=AUTHORIZATION_HEADER,
            status_code=500,
        )
    with pytest.raises(RetryExhaustedException):
        await oidc_client._request(
            "put",
            "hello",
            headers={"header": "test"},
            content='{"file": ""}',
            params=None,
            retries=retries,
            backoff_factor=0.1,
        )
    mock_fetch_token.assert_awaited()
    assert len(httpx_mock.get_requests()) == retries


@pytest.mark.asyncio
@patch("httpx.AsyncClient.request")
@patch("mobster.cmd.upload.oidc.OIDCClientCredentialsClient._fetch_token")
async def test__request_fail_on_request(
    mock_fetch_token: AsyncMock,
    mock_httpx_request: AsyncMock,
    oidc_client: OIDCClientCredentialsClient,
) -> None:
    mock_httpx_request.side_effect = httpx.RequestError("Request failed")

    with pytest.raises(RetryExhaustedException):
        await oidc_client._request(
            "post",
            "hello",
            headers={"header": "test"},
            content='{"file": ""}',
            params=None,
            retries=2,
            backoff_factor=0.1,
        )
    mock_fetch_token.assert_awaited()
    assert mock_httpx_request.await_count == 2


@pytest.mark.asyncio
@patch("httpx.AsyncClient.request")
@patch("mobster.cmd.upload.oidc.OIDCClientCredentialsClient._fetch_token")
async def test__request_fail_on_error(
    mock_fetch_token: AsyncMock,
    mock_httpx_request: AsyncMock,
    oidc_client: OIDCClientCredentialsClient,
) -> None:
    mock_httpx_request.side_effect = ZeroDivisionError("Error")

    with pytest.raises(ZeroDivisionError):
        await oidc_client._request(
            "post",
            "hello",
            headers={"header": "test"},
            content='{"file": ""}',
            params=None,
        )
    mock_fetch_token.assert_awaited_once()
    # no retries on unexpected errors
    assert mock_httpx_request.await_count == 1


@pytest.mark.asyncio
async def test_put(oidc_client: OIDCClientCredentialsClient) -> None:
    with patch.object(
        oidc_client,
        "_request",
        new_callable=AsyncMock,
        return_value=MagicMock(),
    ) as mock_request:
        await oidc_client.put("foo", '{"file": ""}', headers={"header": "test"})

        mock_request.assert_awaited_once_with(
            "put",
            "foo",
            content='{"file": ""}',
            headers={"header": "test"},
            params=None,
            retries=10,
        )


@pytest.mark.asyncio
async def test_post(oidc_client: OIDCClientCredentialsClient) -> None:
    with patch.object(
        oidc_client,
        "_request",
        new_callable=AsyncMock,
        return_value=MagicMock(),
    ) as mock_request:
        await oidc_client.post("foo", '{"file": ""}', headers={"header": "test"})

        mock_request.assert_awaited_once_with(
            "post",
            "foo",
            content='{"file": ""}',
            headers={"header": "test"},
            params=None,
            retries=10,
        )


@pytest.mark.asyncio
async def test__fetch_token_disabled_auth(
    oidc_client: OIDCClientCredentialsClient,
) -> None:
    """
    Test that _fetch_token() returns early when auth is None.
    """
    oidc_client._auth = None
    await oidc_client._fetch_token()  # Should not raise any exception


@pytest.mark.asyncio
async def test__ensure_valid_token_disabled_auth(
    oidc_client: OIDCClientCredentialsClient,
) -> None:
    """
    Test that _ensure_valid_token() returns early when auth is None.
    """
    oidc_client._auth = None
    # Should not raise any exception
    await oidc_client._ensure_valid_token()


@pytest.mark.asyncio
async def test_get(oidc_client: OIDCClientCredentialsClient) -> None:
    with patch.object(
        oidc_client,
        "_request",
        new_callable=AsyncMock,
        return_value=MagicMock(),
    ) as mock_request:
        await oidc_client.get("foo", headers={"header": "test"})

        mock_request.assert_awaited_once_with(
            "get",
            "foo",
            headers={"header": "test"},
            params=None,
            retries=10,
        )


@pytest.mark.asyncio
async def test_delete(oidc_client: OIDCClientCredentialsClient) -> None:
    with patch.object(
        oidc_client,
        "_request",
        new_callable=AsyncMock,
        return_value=MagicMock(),
    ) as mock_request:
        await oidc_client.delete("foo", headers={"header": "test"})

        mock_request.assert_awaited_once_with(
            "delete",
            "foo",
            headers={"header": "test"},
            params=None,
            retries=10,
        )


@pytest.mark.asyncio
@patch("mobster.cmd.upload.oidc.OIDCClientCredentialsClient._ensure_valid_token")
async def test_stream(
    mock_ensure_valid_token: AsyncMock,
    oidc_client: OIDCClientCredentialsClient,
    httpx_mock: HTTPXMock,
) -> None:
    httpx_mock.add_response(stream=IteratorStream([b"chunk1", b"chunk2"]))

    result_chunks = []
    async for chunk in oidc_client.stream(
        "GET",
        "api/v2/sbom/123/download",
        headers={"custom-header": "value"},
        params={"param1": "value1"},
    ):
        result_chunks.append(chunk)

    mock_ensure_valid_token.assert_awaited_once()
    assert result_chunks == [b"chunk1", b"chunk2"]


def test__assert_client_raises_when_client_is_none() -> None:
    """
    Test that _assert_client() raises RuntimeError when client is None.
    """
    client = OIDCClientCredentialsClient(BASE_URL, None)

    with pytest.raises(
        RuntimeError,
        match="The client was not initialized using an async context manager",
    ):
        client._assert_client()
