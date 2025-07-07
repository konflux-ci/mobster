from typing import Any
from unittest.mock import AsyncMock, MagicMock, Mock, patch

import httpx
import pytest

from mobster.cmd.upload import oidc
from mobster.cmd.upload.oidc import RetryExhaustedException

AUTHORIZATION_HEADER = {"Authorization": "Bearer asdfghjkl"}


def _get_valid_client() -> oidc.OIDCClientCredentialsClient:
    token_url = "https://auth.example.com/oidc/token"
    proxy = "http://proxy.example.com:3128"
    auth = oidc.OIDCClientCredentials(
        token_url=token_url, client_id="abc", client_secret="xyz"
    )
    oidc_client = oidc.OIDCClientCredentialsClient(
        "https://api.example.com/v1/", auth, proxy=proxy
    )
    return oidc_client


@pytest.mark.asyncio
async def test__fetch_token_success(httpx_mock: Any) -> None:
    form_encoded_content_type = {"Content-Type": "application/x-www-form-urlencoded"}
    token_url = "https://auth.example.com/oidc/token"
    token_response = {"access_token": "asdfghjkl", "expires_in": 600}

    httpx_mock.add_response(
        url=token_url,
        method="post",
        headers=form_encoded_content_type,
        json=token_response,
    )

    client = _get_valid_client()
    await client._fetch_token()
    assert client._token == "asdfghjkl"
    assert client._token_expiration > 0


@pytest.mark.asyncio
@patch("mobster.cmd.upload.oidc.LOGGER")
@patch("httpx.AsyncClient.post")
async def test__fetch_token_unable(
    mock_post: AsyncMock, mock_logger: MagicMock
) -> None:
    auth = oidc.OIDCClientCredentials(
        token_url="foo", client_id="abc", client_secret="xyz"
    )
    client = oidc.OIDCClientCredentialsClient("bar", auth)
    request = httpx.Request("POST", "foo")
    mock_post.return_value = httpx.Response(500, request=request)

    with pytest.raises(httpx.HTTPStatusError):
        await client._fetch_token()

    mock_logger.error.assert_called_once_with(
        "Unable to fetch auth token. [%s] %s", 500, ""
    )


@pytest.mark.asyncio
async def test__fetch_token_failed(httpx_mock: Any) -> None:
    form_encoded_content_type = {"Content-Type": "application/x-www-form-urlencoded"}
    token_error_url = "https://auth.example.com/oidc/fail/token"
    token_error_response = {
        "error": "unauthorized_client",
        "error_description": "Invalid client secret",
    }
    token_invalid_url = "https://auth.example.com/oidc/invalid/token"
    token_invalid_response = {"something": "else"}

    httpx_mock.add_response(
        url=token_error_url,
        method="post",
        headers=form_encoded_content_type,
        json=token_error_response,
    )
    httpx_mock.add_response(
        url=token_invalid_url,
        method="post",
        headers=form_encoded_content_type,
        json=token_invalid_response,
    )
    # error response
    auth = oidc.OIDCClientCredentials(
        token_url=token_error_url, client_id="abc", client_secret="xyz"
    )
    error_client = oidc.OIDCClientCredentialsClient("https://api.example.com/v1/", auth)

    with pytest.raises(oidc.OIDCAuthenticationError) as exc:
        await error_client._fetch_token()
    assert "unauthorized_client" in str(exc.value)

    # invalid response
    auth = oidc.OIDCClientCredentials(
        token_url=token_invalid_url, client_id="abc", client_secret="xyz"
    )
    error_client = oidc.OIDCClientCredentialsClient("https://api.example.com/v1/", auth)
    with pytest.raises(oidc.OIDCAuthenticationError) as exc:
        await error_client._fetch_token()
    assert "Authentication server did not provide a token" in str(exc.value)


@pytest.mark.asyncio
@patch("mobster.cmd.upload.oidc.OIDCClientCredentialsClient._fetch_token")
async def test__request(mock_fetch_token: AsyncMock, httpx_mock: Any) -> None:
    client = _get_valid_client()

    httpx_mock.add_response(
        url="https://api.example.com/v1/hello",
        method="put",
        headers=AUTHORIZATION_HEADER,
        status_code=200,
        text="Hello, world!",
    )

    resp = await client._request(
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
    mock_fetch_token: AsyncMock, httpx_mock: Any
) -> None:
    client = _get_valid_client()

    httpx_mock.add_response(
        url="https://api.example.com/v1/hello",
        method="put",
        headers=AUTHORIZATION_HEADER,
        status_code=403,
    )
    resp = await client._request(
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
    mock_fetch_token: AsyncMock, httpx_mock: Any
) -> None:
    client = _get_valid_client()

    retries = 2
    for _ in range(retries):
        httpx_mock.add_response(
            url="https://api.example.com/v1/hello",
            method="put",
            headers=AUTHORIZATION_HEADER,
            status_code=500,
        )
    with pytest.raises(RetryExhaustedException):
        await client._request(
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
) -> None:
    client = _get_valid_client()
    mock_httpx_request.side_effect = httpx.RequestError("Request failed")

    with pytest.raises(RetryExhaustedException):
        await client._request(
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
) -> None:
    client = _get_valid_client()
    mock_httpx_request.side_effect = ZeroDivisionError("Error")

    with pytest.raises(ZeroDivisionError):
        await client._request(
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
async def test_put() -> None:
    client = _get_valid_client()

    with patch.object(
        client,
        "_request",
        new_callable=AsyncMock,
        return_value=MagicMock(),
    ) as mock_request:
        await client.put("foo", '{"file": ""}', headers={"header": "test"})

        mock_request.assert_awaited_once_with(
            "put",
            "foo",
            content='{"file": ""}',
            headers={"header": "test"},
            params=None,
        )


@pytest.mark.asyncio
async def test_post() -> None:
    client = _get_valid_client()

    with patch.object(
        client,
        "_request",
        new_callable=AsyncMock,
        return_value=MagicMock(),
    ) as mock_request:
        await client.post("foo", '{"file": ""}', headers={"header": "test"})

        mock_request.assert_awaited_once_with(
            "post",
            "foo",
            content='{"file": ""}',
            headers={"header": "test"},
            params=None,
        )


@pytest.mark.asyncio
async def test__fetch_token_disabled_auth() -> None:
    """
    Test that _fetch_token() returns early when auth is None.
    """
    client = oidc.OIDCClientCredentialsClient("https://api.example.com", auth=None)
    await client._fetch_token()  # Should not raise any exception


@pytest.mark.asyncio
async def test__ensure_valid_token_disabled_auth() -> None:
    """
    Test that _ensure_valid_token() returns early when auth is None.
    """
    client = oidc.OIDCClientCredentialsClient("https://api.example.com", auth=None)

    # Should not raise any exception
    await client._ensure_valid_token(None)  # type: ignore


@pytest.mark.asyncio
async def test_get() -> None:
    client = _get_valid_client()

    with patch.object(
        client,
        "_request",
        new_callable=AsyncMock,
        return_value=MagicMock(),
    ) as mock_request:
        await client.get("foo", headers={"header": "test"})

        mock_request.assert_awaited_once_with(
            "get",
            "foo",
            headers={"header": "test"},
            params=None,
        )


@pytest.mark.asyncio
async def test_delete() -> None:
    client = _get_valid_client()

    with patch.object(
        client,
        "_request",
        new_callable=AsyncMock,
        return_value=MagicMock(),
    ) as mock_request:
        await client.delete("foo", headers={"header": "test"})

        mock_request.assert_awaited_once_with(
            "delete",
            "foo",
            headers={"header": "test"},
            params=None,
        )


@pytest.mark.asyncio
@patch("mobster.cmd.upload.oidc.OIDCClientCredentialsClient._ensure_valid_token")
@patch("httpx.AsyncClient")
async def test_stream(
    mock_async_client_class: MagicMock, mock_ensure_valid_token: AsyncMock
) -> None:
    client = _get_valid_client()

    # Mock the httpx.AsyncClient instance
    mock_client_instance = MagicMock()
    mock_client_instance.headers = {}

    # Mock the response object
    mock_response = AsyncMock()
    mock_response.raise_for_status = Mock()

    # Mock aiter_bytes to return an async iterator
    async def mock_aiter_bytes() -> Any:
        for chunk in [b"chunk1", b"chunk2"]:
            yield chunk

    mock_response.aiter_bytes = mock_aiter_bytes

    # Mock the stream context manager
    mock_stream_context = AsyncMock()
    mock_stream_context.__aenter__.return_value = mock_response
    mock_stream_context.__aexit__.return_value = None
    mock_client_instance.stream.return_value = mock_stream_context
    mock_async_client_class.return_value = mock_client_instance

    # Call the stream method and collect results
    result_chunks = []
    async for chunk in client.stream(
        "GET",
        "api/v2/sbom/123/download",
        headers={"custom-header": "value"},
        params={"param1": "value1"},
    ):
        result_chunks.append(chunk)

    # Verify httpx.AsyncClient was created with correct parameters
    mock_async_client_class.assert_called_once_with(proxy=client._proxies, timeout=60)

    # Verify token was ensured
    mock_ensure_valid_token.assert_awaited_once_with(mock_client_instance)

    # Verify the stream method was called with correct parameters
    mock_client_instance.stream.assert_called_once_with(
        "GET",
        "https://api.example.com/v1/api/v2/sbom/123/download",
        params={"param1": "value1"},
    )

    # Verify response status was checked
    mock_response.raise_for_status.assert_called_once()

    # Verify we got the expected chunks
    assert result_chunks == [b"chunk1", b"chunk2"]
