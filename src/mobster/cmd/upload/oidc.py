"""
OIDC client wrapped around httpx
"""

import asyncio
import logging
import time
from asyncio import sleep
from collections.abc import AsyncGenerator
from dataclasses import dataclass
from typing import Any
from urllib.parse import urljoin

import httpx
from httpx import Proxy, Timeout

LOGGER = logging.getLogger(__name__)

DEFAULT_TIMEOUT_SECONDS = 60
DEFAULT_CONNECT_TIMEOUT_SECONDS = 5
TOKEN_EXPIRY_BUFFER_SECONDS = 15


class OIDCAuthenticationError(Exception):
    """
    Raised when token refresh fails
    """


class RetryExhaustedException(Exception):
    """
    Raised when all the retries on transient errors are exhausted
    """


@dataclass
class OIDCClientCredentials:
    """
    Container class for the authentication info necessary for the OIDC
    client credential flow

    Fields:
        token_url (str): The OAuth2/OIDC token endpoint. Can usually be obtained
            by fetching ${oidc_root}/.well-known/openid-configuration and extracting
            the token_endpoint field
        client_id (str): Client ID to be used to obtain a JWT token
        client_secret (str): Client secret to be used to obtain a JWT token
    """

    token_url: str
    client_id: str
    client_secret: str


class OIDCClientCredentialsClient:  # pylint: disable=too-few-public-methods
    """
    Generic OIDC client credential client

    Transparently handles the OIDC client credential flow required for authentication,
    including automatic token renewal. Uses connection pooling for improved performance.

    WARNING: this client should not be initialized directly, but using an
    "async with" statement. Only that guarantees proper clean up of the
    internal HTTPX client used.

    Example:
        async with OIDCClientCredentialsClient(
            base_url="https://api.example.com",
            auth=OIDCClientCredentials(
                token_url="https://auth.example.com/token",
                client_id="your-client-id",
                client_secret="your-client-secret"
            )
        ) as client:
            response = await client.get("/api/endpoint")
    """

    def __init__(
        self,
        base_url: str,
        auth: OIDCClientCredentials | None,
        proxy: str | None = None,
    ):
        """
        Create a new client.


        Args:
            base_url (str): Base url for the API server
            auth (OIDCClientCredentials | None): Authentication info. "None"
                disables authentication.
            proxy (Optional[str]): Proxy to use to talk to the API server
                Defaults to None, which means no proxy.
        """
        self.client: httpx.AsyncClient | None = None
        self._proxies = Proxy(proxy) if proxy else None
        self._base_url = base_url
        self._auth = auth
        self._token = ""
        self._token_expiration = 0
        self._token_mutex = asyncio.Lock()

    async def __aenter__(self) -> "OIDCClientCredentialsClient":
        """
        Initialize the HTTP client for connection pooling.

        Returns:
            Self instance with initialized HTTP client

        Raises:
            RuntimeError: If client initialization fails
        """
        try:
            self.client = httpx.AsyncClient(
                proxy=self._proxies,
                timeout=Timeout(
                    DEFAULT_TIMEOUT_SECONDS, connect=DEFAULT_CONNECT_TIMEOUT_SECONDS
                ),
            )
            return self
        except Exception as exc:
            raise RuntimeError(f"Failed to initialize HTTP client: {exc}") from exc

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:  # type: ignore
        """
        Clean up the HTTP client and close connections.

        Args:
            exc_type: Exception type if an exception occurred
            exc_val: Exception value if an exception occurred
            exc_tb: Exception traceback if an exception occurred
        """
        if self.client:
            await self.client.aclose()
            self.client = None

    def _assert_client(self) -> None:
        """
        Raises a RuntimeError if the client was not initialized using an async
        context manager.
        Raises:
            RuntimeError if the client attribute is None
        """
        if self.client is None:
            raise RuntimeError(
                "The client was not initialized using an async context manager."
            )

    def _token_expired(self) -> bool:
        """
        Check if the current token should be renewed

        Returns:
            bool: True if the current token needs to be renewed
        """
        # Avoid reusing a token which is too close to its expiration by considering it
        # expired if it has less than TOKEN_EXPIRY_BUFFER_SECONDS of validity left
        return time.time() > self._token_expiration - TOKEN_EXPIRY_BUFFER_SECONDS

    # pylint: disable=missing-timeout
    async def _fetch_token(self) -> None:
        """
        Retrieve a new token using the OAuth2/OID client credential flow

        Raises:
            OIDCAuthenticationError: If the token renewal failed
        """
        if self._auth is None:
            return

        # See https://www.oauth.com/oauth2-servers/access-tokens/client-credentials/
        # and https://www.ietf.org/rfc/rfc6749.txt section 4.4 and 2.3.1
        LOGGER.debug("Fetching new token from %s", self._auth.token_url)

        self._assert_client()
        resp = await self.client.post(  # type:ignore[union-attr]
            self._auth.token_url,
            data={
                "grant_type": "client_credentials",
                "client_id": self._auth.client_id,
                "client_secret": self._auth.client_secret,
            },
        )
        if not resp.is_success:
            LOGGER.error(
                "Unable to fetch auth token. [%s] %s", resp.status_code, resp.text
            )
            resp.raise_for_status()
        token = resp.json()
        if "access_token" not in token:
            if "error" in token:
                error_type = token["error"]
                error_description = token.get("error_description", "")
                error_msg = f"Authentication failed: {error_type} {error_description}"
            else:
                error_msg = "Authentication server did not provide a token"
            raise OIDCAuthenticationError(error_msg)
        self._token = token["access_token"]
        self._token_expiration = int(token.get("expires_in", 300) + time.time())
        LOGGER.debug("Token will expire in %s seconds", token.get("expires_in"))

    async def _ensure_valid_token(self) -> None:
        """
        Check if we have a valid token and if not, renew it
        Always store the token in client header to ensure
        all active clients use valid token
        """
        if self._auth is None:
            return

        async with self._token_mutex:
            if self._token_expired():
                await self._fetch_token()
            self._assert_client()
            self.client.headers["Authorization"] = (  # type:ignore[union-attr]
                "Bearer " + self._token
            )

    # Mypy doesn't recognize that either a value is returned
    # or an exception is raised in all cases
    async def _request(  # type: ignore[return]
        # pylint: disable=too-many-arguments
        self,
        method: str,
        url: str,
        *,
        headers: Any = None,
        content: Any = None,
        params: Any = None,
        retries: int = 10,
        backoff_factor: float = 1,
        status_forcelist: list[int] | None = None,
    ) -> httpx.Response:
        """
        Perform an HTTP request.
        The default values provide exponential backoff for a max wait of ~8.5 mins
        with forcelist of statuses that should be retried.

        Args:
            method: HTTP method (GET, POST, ...)
            url: Relative URL of the endpoint. Will be combined with the base URL.
            headers: headers to add to the request. Defaults to None.
            content: data to send in the request. Defaults to None.
            params: Parameters to add to the request. Defaults to None.
            retries: Maximum number of retries. Default to 10.
            backoff_factor: A backoff factor to apply between attempts.
                Default to 1.
            status_forcelist: A set of HTTP status codes that we should
                force a retry on.

        Returns:
            httpx.Response: The response returned by the server

        Raises:
            httpx.RequestError: If the request failed
            httpx.HTTPStatusError: If the server returned an unexpected status code
            RetryExhaustedException: If even after retries, the request fails with
                transient error
        """
        effective_url = urljoin(self._base_url, url)
        LOGGER.debug("HTTP %s %s, retrying %d times", method, effective_url, retries)

        if status_forcelist is None:
            status_forcelist = [408, 429, 500, 502, 503, 504]

        self._assert_client()
        for attempt in range(retries):
            await self._ensure_valid_token()
            try:
                resp = await self.client.request(  # type:ignore[union-attr]
                    method,
                    effective_url,
                    content=content,
                    params=params,
                    headers=headers,
                )
                if resp.status_code in status_forcelist:
                    raise httpx.HTTPStatusError(
                        message=f"Retry-able HTTP status code: {resp.status_code}",
                        request=resp.request,
                        response=resp,
                    )
                LOGGER.debug(
                    "HTTP request [%s]: status code: %s",
                    method,
                    effective_url,
                    extra={"mobster_httpx_request_response_code": resp.status_code},
                )
                return resp
            except (httpx.RequestError, httpx.HTTPStatusError) as exc:
                # retry on problems with request and forcelist status codes
                if attempt < retries - 1:
                    delta_to_next_att = backoff_factor * (2**attempt)
                    extra_info = {
                        "mobster_httpx_request_params": params,
                        "mobster_httpx_request_headers": headers,
                    }
                    if isinstance(exc, httpx.HTTPStatusError):
                        extra_info["mobster_httpx_request_response_code"] = (
                            exc.response.status_code
                        )

                    LOGGER.exception(
                        "HTTP %s request to %s failed: %s. "
                        "Next attempt in %f seconds, remaining retries: %d",
                        method,
                        effective_url,
                        exc,
                        delta_to_next_att,
                        retries - attempt,
                        extra=extra_info,
                    )
                    await sleep(delta_to_next_att)
                else:
                    raise RetryExhaustedException(
                        f"Retries exhausted for "
                        f"HTTP {method} request for {effective_url}"
                    ) from exc
            except Exception as exc:  # pylint: disable=broad-except
                # capture broad exception and raise it without retrying
                LOGGER.exception("HTTP %s request failed: %s", method, exc)
                raise

    async def get(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        params: dict[str, Any] | None = None,
        retries: int = 10,
    ) -> httpx.Response:
        """
        Issue a JSON GET request

        Args:
            url: endpoint to call
            headers: headers to add to the request.
                Defaults to None.
            params: Parameters to add to the request.
                Defaults to None.
            retries: Maximum number of retries. Default to 10.

        Returns:
            Any: JSON response from PUT request
        """
        response = await self._request(
            "get", url, headers=headers, params=params, retries=retries
        )
        response.raise_for_status()
        return response

    async def put(
        # pylint: disable=too-many-arguments
        self,
        url: str,
        content: Any,
        *,
        headers: Any = None,
        params: Any = None,
        retries: int = 10,
    ) -> httpx.Response:
        """
        Issue a JSON PUT request

        Args:
            url: endpoint to call
            content: data to send in request body
            headers: headers to add to the request.
                Defaults to None.
            params: Parameters to add to the request.
                Defaults to None.
            retries: Maximum number of retries. Default to 10.

        Returns:
            Any: JSON response from PUT request
        """
        response = await self._request(
            "put", url, content=content, headers=headers, params=params, retries=retries
        )
        response.raise_for_status()
        return response

    async def post(
        # pylint: disable=too-many-arguments
        self,
        url: str,
        content: Any,
        *,
        headers: dict[str, str] | None = None,
        params: dict[str, Any] | None = None,
        retries: int = 10,
    ) -> httpx.Response:
        """
        Issue a JSON POST request

        Args:
            url: endpoint to call
            content: data to send in request body
            headers: headers to add to the request.
                Defaults to None.
            params: Parameters to add to the request.
                Defaults to None.
            retries: Maximum number of retries. Default to 10.


        Returns:
            Any: JSON response from POST request
        """
        response = await self._request(
            "post",
            url,
            content=content,
            headers=headers,
            params=params,
            retries=retries,
        )
        response.raise_for_status()
        return response

    async def delete(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        params: dict[str, Any] | None = None,
        retries: int = 10,
    ) -> httpx.Response:
        """
        Issue a JSON POST request

        Args:
            url: endpoint to call
            headers: headers to add to the request.
                Defaults to None.
            params: Parameters to add to the request.
                Defaults to None.
            retries: Maximum number of retries. Default to 10.

        Returns:
            Any: JSON response from POST request
        """
        response = await self._request(
            "delete", url, headers=headers, params=params, retries=retries
        )
        response.raise_for_status()
        return response

    async def stream(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        params: dict[str, Any] | None = None,
    ) -> AsyncGenerator[
        bytes,
        None,
    ]:
        """
        Create a streaming response that yields byte chunks directly

        Args:
            method (str): HTTP method (GET, POST, ...)
            url (str): endpoint to call
            headers(dict[str, Any] | None): headers to add to the request.
            Defaults to None.
            params (dict[str, Any] | None, optional): Parameters to add to the request.
            Defaults to None.

        Yields:
            bytes: Chunks of response data
        """
        effective_url = urljoin(self._base_url, url)
        LOGGER.debug("HTTP %s %s (streaming)", method, effective_url)

        await self._ensure_valid_token()

        self._assert_client()
        async with self.client.stream(  # type:ignore[union-attr]
            method, effective_url, params=params, headers=headers
        ) as response:
            response.raise_for_status()
            async for chunk in response.aiter_bytes():
                yield chunk
