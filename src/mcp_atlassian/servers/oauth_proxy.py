"""OAuth proxy extensions and configuration helpers."""

from __future__ import annotations

import ipaddress
import logging
import posixpath
from collections.abc import Iterable
from urllib.parse import unquote, urlsplit, urlunsplit

from fastmcp.server.auth.oauth_proxy import OAuthProxy
from mcp.server.auth.provider import (
    AuthorizationParams,
    AuthorizeError,
    OAuthClientInformationFull,
    RegistrationError,
)
from pydantic import AnyHttpUrl, AnyUrl

logger = logging.getLogger("mcp-atlassian.server.oauth_proxy")


def _normalize_list(values: Iterable[str] | None) -> list[str] | None:
    if values is None:
        return None
    return [value.strip() for value in values if value and value.strip()]


def _is_registered_redirect_uri(
    redirect_uri: str,
    registered_uris: Iterable[str | AnyUrl],
) -> bool:
    """Return whether a redirect URI exactly matches a registered URI."""
    return redirect_uri in {str(uri) for uri in registered_uris}


def parse_env_list(raw: str | None) -> list[str] | None:
    """Parse a comma- or whitespace-separated environment variable."""
    if raw is None:
        return None
    if not raw.strip():
        return []
    return [item for item in raw.replace(",", " ").split() if item]


def _redirect_target(uri: str) -> tuple[str, str, int | None, str] | None:
    """Return the normalized origin and route used by a redirect URI."""
    try:
        parsed = urlsplit(uri)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError:
        return None
    if not parsed.scheme or not hostname:
        return None

    scheme = parsed.scheme.lower()
    if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
        port = None

    hostname = hostname.rstrip(".").lower()
    try:
        hostname = hostname.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    try:
        hostname = str(ipaddress.ip_address(hostname))
    except ValueError:
        pass

    path = posixpath.normpath(unquote(parsed.path or "/"))
    if not path.startswith("/"):
        path = f"/{path}"
    return scheme, hostname, port, path.rstrip("/") or "/"


def _callback_uri(base_url: str, redirect_path: str) -> str:
    parsed = urlsplit(base_url)
    callback_path = f"{parsed.path.rstrip('/')}/{redirect_path.lstrip('/')}"
    return urlunsplit((parsed.scheme, parsed.netloc, callback_path, "", ""))


class HardenedOAuthProxy(OAuthProxy):
    """OAuth proxy with strict dynamic-registration grants and scopes."""

    def __init__(
        self,
        *,
        base_url: AnyHttpUrl | str,
        redirect_path: str | None = None,
        allowed_grant_types: list[str] | None = None,
        forced_scopes: list[str] | None = None,
        **kwargs: object,
    ) -> None:
        super().__init__(base_url=base_url, redirect_path=redirect_path, **kwargs)
        self._allowed_grant_types = _normalize_list(allowed_grant_types)
        self._forced_scopes = _normalize_list(forced_scopes)
        self._proxy_callback_target = _redirect_target(
            _callback_uri(str(self.base_url), self._redirect_path)
        )

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        """Load a client with validation bound to its registered callbacks."""
        client = await super().get_client(client_id)
        if client is not None and hasattr(client, "allowed_redirect_uri_patterns"):
            client.allowed_redirect_uri_patterns = [
                str(redirect_uri) for redirect_uri in client.redirect_uris or []
            ]
        return client

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        """Register a client after enforcing redirect, grant, and scope policy."""
        for redirect_uri in client_info.redirect_uris or []:
            if "*" in str(redirect_uri):
                raise RegistrationError(
                    "invalid_redirect_uri",
                    "Wildcard client redirect URIs are not allowed",
                )
            if _redirect_target(str(redirect_uri)) == self._proxy_callback_target:
                raise RegistrationError(
                    "invalid_redirect_uri",
                    "Client redirect URI must not target the OAuth proxy callback",
                )

        updates: dict[str, object] = {"response_types": ["code"]}
        if self._allowed_grant_types is not None:
            requested = list(client_info.grant_types or [])
            filtered = [
                grant for grant in requested if grant in self._allowed_grant_types
            ]
            updates["grant_types"] = filtered or list(self._allowed_grant_types)

        if self._forced_scopes is not None:
            forced_scope = " ".join(self._forced_scopes).strip()
            updates["scope"] = forced_scope or None

        await super().register_client(client_info.model_copy(update=updates))

    async def authorize(
        self,
        client: OAuthClientInformationFull,
        params: AuthorizationParams,
    ) -> str:
        """Authorize only callbacks registered to the requesting client."""
        if not _is_registered_redirect_uri(
            str(params.redirect_uri),
            client.redirect_uris or [],
        ):
            raise AuthorizeError(
                error="invalid_request",
                error_description="Redirect URI is not registered for this client",
            )
        return await super().authorize(client, params)


__all__ = ["HardenedOAuthProxy", "parse_env_list"]
