"""Token verifier used for Atlassian opaque OAuth access tokens."""

from __future__ import annotations

import hashlib
from typing import Any, Literal
from urllib.parse import quote

import httpx
from cachetools import TTLCache
from fastmcp.server.auth.auth import AccessToken, TokenVerifier

from mcp_atlassian.utils.urls import is_atlassian_cloud_url

DEFAULT_TOKEN_CACHE_TTL_SECONDS = 60


class AtlassianDataCenterTokenVerifier(TokenVerifier):
    """Validate Data Center OAuth tokens against their product instance."""

    def __init__(
        self,
        instance_url: str,
        product: Literal["jira", "confluence", "bitbucket"],
        required_scopes: list[str] | None = None,
        cache_ttl_seconds: int = DEFAULT_TOKEN_CACHE_TTL_SECONDS,
    ) -> None:
        """Initialize the token verifier.

        Args:
            instance_url: Base URL of the Atlassian Data Center product.
            product: Product whose authenticated endpoint validates the token.
            required_scopes: OAuth scopes forced during upstream authorization.
            cache_ttl_seconds: Seconds to cache successful validation results.

        Raises:
            ValueError: If the URL is an Atlassian Cloud URL or the cache TTL is
                negative.
        """
        super().__init__(required_scopes=required_scopes)
        if is_atlassian_cloud_url(instance_url):
            raise ValueError(
                "AtlassianDataCenterTokenVerifier does not support Cloud URLs"
            )
        if cache_ttl_seconds < 0:
            raise ValueError("Token validation cache TTL cannot be negative")
        self.instance_url = instance_url
        self.product = product
        self._cache: TTLCache[str, AccessToken] = TTLCache(
            maxsize=256,
            ttl=cache_ttl_seconds,
        )

    async def _get_json(self, token: str, path: str) -> dict[str, Any] | None:
        """Get a JSON object from an authenticated Data Center endpoint."""
        url = f"{self.instance_url.rstrip('/')}{path}"
        try:
            async with httpx.AsyncClient(
                timeout=20,
                follow_redirects=False,
            ) as client:
                response = await client.get(
                    url,
                    headers={
                        "Authorization": f"Bearer {token}",
                        "Accept": "application/json",
                    },
                )
            response.raise_for_status()
            data = response.json()
            return data if isinstance(data, dict) else None
        except (httpx.HTTPError, ValueError):
            return None

    async def get_user_info(self, token: str) -> dict[str, Any] | None:
        """Return the profile associated with a Data Center access token."""
        profile_paths = {
            "jira": "/rest/api/2/myself",
            "confluence": "/rest/api/user/current",
        }
        if self.product in profile_paths:
            return await self._get_json(token, profile_paths[self.product])
        if self.product != "bitbucket":
            return None

        whoami_url = f"{self.instance_url.rstrip('/')}/plugins/servlet/applinks/whoami"
        try:
            async with httpx.AsyncClient(
                timeout=20,
                follow_redirects=False,
            ) as client:
                response = await client.get(
                    whoami_url,
                    headers={
                        "Authorization": f"Bearer {token}",
                        "Accept": "text/plain",
                    },
                )
            response.raise_for_status()
            username = response.text.strip()
        except httpx.HTTPError:
            return None
        if not username or username.casefold() in {"anonymous", "null"}:
            return None
        user_page = await self._get_json(
            token,
            f"/rest/api/1.0/users?filter={quote(username, safe='')}",
        )
        users = user_page.get("values") if user_page else None
        if not isinstance(users, list):
            return None
        return next(
            (
                user
                for user in users
                if isinstance(user, dict) and user.get("name") == username
            ),
            None,
        )

    async def verify_token(self, token: str) -> AccessToken | None:
        if not token:
            return None

        token_hash = hashlib.sha256(token.encode()).hexdigest()
        cached = self._cache.get(token_hash)
        if cached:
            return cached

        user_info = await self.get_user_info(token)
        if user_info is None:
            return None

        claims: dict[str, Any] = {"base_url": self.instance_url.rstrip("/")}
        claims["user_info"] = user_info
        access_token = AccessToken(
            token=token,
            client_id="atlassian",
            scopes=self.required_scopes or [],
            claims=claims,
        )
        self._cache[token_hash] = access_token
        return access_token
