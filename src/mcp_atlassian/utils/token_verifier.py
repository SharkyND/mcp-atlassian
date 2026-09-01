"""Token verifier used for Atlassian opaque OAuth access tokens."""

from __future__ import annotations

import hashlib
from typing import Literal

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

    async def _validate_data_center_token(self, token: str) -> bool:
        """Validate a token against a lightweight authenticated product API."""
        validation_paths = {
            "jira": "/rest/api/2/myself",
            "confluence": "/rest/api/user/current",
            "bitbucket": "/rest/api/1.0/projects?limit=1",
        }
        if self.product not in validation_paths:
            return False

        validation_url = (
            f"{self.instance_url.rstrip('/')}{validation_paths[self.product]}"
        )
        try:
            async with httpx.AsyncClient(
                timeout=20,
                follow_redirects=False,
            ) as client:
                response = await client.get(
                    validation_url,
                    headers={
                        "Authorization": f"Bearer {token}",
                        "Accept": "application/json",
                    },
                )
            response.raise_for_status()
            return isinstance(response.json(), dict)
        except (httpx.HTTPError, ValueError):
            return False

    async def verify_token(self, token: str) -> AccessToken | None:
        if not token:
            return None

        token_hash = hashlib.sha256(token.encode()).hexdigest()
        cached = self._cache.get(token_hash)
        if cached:
            return cached

        if not await self._validate_data_center_token(token):
            return None

        access_token = AccessToken(
            token=token,
            client_id="atlassian",
            scopes=self.required_scopes or [],
            claims={"base_url": self.instance_url.rstrip("/")},
        )
        self._cache[token_hash] = access_token
        return access_token
