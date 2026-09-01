"""Tests for Data Center OAuth access-token validation."""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from mcp_atlassian.utils.token_verifier import AtlassianDataCenterTokenVerifier


class FakeAsyncClient:
    """Minimal async HTTP client that records validation requests."""

    responses: list[httpx.Response] = []
    requests: list[tuple[str, dict[str, str]]] = []

    def __init__(self, **kwargs: Any) -> None:
        self.kwargs = kwargs

    async def __aenter__(self) -> FakeAsyncClient:
        return self

    async def __aexit__(self, *args: object) -> None:
        return None

    async def get(self, url: str, headers: dict[str, str]) -> httpx.Response:
        self.requests.append((url, headers))
        return self.responses.pop(0)


@pytest.fixture(autouse=True)
def reset_fake_client(monkeypatch):
    FakeAsyncClient.responses = []
    FakeAsyncClient.requests = []
    monkeypatch.setattr(httpx, "AsyncClient", FakeAsyncClient)


@pytest.mark.parametrize(
    ("product", "expected_path"),
    [
        ("jira", "/rest/api/2/myself"),
        ("confluence", "/rest/api/user/current"),
        ("bitbucket", "/rest/api/1.0/projects?limit=1"),
    ],
)
@pytest.mark.asyncio
async def test_data_center_token_is_validated_by_product(product, expected_path):
    FakeAsyncClient.responses = [
        httpx.Response(
            200,
            json={"authenticated": True},
            request=httpx.Request("GET", f"https://dc.example.com{expected_path}"),
        )
    ]
    verifier = AtlassianDataCenterTokenVerifier(
        instance_url="https://dc.example.com",
        product=product,
        required_scopes=["READ"],
    )

    access_token = await verifier.verify_token("upstream-token")

    assert access_token is not None
    assert access_token.token == "upstream-token"
    assert access_token.scopes == ["READ"]
    assert access_token.expires_at is None
    assert access_token.claims == {"base_url": "https://dc.example.com"}
    assert FakeAsyncClient.requests == [
        (
            f"https://dc.example.com{expected_path}",
            {
                "Authorization": "Bearer upstream-token",
                "Accept": "application/json",
            },
        )
    ]


@pytest.mark.asyncio
async def test_data_center_token_rejects_unauthorized_response():
    FakeAsyncClient.responses = [
        httpx.Response(
            401,
            json={"error": "unauthorized"},
            request=httpx.Request("GET", "https://jira.example.com/rest/api/2/myself"),
        )
    ]
    verifier = AtlassianDataCenterTokenVerifier(
        instance_url="https://jira.example.com",
        product="jira",
    )

    assert await verifier.verify_token("invalid-token") is None


@pytest.mark.asyncio
async def test_successful_validation_is_cached():
    FakeAsyncClient.responses = [
        httpx.Response(
            200,
            json={"name": "user"},
            request=httpx.Request("GET", "https://jira.example.com/rest/api/2/myself"),
        )
    ]
    verifier = AtlassianDataCenterTokenVerifier(
        instance_url="https://jira.example.com",
        product="jira",
    )

    first = await verifier.verify_token("cached-token")
    second = await verifier.verify_token("cached-token")

    assert first is second
    assert len(FakeAsyncClient.requests) == 1


@pytest.mark.asyncio
async def test_validation_cache_can_be_disabled():
    validation_url = "https://jira.example.com/rest/api/2/myself"
    FakeAsyncClient.responses = [
        httpx.Response(
            200,
            json={"name": "user"},
            request=httpx.Request("GET", validation_url),
        ),
        httpx.Response(
            200,
            json={"name": "user"},
            request=httpx.Request("GET", validation_url),
        ),
    ]
    verifier = AtlassianDataCenterTokenVerifier(
        instance_url="https://jira.example.com",
        product="jira",
        cache_ttl_seconds=0,
    )

    assert await verifier.verify_token("uncached-token") is not None
    assert await verifier.verify_token("uncached-token") is not None
    assert len(FakeAsyncClient.requests) == 2


def test_data_center_verifier_rejects_negative_cache_ttl():
    with pytest.raises(ValueError, match="cache TTL cannot be negative"):
        AtlassianDataCenterTokenVerifier(
            instance_url="https://jira.example.com",
            product="jira",
            cache_ttl_seconds=-1,
        )


def test_data_center_verifier_rejects_cloud_url():
    with pytest.raises(ValueError, match="does not support Cloud URLs"):
        AtlassianDataCenterTokenVerifier(
            instance_url="https://acme.atlassian.net",
            product="jira",
        )
