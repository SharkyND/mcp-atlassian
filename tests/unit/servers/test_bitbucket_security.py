"""Fork-only Bitbucket paths must share the upstream security boundaries."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest
from fastmcp.exceptions import NotFoundError
from starlette.requests import Request

from mcp_atlassian.bitbucket.cloud import BitbucketCloudClient
from mcp_atlassian.bitbucket.config import BitbucketConfig
from mcp_atlassian.servers import dependencies, main
from mcp_atlassian.servers.context import MainAppContext
from mcp_atlassian.utils.urls import is_atlassian_cloud_url


def request(token: str | None = None) -> Request:
    result = Request(
        {
            "type": "http",
            "headers": [],
            "state": {},
            "path": "/mcp",
            "method": "POST",
            "scheme": "https",
            "query_string": b"",
            "server": ("synthetic.invalid", 443),
        }
    )
    if token:
        result.state.user_atlassian_auth_type = "pat"
        result.state.atlassian_service_headers = {
            "X-Atlassian-Bitbucket-Personal-Token": token,
            "X-Atlassian-Bitbucket-Url": "https://bitbucket.synthetic.invalid",
        }
    return result


@pytest.mark.anyio
async def test_bitbucket_never_falls_back_to_operator_credentials_in_http(monkeypatch):
    config = BitbucketConfig(
        url="https://bitbucket.synthetic.invalid",
        auth_type="pat",
        personal_token="synthetic-operator",
    )
    context = SimpleNamespace(
        request_context=SimpleNamespace(
            lifespan_context={
                "app_lifespan_context": MainAppContext(full_bitbucket_config=config)
            }
        )
    )
    monkeypatch.delenv("ALLOW_GLOBAL_CRED_FALLBACK", raising=False)
    monkeypatch.setattr(dependencies, "get_http_request", lambda: request())
    factory = Mock()
    monkeypatch.setattr(dependencies, "BitbucketFetcher", factory)
    with pytest.raises(ValueError, match="unauthenticated request"):
        await dependencies.get_bitbucket_fetcher(context)
    factory.assert_not_called()


@pytest.mark.anyio
async def test_bitbucket_fetchers_and_headers_are_isolated_per_request(monkeypatch):
    first, second = request("synthetic-a"), request("synthetic-b")
    requests = iter([first, second])
    monkeypatch.setattr(dependencies, "get_http_request", lambda: next(requests))
    monkeypatch.setattr(dependencies, "_validation_cache", None)
    created = []

    def factory(config):
        fetcher = SimpleNamespace(
            config=config,
            bitbucket=SimpleNamespace(_session=SimpleNamespace(hooks={"response": []})),
            get_current_user_info=lambda: {"displayName": "synthetic"},
        )
        created.append(fetcher)
        return fetcher

    monkeypatch.setattr(dependencies, "BitbucketFetcher", factory)
    context = SimpleNamespace(request_context=SimpleNamespace(lifespan_context={}))
    a = await dependencies.get_bitbucket_fetcher(context)
    b = await dependencies.get_bitbucket_fetcher(context)
    assert a is not b
    assert a.config.personal_token == "synthetic-a"
    assert b.config.personal_token == "synthetic-b"
    assert first.state.bitbucket_fetcher is a
    assert second.state.bitbucket_fetcher is b
    assert a.bitbucket._session.hooks["response"]


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1:8080",
        "http://169.254.169.254/latest/meta-data",
        "http://localhost:8080",
        "http://internal\\@public.invalid/",
    ],
)
def test_bitbucket_header_urls_reject_internal_targets_before_auth(url):
    scope = {
        "type": "http",
        "path": "/mcp",
        "method": "POST",
        "state": {},
        "headers": [
            (b"x-atlassian-bitbucket-url", url.encode()),
            (b"x-atlassian-bitbucket-personal-token", b"synthetic"),
        ],
    }
    middleware = main.UserTokenMiddleware(AsyncMock(), main.main_mcp)
    middleware._process_authentication_headers(scope)
    assert scope["state"]["auth_validation_error"]
    assert "atlassian_service_headers" not in scope["state"]


@pytest.mark.parametrize(
    "url",
    [
        "https://other.invalid/2.0/repositories",
        "https://api.bitbucket.org/other",
        "//other.invalid/2.0/user",
        "https://user:password@api.bitbucket.org/2.0/user",
    ],
)
def test_bitbucket_pagination_cannot_send_credentials_outside_its_api(url):
    session = Mock()
    client = BitbucketCloudClient(session)
    with pytest.raises(ValueError, match="escaped"):
        client._request("GET", url)
    session.request.assert_not_called()


def test_bitbucket_cloud_detection_requires_exact_hosts():
    assert is_atlassian_cloud_url("https://api.bitbucket.org")
    assert not is_atlassian_cloud_url("https://evilbitbucket.org")
    assert not is_atlassian_cloud_url("https://bitbucket.org.attacker.invalid")


@pytest.mark.anyio
@pytest.mark.parametrize(
    "context",
    [
        {
            "read_only": True,
            "enabled_tools_filter": None,
            "enabled_toolsets_filter": {"bitbucket"},
        },
        {
            "read_only": False,
            "enabled_tools_filter": ["jira_get_issue"],
            "enabled_toolsets_filter": None,
        },
        {
            "read_only": False,
            "enabled_tools_filter": None,
            "enabled_toolsets_filter": {"jira_issues"},
        },
    ],
)
async def test_bitbucket_hidden_tools_cannot_be_called_by_name(monkeypatch, context):
    server = main.AtlassianMCP(name="synthetic")
    tool = Mock(tags={"bitbucket", "write", "toolset:bitbucket"})
    monkeypatch.setattr(server, "_tool_filter_context", lambda: context)
    monkeypatch.setattr(server, "get_tool", AsyncMock(return_value=tool))
    with pytest.raises(NotFoundError, match="Unknown tool"):
        await server._call_tool_mcp("bitbucket_create_branch", {})


@pytest.mark.anyio
async def test_authorized_dispatch_retains_usage_metrics_without_reading_body(
    monkeypatch,
):
    from fastmcp import FastMCP

    server = main.AtlassianMCP(name="synthetic")
    monkeypatch.setattr(server, "_tool_filter_context", lambda: None)
    monkeypatch.setattr(
        FastMCP, "_call_tool_mcp", AsyncMock(return_value={"synthetic": True})
    )
    metrics = Mock()
    monkeypatch.setattr(main, "get_metrics", lambda: metrics)
    monkeypatch.setattr(
        main,
        "get_http_request",
        lambda: SimpleNamespace(
            headers={
                "X-Atlassian-Username": "synthetic-user",
                "User-Agent": "Synthetic-MCP",
            }
        ),
    )
    assert await server._call_tool_mcp("bitbucket_get_file_content", {}) == {
        "synthetic": True
    }
    metrics.track_user_activity.assert_called_once_with(
        username="synthetic-user",
        user_agent="synthetic-mcp",
        activity_type="tool_usage",
    )
