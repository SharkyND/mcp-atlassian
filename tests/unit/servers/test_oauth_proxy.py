"""Tests for browser-based OAuth proxy configuration."""

from __future__ import annotations

import pytest
from starlette.testclient import TestClient

from mcp_atlassian.servers.main import (
    AtlassianMCP,
    MultiProductDataCenterMCP,
    _build_auth_provider,
    _build_main_mcp,
)


def _set_jira_dc_oauth_env(monkeypatch) -> None:
    monkeypatch.setenv("ATLASSIAN_OAUTH_PROXY_ENABLE", "true")
    monkeypatch.setenv("JIRA_URL", "https://jira.example.com")
    monkeypatch.setenv("JIRA_OAUTH_CLIENT_ID", "client-id")
    monkeypatch.setenv("JIRA_OAUTH_CLIENT_SECRET", "client-secret")
    monkeypatch.setenv(
        "JIRA_OAUTH_REDIRECT_URI",
        "https://mcp.example.com/jira/oauth/callback",
    )
    monkeypatch.setenv("PUBLIC_BASE_URL", "https://mcp.example.com")
    monkeypatch.setenv("JIRA_OAUTH_SCOPE", "WRITE")


def _set_multi_product_dc_oauth_env(monkeypatch, tmp_path) -> None:
    from fastmcp import settings

    monkeypatch.setattr(settings, "home", tmp_path)
    monkeypatch.setenv("ATLASSIAN_OAUTH_PROXY_ENABLE", "true")
    monkeypatch.setenv("PUBLIC_BASE_URL", "https://mcp.example.com")
    monkeypatch.setenv("JIRA_URL", "https://jira.example.com")
    monkeypatch.setenv("JIRA_OAUTH_CLIENT_ID", "jira-client")
    monkeypatch.setenv("JIRA_OAUTH_CLIENT_SECRET", "jira-secret")
    monkeypatch.setenv(
        "JIRA_OAUTH_REDIRECT_URI",
        "https://mcp.example.com/jira/oauth/callback",
    )
    monkeypatch.setenv("JIRA_OAUTH_SCOPE", "WRITE")
    monkeypatch.setenv("CONFLUENCE_URL", "https://confluence.example.com")
    monkeypatch.setenv("CONFLUENCE_OAUTH_CLIENT_ID", "confluence-client")
    monkeypatch.setenv("CONFLUENCE_OAUTH_CLIENT_SECRET", "confluence-secret")
    monkeypatch.setenv(
        "CONFLUENCE_OAUTH_REDIRECT_URI",
        "https://mcp.example.com/confluence/oauth/callback",
    )
    monkeypatch.setenv("CONFLUENCE_OAUTH_SCOPE", "READ WRITE")


def test_build_auth_provider_disabled_by_default(monkeypatch):
    monkeypatch.delenv("ATLASSIAN_OAUTH_PROXY_ENABLE", raising=False)

    assert _build_auth_provider() is None


def test_build_auth_provider_fails_closed_when_configuration_is_missing(
    monkeypatch,
):
    monkeypatch.setenv("ATLASSIAN_OAUTH_PROXY_ENABLE", "true")
    for name in (
        "ATLASSIAN_OAUTH_INSTANCE_URL",
        "JIRA_URL",
        "CONFLUENCE_URL",
        "ATLASSIAN_OAUTH_CLIENT_ID",
        "JIRA_OAUTH_CLIENT_ID",
        "CONFLUENCE_OAUTH_CLIENT_ID",
        "ATLASSIAN_OAUTH_CLIENT_SECRET",
        "JIRA_OAUTH_CLIENT_SECRET",
        "CONFLUENCE_OAUTH_CLIENT_SECRET",
        "ATLASSIAN_OAUTH_REDIRECT_URI",
    ):
        monkeypatch.delenv(name, raising=False)

    try:
        _build_auth_provider(
            product="jira",
            public_base_url="https://mcp.example.com/jira",
        )
    except ValueError as exc:
        assert "required configuration is missing" in str(exc)
    else:
        raise AssertionError("OAuth mode must not start without its configuration")


def test_build_auth_provider_exposes_data_center_oauth_routes(monkeypatch):
    _set_jira_dc_oauth_env(monkeypatch)

    provider = _build_auth_provider(
        product="jira",
        public_base_url="https://mcp.example.com/jira",
    )

    assert provider is not None
    assert provider._upstream_authorization_endpoint == (
        "https://jira.example.com/rest/oauth2/latest/authorize"
    )
    assert provider._upstream_token_endpoint == (
        "https://jira.example.com/rest/oauth2/latest/token"
    )
    route_paths = {route.path for route in provider.get_routes("/mcp")}
    assert "/authorize" in route_paths
    assert "/token" in route_paths
    assert "/register" in route_paths
    assert "/.well-known/oauth-authorization-server" in route_paths
    assert "/.well-known/oauth-protected-resource/jira/mcp" in route_paths
    assert "/oauth/callback" in route_paths


def test_jira_public_url_selects_only_jira_dc_provider(monkeypatch):
    monkeypatch.setenv("ATLASSIAN_OAUTH_PROXY_ENABLE", "true")
    monkeypatch.setenv("PUBLIC_BASE_URL", "https://mcp.example.com/jira")
    monkeypatch.setenv("JIRA_URL", "https://jira.example.com")
    monkeypatch.setenv("JIRA_OAUTH_CLIENT_ID", "jira-client")
    monkeypatch.setenv("JIRA_OAUTH_CLIENT_SECRET", "jira-secret")
    monkeypatch.setenv(
        "JIRA_OAUTH_REDIRECT_URI",
        "https://mcp.example.com/jira/oauth/callback",
    )
    monkeypatch.setenv("JIRA_OAUTH_SCOPE", "WRITE")
    monkeypatch.setenv("CONFLUENCE_URL", "https://confluence.example.com")
    monkeypatch.setenv("CONFLUENCE_OAUTH_CLIENT_ID", "confluence-client")
    monkeypatch.setenv("CONFLUENCE_OAUTH_CLIENT_SECRET", "confluence-secret")
    monkeypatch.setenv(
        "CONFLUENCE_OAUTH_REDIRECT_URI",
        "https://mcp.example.com/confluence/oauth/callback",
    )
    monkeypatch.setenv("CONFLUENCE_OAUTH_SCOPE", "READ")

    provider = _build_auth_provider(
        product="jira",
        public_base_url="https://mcp.example.com/jira",
    )

    assert provider is not None
    assert provider._upstream_client_id == "jira-client"
    assert provider._upstream_authorization_endpoint == (
        "https://jira.example.com/rest/oauth2/latest/authorize"
    )


def test_confluence_public_url_selects_only_confluence_dc_provider(monkeypatch):
    monkeypatch.setenv("ATLASSIAN_OAUTH_PROXY_ENABLE", "true")
    monkeypatch.setenv("PUBLIC_BASE_URL", "https://mcp.example.com/confluence")
    monkeypatch.setenv("JIRA_URL", "https://jira.example.com")
    monkeypatch.setenv("JIRA_OAUTH_CLIENT_ID", "jira-client")
    monkeypatch.setenv("JIRA_OAUTH_CLIENT_SECRET", "jira-secret")
    monkeypatch.setenv(
        "JIRA_OAUTH_REDIRECT_URI",
        "https://mcp.example.com/jira/oauth/callback",
    )
    monkeypatch.setenv("CONFLUENCE_URL", "https://confluence.example.com")
    monkeypatch.setenv("CONFLUENCE_OAUTH_CLIENT_ID", "confluence-client")
    monkeypatch.setenv("CONFLUENCE_OAUTH_CLIENT_SECRET", "confluence-secret")
    monkeypatch.setenv(
        "CONFLUENCE_OAUTH_REDIRECT_URI",
        "https://mcp.example.com/confluence/oauth/callback",
    )

    provider = _build_auth_provider(
        product="confluence",
        public_base_url="https://mcp.example.com/confluence",
    )

    assert provider is not None
    assert provider._upstream_client_id == "confluence-client"
    assert provider._upstream_authorization_endpoint == (
        "https://confluence.example.com/rest/oauth2/latest/authorize"
    )


def test_cloud_browser_proxy_configuration_fails_closed(monkeypatch):
    monkeypatch.setenv("ATLASSIAN_OAUTH_PROXY_ENABLE", "true")
    monkeypatch.setenv("PUBLIC_BASE_URL", "https://mcp.example.com")
    monkeypatch.setenv("JIRA_URL", "https://acme.atlassian.net")
    monkeypatch.setenv("ATLASSIAN_OAUTH_CLIENT_ID", "cloud-client")
    monkeypatch.setenv("ATLASSIAN_OAUTH_CLIENT_SECRET", "cloud-secret")
    monkeypatch.setenv(
        "ATLASSIAN_OAUTH_REDIRECT_URI",
        "https://mcp.example.com/oauth/callback",
    )

    with pytest.raises(ValueError, match="Cloud browser proxy support is not enabled"):
        _build_main_mcp()


def test_multi_product_dc_oauth_builds_one_server_with_isolated_products(
    monkeypatch, tmp_path
):
    _set_multi_product_dc_oauth_env(monkeypatch, tmp_path)

    server = _build_main_mcp()

    assert isinstance(server, MultiProductDataCenterMCP)
    assert set(server.product_servers) == {"jira", "confluence"}
    assert server.product_servers["jira"].oauth_product == "jira"
    assert server.product_servers["confluence"].oauth_product == "confluence"
    assert (
        server.product_servers["jira"].auth._upstream_authorization_endpoint
        == "https://jira.example.com/rest/oauth2/latest/authorize"
    )
    assert (
        server.product_servers["confluence"].auth._upstream_authorization_endpoint
        == "https://confluence.example.com/rest/oauth2/latest/authorize"
    )


def test_single_jira_dc_accepts_existing_product_public_base(monkeypatch, tmp_path):
    from fastmcp import settings

    monkeypatch.setattr(settings, "home", tmp_path)
    monkeypatch.setenv("ATLASSIAN_OAUTH_PROXY_ENABLE", "true")
    monkeypatch.setenv("PUBLIC_BASE_URL", "http://localhost:8000/jira")
    monkeypatch.setenv("JIRA_URL", "https://wrong-jira.example.invalid")
    monkeypatch.setenv("JIRA_OAUTH_CLIENT_ID", "jira-client")
    monkeypatch.setenv("JIRA_OAUTH_CLIENT_SECRET", "jira-secret")
    monkeypatch.setenv(
        "JIRA_OAUTH_REDIRECT_URI",
        "http://localhost:8000/jira/oauth/callback",
    )
    monkeypatch.setenv("JIRA_OAUTH_SCOPE", "WRITE")

    server = _build_main_mcp()

    assert isinstance(server, MultiProductDataCenterMCP)
    provider = server.product_servers["jira"].auth
    assert str(provider.base_url).rstrip("/") == "http://localhost:8000/jira"
    assert provider._redirect_path == "/oauth/callback"


@pytest.mark.parametrize(
    ("product", "scopes"),
    [("jira", ["WRITE"]), ("confluence", ["READ", "WRITE"])],
)
def test_multi_product_dc_oauth_exposes_independent_discovery(
    monkeypatch, tmp_path, product, scopes
):
    _set_multi_product_dc_oauth_env(monkeypatch, tmp_path)
    server = _build_main_mcp()
    app = server.http_app(path="/mcp", transport="streamable-http")

    with TestClient(app, base_url="https://mcp.example.com") as client:
        response = client.post(
            f"/{product}/mcp",
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": "test-client", "version": "1.0"},
                },
            },
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream",
            },
        )
        protected_metadata = client.get(
            f"/.well-known/oauth-protected-resource/{product}/mcp"
        )
        authorization_metadata = client.get(
            f"/.well-known/oauth-authorization-server/{product}"
        )

    assert response.status_code == 401
    assert (
        f'resource_metadata="https://mcp.example.com/.well-known/'
        f'oauth-protected-resource/{product}/mcp"'
        in response.headers["www-authenticate"]
    )
    assert protected_metadata.status_code == 200
    assert protected_metadata.json() == {
        "resource": f"https://mcp.example.com/{product}/mcp",
        "authorization_servers": [f"https://mcp.example.com/{product}"],
        "scopes_supported": scopes,
        "bearer_methods_supported": ["header"],
    }
    assert authorization_metadata.status_code == 200
    metadata = authorization_metadata.json()
    assert metadata["issuer"] == f"https://mcp.example.com/{product}"
    assert metadata["authorization_endpoint"] == (
        f"https://mcp.example.com/{product}/authorize"
    )
    assert metadata["registration_endpoint"] == (
        f"https://mcp.example.com/{product}/register"
    )


def test_multi_product_dc_oauth_has_no_ambiguous_root_mcp(monkeypatch, tmp_path):
    _set_multi_product_dc_oauth_env(monkeypatch, tmp_path)
    app = _build_main_mcp().http_app(path="/mcp", transport="streamable-http")

    with TestClient(app, base_url="https://mcp.example.com") as client:
        response = client.post("/mcp", json={})

    assert response.status_code == 404


def test_oauth_mode_challenges_request_without_auth_header(monkeypatch):
    _set_jira_dc_oauth_env(monkeypatch)
    provider = _build_auth_provider(
        product="jira",
        public_base_url="https://mcp.example.com/jira",
    )
    assert provider is not None
    server = AtlassianMCP(name="OAuth Test", auth=provider)
    app = server.http_app(path="/mcp", transport="streamable-http")

    with TestClient(app) as client:
        response = client.post(
            "/mcp",
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": "test-client", "version": "1.0"},
                },
            },
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream",
            },
        )

    assert response.status_code == 401
    assert response.headers["www-authenticate"].startswith("Bearer ")
    assert "resource_metadata=" in response.headers["www-authenticate"]
