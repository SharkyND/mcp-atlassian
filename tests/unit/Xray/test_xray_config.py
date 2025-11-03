"""Tests for the Xray config module."""

import os
from unittest.mock import patch

import pytest

from mcp_atlassian.Xray.config import XrayConfig


def test_from_env_basic_auth_cloud():
    """Test that from_env correctly loads basic auth configuration for cloud."""
    with patch.dict(
        os.environ,
        {
            "XRAY_URL": "https://test.atlassian.net",
            "XRAY_USERNAME": "test_username",
            "XRAY_API_TOKEN": "test_token",
        },
        clear=True,
    ):
        config = XrayConfig.from_env()
        assert config.url == "https://test.atlassian.net"
        assert config.auth_type == "basic"
        assert config.username == "test_username"
        assert config.api_token == "test_token"
        assert config.personal_token is None
        assert config.ssl_verify is True


def test_from_env_pat_auth_server():
    """Test that from_env correctly loads PAT auth configuration for server."""
    with patch.dict(
        os.environ,
        {
            "XRAY_URL": "https://xray.example.com",
            "XRAY_PERSONAL_TOKEN": "test_personal_token",
            "XRAY_SSL_VERIFY": "false",
        },
        clear=True,
    ):
        config = XrayConfig.from_env()
        assert config.url == "https://xray.example.com"
        assert config.auth_type == "pat"
        assert config.username is None
        assert config.api_token is None
        assert config.personal_token == "test_personal_token"
        assert config.ssl_verify is False


def test_from_env_basic_auth_server():
    """Test that from_env correctly loads basic auth configuration for server."""
    with patch.dict(
        os.environ,
        {
            "XRAY_URL": "https://xray.example.com",
            "XRAY_USERNAME": "test_username",
            "XRAY_API_TOKEN": "test_token",
        },
        clear=True,
    ):
        config = XrayConfig.from_env()
        assert config.url == "https://xray.example.com"
        assert config.auth_type == "basic"
        assert config.username == "test_username"
        assert config.api_token == "test_token"
        assert config.personal_token is None


def test_from_env_missing_url():
    """Test that from_env raises ValueError when URL is missing."""
    original_env = os.environ.copy()
    try:
        os.environ.clear()
        with pytest.raises(
            ValueError, match="Missing required XRAY_URL environment variable"
        ):
            XrayConfig.from_env()
    finally:
        # Restore original environment
        os.environ.clear()
        os.environ.update(original_env)


def test_from_env_missing_cloud_auth():
    """Test that from_env raises ValueError when cloud auth credentials are missing."""
    with patch.dict(
        os.environ,
        {
            "XRAY_URL": "https://test.atlassian.net",  # Cloud URL
        },
        clear=True,
    ):
        with pytest.raises(
            ValueError,
            match="Cloud authentication requires XRAY_USERNAME and XRAY_API_TOKEN",
        ):
            XrayConfig.from_env()


def test_from_env_missing_server_auth():
    """Test that from_env raises ValueError when server auth credentials are missing."""
    with patch.dict(
        os.environ,
        {
            "XRAY_URL": "https://xray.example.com",  # Server URL
        },
        clear=True,
    ):
        with pytest.raises(
            ValueError,
            match="Server/Data Center authentication requires XRAY_PERSONAL_TOKEN or XRAY_USERNAME and XRAY_API_TOKEN",
        ):
            XrayConfig.from_env()


def test_from_env_oauth_enable():
    """Test that from_env works with OAuth enabled."""
    with patch.dict(
        os.environ,
        {
            "ATLASSIAN_OAUTH_ENABLE": "true",
        },
        clear=True,
    ):
        # This should not raise an error even without XRAY_URL when OAuth is enabled
        config = XrayConfig.from_env()
        assert config.auth_type == "oauth"
        assert config.oauth_config is not None


def test_from_env_projects_filter():
    """Test that from_env correctly loads projects filter configuration."""
    with patch.dict(
        os.environ,
        {
            "XRAY_URL": "https://test.atlassian.net",
            "XRAY_USERNAME": "test_username",
            "XRAY_API_TOKEN": "test_token",
            "XRAY_PROJECTS_FILTER": "PROJ1,PROJ2,PROJ3",
        },
        clear=True,
    ):
        config = XrayConfig.from_env()
        assert config.projects_filter == "PROJ1,PROJ2,PROJ3"


def test_from_env_custom_headers():
    """Test that from_env correctly loads custom headers configuration."""
    with patch.dict(
        os.environ,
        {
            "XRAY_URL": "https://test.atlassian.net",
            "XRAY_USERNAME": "test_username",
            "XRAY_API_TOKEN": "test_token",
            "XRAY_CUSTOM_HEADERS": "X-Custom-Header1=Value1,X-Custom-Header2=Value2",
        },
        clear=True,
    ):
        config = XrayConfig.from_env()
        assert config.custom_headers == {
            "X-Custom-Header1": "Value1",
            "X-Custom-Header2": "Value2",
        }


def test_is_cloud():
    """Test that is_cloud property returns correct value."""
    # Arrange & Act - Cloud URL
    config = XrayConfig(
        url="https://example.atlassian.net",
        auth_type="basic",
        username="test",
        api_token="test",
    )

    # Assert
    assert config.is_cloud is True

    # Arrange & Act - Server URL
    config = XrayConfig(
        url="https://xray.example.com",
        auth_type="pat",
        personal_token="test",
    )

    # Assert
    assert config.is_cloud is False

    # Arrange & Act - Localhost URL (Data Center/Server)
    config = XrayConfig(
        url="http://localhost:8080",
        auth_type="pat",
        personal_token="test",
    )

    # Assert
    assert config.is_cloud is False

    # Arrange & Act - IP localhost URL (Data Center/Server)
    config = XrayConfig(
        url="http://127.0.0.1:8080",
        auth_type="pat",
        personal_token="test",
    )

    # Assert
    assert config.is_cloud is False


def test_from_env_proxy_settings():
    """Test that from_env correctly loads proxy environment variables."""
    with patch.dict(
        os.environ,
        {
            "XRAY_URL": "https://test.atlassian.net",
            "XRAY_USERNAME": "test_username",
            "XRAY_API_TOKEN": "test_token",
            "HTTP_PROXY": "http://proxy.example.com:8080",
            "HTTPS_PROXY": "https://proxy.example.com:8443",
            "SOCKS_PROXY": "socks5://user:pass@proxy.example.com:1080",
            "NO_PROXY": "localhost,127.0.0.1",
        },
        clear=True,
    ):
        config = XrayConfig.from_env()
        assert config.http_proxy == "http://proxy.example.com:8080"
        assert config.https_proxy == "https://proxy.example.com:8443"
        assert config.socks_proxy == "socks5://user:pass@proxy.example.com:1080"
        assert config.no_proxy == "localhost,127.0.0.1"

    # Service-specific overrides
    with patch.dict(
        os.environ,
        {
            "XRAY_URL": "https://test.atlassian.net",
            "XRAY_USERNAME": "test_username",
            "XRAY_API_TOKEN": "test_token",
            "XRAY_HTTP_PROXY": "http://xray-proxy.example.com:8080",
            "XRAY_HTTPS_PROXY": "https://xray-proxy.example.com:8443",
            "XRAY_SOCKS_PROXY": "socks5://user:pass@xray-proxy.example.com:1080",
            "XRAY_NO_PROXY": "localhost,127.0.0.1,.internal.example.com",
        },
        clear=True,
    ):
        config = XrayConfig.from_env()
        assert config.http_proxy == "http://xray-proxy.example.com:8080"
        assert config.https_proxy == "https://xray-proxy.example.com:8443"
        assert config.socks_proxy == "socks5://user:pass@xray-proxy.example.com:1080"
        assert config.no_proxy == "localhost,127.0.0.1,.internal.example.com"


def test_is_cloud_oauth_with_cloud_id():
    """Test that is_cloud returns True for OAuth with cloud_id regardless of URL."""
    from mcp_atlassian.utils.oauth import BYOAccessTokenOAuthConfig

    # OAuth with cloud_id and no URL - should be Cloud
    oauth_config = BYOAccessTokenOAuthConfig(
        cloud_id="test-cloud-id", access_token="test-token"
    )
    config = XrayConfig(
        url=None,  # URL can be None in Multi-Cloud OAuth mode
        auth_type="oauth",
        oauth_config=oauth_config,
    )
    assert config.is_cloud is True

    # OAuth with cloud_id and server URL - should still be Cloud
    config = XrayConfig(
        url="https://xray.example.com",  # Server-like URL
        auth_type="oauth",
        oauth_config=oauth_config,
    )
    assert config.is_cloud is True


def test_is_auth_configured_basic():
    """Test is_auth_configured for basic auth."""
    # Valid basic auth
    config = XrayConfig(
        url="https://test.atlassian.net",
        auth_type="basic",
        username="test_user",
        api_token="test_token",
    )
    assert config.is_auth_configured() is True

    # Missing username
    config = XrayConfig(
        url="https://test.atlassian.net",
        auth_type="basic",
        username=None,
        api_token="test_token",
    )
    assert config.is_auth_configured() is False

    # Missing API token
    config = XrayConfig(
        url="https://test.atlassian.net",
        auth_type="basic",
        username="test_user",
        api_token=None,
    )
    assert config.is_auth_configured() is False


def test_is_auth_configured_pat():
    """Test is_auth_configured for PAT auth."""
    # Valid PAT auth
    config = XrayConfig(
        url="https://xray.example.com",
        auth_type="pat",
        personal_token="test_token",
    )
    assert config.is_auth_configured() is True

    # Missing personal token
    config = XrayConfig(
        url="https://xray.example.com",
        auth_type="pat",
        personal_token=None,
    )
    assert config.is_auth_configured() is False


def test_is_auth_configured_oauth():
    """Test is_auth_configured for OAuth auth."""
    from mcp_atlassian.utils.oauth import BYOAccessTokenOAuthConfig, OAuthConfig

    # Valid BYO OAuth config
    oauth_config = BYOAccessTokenOAuthConfig(
        cloud_id="test-cloud-id", access_token="test-token"
    )
    config = XrayConfig(
        url="https://test.atlassian.net",
        auth_type="oauth",
        oauth_config=oauth_config,
    )
    assert config.is_auth_configured() is True

    # Valid full OAuth config
    oauth_config = OAuthConfig(
        client_id="test-client-id",
        client_secret="test-client-secret",
        redirect_uri="http://localhost:8080/callback",
        scope="read:xray",
        cloud_id="test-cloud-id",
    )
    config = XrayConfig(
        url="https://test.atlassian.net",
        auth_type="oauth",
        oauth_config=oauth_config,
    )
    assert config.is_auth_configured() is True

    # Missing OAuth config
    config = XrayConfig(
        url="https://test.atlassian.net",
        auth_type="oauth",
        oauth_config=None,
    )
    assert config.is_auth_configured() is False

    # Incomplete BYO OAuth config
    oauth_config = BYOAccessTokenOAuthConfig(cloud_id=None, access_token="test-token")
    config = XrayConfig(
        url="https://test.atlassian.net",
        auth_type="oauth",
        oauth_config=oauth_config,
    )
    assert config.is_auth_configured() is False


def test_is_auth_configured_minimal_oauth():
    """Test is_auth_configured for minimal OAuth config (user-provided tokens)."""
    from mcp_atlassian.utils.oauth import OAuthConfig

    # Minimal OAuth config (missing client credentials but valid for user-provided tokens)
    oauth_config = OAuthConfig(
        client_id=None,  # Missing client_id
        client_secret=None,  # Missing client_secret
        redirect_uri=None,
        scope=None,
        cloud_id="test-cloud-id",
    )
    config = XrayConfig(
        url="https://test.atlassian.net",
        auth_type="oauth",
        oauth_config=oauth_config,
    )
    # Should be True for minimal config expecting user-provided tokens
    assert config.is_auth_configured() is True


def test_is_auth_configured_unknown_auth_type():
    """Test is_auth_configured for unknown auth type."""
    config = XrayConfig(
        url="https://test.atlassian.net",
        auth_type="unknown",  # Invalid auth type
        username="test_user",
        api_token="test_token",
    )
    assert config.is_auth_configured() is False


def test_verify_ssl_property():
    """Test the verify_ssl compatibility property."""
    config = XrayConfig(
        url="https://test.atlassian.net",
        auth_type="basic",
        username="test_user",
        api_token="test_token",
        ssl_verify=False,
    )
    assert config.verify_ssl is False
    assert config.ssl_verify is False

    config = XrayConfig(
        url="https://test.atlassian.net",
        auth_type="basic",
        username="test_user",
        api_token="test_token",
        ssl_verify=True,
    )
    assert config.verify_ssl is True
    assert config.ssl_verify is True


def test_from_env_ssl_verify_variations():
    """Test different SSL verify environment variable values."""
    test_cases = [
        ("true", True),
        ("True", True),
        ("TRUE", True),
        ("1", True),
        ("yes", True),
        ("false", False),
        ("False", False),
        ("FALSE", False),
        ("0", False),
        ("no", False),
        ("", True),  # Default when not set
    ]

    for ssl_value, expected in test_cases:
        with patch.dict(
            os.environ,
            {
                "XRAY_URL": "https://xray.example.com",
                "XRAY_PERSONAL_TOKEN": "test_token",
                "XRAY_SSL_VERIFY": ssl_value,
            },
            clear=True,
        ):
            config = XrayConfig.from_env()
            assert config.ssl_verify is expected, f"Failed for SSL value: '{ssl_value}'"
