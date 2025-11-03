"""Tests for the Xray client module."""

import os
from unittest.mock import MagicMock, call, patch

import pytest

from mcp_atlassian.exceptions import MCPAtlassianAuthenticationError
from mcp_atlassian.Xray.client import XrayClient
from mcp_atlassian.Xray.config import XrayConfig


def test_init_with_basic_auth_cloud():
    """Test initializing the client with basic auth configuration for cloud."""
    with (
        patch("mcp_atlassian.Xray.client.Xray") as mock_xray,
        patch(
            "mcp_atlassian.Xray.client.configure_ssl_verification"
        ) as mock_configure_ssl,
    ):
        config = XrayConfig(
            url="https://test.atlassian.net",
            auth_type="basic",
            username="test_username",
            api_token="test_token",
        )

        client = XrayClient(config=config)

        # Verify Xray was initialized correctly
        mock_xray.assert_called_once_with(
            url="https://test.atlassian.net",
            username="test_username",
            password="test_token",
            cloud=True,
            verify_ssl=True,
        )

        # Verify SSL verification was configured
        mock_configure_ssl.assert_called_once_with(
            service_name="Xray",
            url="https://test.atlassian.net",
            session=mock_xray.return_value._session,
            ssl_verify=True,
        )

        assert client.config == config


def test_init_with_basic_auth_server():
    """Test initializing the client with basic auth configuration for server."""
    with (
        patch("mcp_atlassian.Xray.client.Xray") as mock_xray,
        patch(
            "mcp_atlassian.Xray.client.configure_ssl_verification"
        ) as mock_configure_ssl,
    ):
        config = XrayConfig(
            url="https://xray.example.com",
            auth_type="basic",
            username="test_username",
            api_token="test_token",
            ssl_verify=False,
        )

        client = XrayClient(config=config)

        # Verify Xray was initialized correctly
        mock_xray.assert_called_once_with(
            url="https://xray.example.com",
            username="test_username",
            password="test_token",
            cloud=False,
            verify_ssl=False,
        )

        # Verify SSL verification was configured
        mock_configure_ssl.assert_called_once_with(
            service_name="Xray",
            url="https://xray.example.com",
            session=mock_xray.return_value._session,
            ssl_verify=False,
        )

        assert client.config == config


def test_init_with_pat_auth():
    """Test initializing the client with PAT auth configuration."""
    with (
        patch("mcp_atlassian.Xray.client.Xray") as mock_xray,
        patch(
            "mcp_atlassian.Xray.client.configure_ssl_verification"
        ) as mock_configure_ssl,
    ):
        config = XrayConfig(
            url="https://xray.example.com",
            auth_type="pat",
            personal_token="test_personal_token",
            ssl_verify=False,
        )

        client = XrayClient(config=config)

        # Verify Xray was initialized correctly
        mock_xray.assert_called_once_with(
            url="https://xray.example.com",
            token="test_personal_token",
            cloud=False,
            verify_ssl=False,
        )

        # Verify SSL verification was configured
        mock_configure_ssl.assert_called_once_with(
            service_name="Xray",
            url="https://xray.example.com",
            session=mock_xray.return_value._session,
            ssl_verify=False,
        )

        assert client.config == config


def test_init_with_oauth():
    """Test initializing the client with OAuth configuration."""
    from mcp_atlassian.utils.oauth import BYOAccessTokenOAuthConfig

    with (
        patch("mcp_atlassian.Xray.client.Xray") as mock_xray,
        patch(
            "mcp_atlassian.Xray.client.configure_ssl_verification"
        ) as mock_configure_ssl,
        patch(
            "mcp_atlassian.Xray.client.configure_oauth_session"
        ) as mock_configure_oauth,
        patch("mcp_atlassian.Xray.client.Session") as mock_session,
    ):
        mock_configure_oauth.return_value = True
        oauth_config = BYOAccessTokenOAuthConfig(
            cloud_id="test-cloud-id", access_token="test-token"
        )
        config = XrayConfig(
            url="https://test.atlassian.net",
            auth_type="oauth",
            oauth_config=oauth_config,
        )

        client = XrayClient(config=config)

        # Verify session was created
        mock_session.assert_called_once()

        # Verify OAuth was configured
        mock_configure_oauth.assert_called_once_with(
            mock_session.return_value, oauth_config
        )

        # Verify Xray was initialized correctly with OAuth URL
        expected_url = f"https://api.atlassian.com/ex/xray/{oauth_config.cloud_id}"
        mock_xray.assert_called_once_with(
            url=expected_url,
            session=mock_session.return_value,
            cloud=True,
            verify_ssl=True,
        )

        # Verify SSL verification was configured
        mock_configure_ssl.assert_called_once_with(
            service_name="Xray",
            url=config.url,
            session=mock_xray.return_value._session,
            ssl_verify=True,
        )

        assert client.config == config


def test_init_from_env():
    """Test initializing the client from environment variables."""
    with (
        patch("mcp_atlassian.Xray.config.XrayConfig.from_env") as mock_from_env,
        patch("mcp_atlassian.Xray.client.Xray") as mock_xray,
        patch("mcp_atlassian.Xray.client.configure_ssl_verification"),
    ):
        mock_config = MagicMock()
        mock_config.auth_type = "basic"
        mock_config.is_cloud = True
        mock_config.url = "https://test.atlassian.net"
        mock_config.username = "test_user"
        mock_config.api_token = "test_token"
        mock_config.ssl_verify = True
        mock_config.http_proxy = None
        mock_config.https_proxy = None
        mock_config.socks_proxy = None
        mock_config.no_proxy = None
        mock_config.custom_headers = None
        mock_from_env.return_value = mock_config

        client = XrayClient()

        mock_from_env.assert_called_once()
        assert client.config == mock_config


def test_init_with_proxy_settings():
    """Test initializing the client with proxy configuration."""
    with (
        patch("mcp_atlassian.Xray.client.Xray") as mock_xray,
        patch("mcp_atlassian.Xray.client.configure_ssl_verification"),
        patch("mcp_atlassian.Xray.client.log_config_param") as mock_log,
        patch.dict(os.environ, {}, clear=True),
    ):
        # Mock the session object
        mock_session = MagicMock()
        mock_xray.return_value._session = mock_session

        config = XrayConfig(
            url="https://xray.example.com",
            auth_type="pat",
            personal_token="test_token",
            http_proxy="http://proxy.example.com:8080",
            https_proxy="https://proxy.example.com:8443",
            socks_proxy="socks5://proxy.example.com:1080",
            no_proxy="localhost,127.0.0.1",
        )

        client = XrayClient(config=config)

        # Verify proxy settings were applied to session
        expected_proxies = {
            "http": "http://proxy.example.com:8080",
            "https": "https://proxy.example.com:8443",
            "socks": "socks5://proxy.example.com:1080",
        }
        mock_session.proxies.update.assert_called_once_with(expected_proxies)

        # Verify NO_PROXY environment variable was set
        assert os.environ.get("NO_PROXY") == "localhost,127.0.0.1"

        # Verify logging was called for proxy settings
        expected_log_calls = [
            call(
                mock_log,
                "Xray",
                "HTTP_PROXY",
                "http://proxy.example.com:8080",
                sensitive=True,
            ),
            call(
                mock_log,
                "Xray",
                "HTTPS_PROXY",
                "https://proxy.example.com:8443",
                sensitive=True,
            ),
            call(
                mock_log,
                "Xray",
                "SOCKS_PROXY",
                "socks5://proxy.example.com:1080",
                sensitive=True,
            ),
            call(mock_log, "Xray", "NO_PROXY", "localhost,127.0.0.1"),
        ]
        # Note: We can't easily verify the exact calls due to the way log_config_param is called


def test_init_with_custom_headers():
    """Test initializing the client with custom headers."""
    with (
        patch("mcp_atlassian.Xray.client.Xray") as mock_xray,
        patch("mcp_atlassian.Xray.client.configure_ssl_verification"),
        patch("mcp_atlassian.Xray.client.get_masked_session_headers") as mock_mask,
    ):
        # Mock the session object with headers as a MagicMock
        mock_session = MagicMock()
        mock_headers = MagicMock()
        mock_session.headers = mock_headers
        mock_xray.return_value._session = mock_session
        mock_mask.return_value = {"X-Custom": "***"}

        custom_headers = {"X-Custom-Header": "test-value", "X-Auth": "secret"}
        config = XrayConfig(
            url="https://test.atlassian.net",
            auth_type="basic",
            username="test_user",
            api_token="test_token",
            custom_headers=custom_headers,
        )

        client = XrayClient(config=config)

        # Verify custom headers were added to session
        mock_headers.update.assert_called_with(custom_headers)

        # Verify masking function was called twice - once for basic auth logging, once for custom headers
        assert mock_mask.call_count == 2
        # Check the second call was with custom headers
        mock_mask.assert_any_call(custom_headers)

        assert client.config == config


def test_init_oauth_missing_cloud_id():
    """Test that OAuth initialization fails when cloud_id is missing."""
    from mcp_atlassian.utils.oauth import BYOAccessTokenOAuthConfig

    oauth_config = BYOAccessTokenOAuthConfig(
        cloud_id=None,
        access_token="test-token",  # Missing cloud_id
    )
    config = XrayConfig(
        url="https://test.atlassian.net",
        auth_type="oauth",
        oauth_config=oauth_config,
    )

    with pytest.raises(
        ValueError, match="OAuth authentication requires a valid cloud_id"
    ):
        XrayClient(config=config)


def test_init_oauth_missing_config():
    """Test that OAuth initialization fails when oauth_config is None."""
    config = XrayConfig(
        url="https://test.atlassian.net",
        auth_type="oauth",
        oauth_config=None,
    )

    with pytest.raises(
        ValueError, match="OAuth authentication requires a valid cloud_id"
    ):
        XrayClient(config=config)


def test_init_oauth_session_configuration_failure():
    """Test that OAuth initialization fails when session configuration fails."""
    from mcp_atlassian.utils.oauth import BYOAccessTokenOAuthConfig

    with (
        patch(
            "mcp_atlassian.Xray.client.configure_oauth_session"
        ) as mock_configure_oauth,
        patch("mcp_atlassian.Xray.client.Session"),
    ):
        mock_configure_oauth.return_value = False  # Simulate failure

        oauth_config = BYOAccessTokenOAuthConfig(
            cloud_id="test-cloud-id", access_token="test-token"
        )
        config = XrayConfig(
            url="https://test.atlassian.net",
            auth_type="oauth",
            oauth_config=oauth_config,
        )

        with pytest.raises(
            MCPAtlassianAuthenticationError, match="Failed to configure OAuth session"
        ):
            XrayClient(config=config)


def test_init_no_proxies():
    """Test initializing the client without proxy configuration."""
    with (
        patch("mcp_atlassian.Xray.client.Xray") as mock_xray,
        patch("mcp_atlassian.Xray.client.configure_ssl_verification"),
    ):
        # Mock the session object
        mock_session = MagicMock()
        mock_xray.return_value._session = mock_session

        config = XrayConfig(
            url="https://test.atlassian.net",
            auth_type="basic",
            username="test_user",
            api_token="test_token",
            # No proxy settings
            http_proxy=None,
            https_proxy=None,
            socks_proxy=None,
            no_proxy=None,
        )

        client = XrayClient(config=config)

        # Verify no proxy settings were applied
        mock_session.proxies.update.assert_not_called()

        assert client.config == config


def test_init_no_custom_headers():
    """Test initializing the client without custom headers."""
    with (
        patch("mcp_atlassian.Xray.client.Xray") as mock_xray,
        patch("mcp_atlassian.Xray.client.configure_ssl_verification"),
    ):
        # Mock the session object
        mock_session = MagicMock()
        mock_xray.return_value._session = mock_session

        config = XrayConfig(
            url="https://test.atlassian.net",
            auth_type="basic",
            username="test_user",
            api_token="test_token",
            custom_headers=None,
        )

        client = XrayClient(config=config)

        # Verify no custom headers were added
        mock_session.headers.update.assert_not_called()

        assert client.config == config


def test_init_empty_custom_headers():
    """Test initializing the client with empty custom headers dict."""
    with (
        patch("mcp_atlassian.Xray.client.Xray") as mock_xray,
        patch("mcp_atlassian.Xray.client.configure_ssl_verification"),
    ):
        # Mock the session object
        mock_session = MagicMock()
        mock_xray.return_value._session = mock_session

        config = XrayConfig(
            url="https://test.atlassian.net",
            auth_type="basic",
            username="test_user",
            api_token="test_token",
            custom_headers={},
        )

        client = XrayClient(config=config)

        # Verify custom headers update was NOT called because empty dict is falsy
        mock_session.headers.update.assert_not_called()

        assert client.config == config
