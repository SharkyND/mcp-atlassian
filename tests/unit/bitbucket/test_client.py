"""Tests for the Bitbucket client module."""

from unittest.mock import MagicMock, patch

import pytest

from mcp_atlassian.bitbucket.client import BitbucketClient
from mcp_atlassian.bitbucket.config import BitbucketConfig
from mcp_atlassian.exceptions import MCPAtlassianAuthenticationError
from mcp_atlassian.utils.oauth import OAuthConfig


class TestBitbucketClient:
    """Test cases for BitbucketClient class."""

    @pytest.fixture
    def basic_auth_config(self):
        """Create a basic auth configuration for testing."""
        return BitbucketConfig(
            url="https://api.bitbucket.org/2.0",
            auth_type="basic",
            username="test@example.com",
            app_password="app_password",
        )

    @pytest.fixture
    def pat_config(self):
        """Create a PAT configuration for testing."""
        return BitbucketConfig(
            url="https://bitbucket.company.com",
            auth_type="pat",
            username="testuser",
            personal_token="pat_token",
        )

    @pytest.fixture
    def oauth_config(self):
        """Create an OAuth configuration for testing."""
        oauth_conf = OAuthConfig(
            client_id="client_id",
            client_secret="client_secret",
            redirect_uri="http://localhost:8080/callback",
            scope="read",
            cloud_id="cloud_id",
        )
        return BitbucketConfig(
            url="https://api.bitbucket.org/2.0",
            auth_type="oauth",
            oauth_config=oauth_conf,
        )

    @patch("mcp_atlassian.bitbucket.client.Bitbucket")
    @patch("mcp_atlassian.bitbucket.client.configure_ssl_verification")
    def test_init_basic_auth_cloud(
        self, mock_ssl_config, mock_bitbucket, basic_auth_config
    ):
        """Test initialization with basic auth for cloud."""
        mock_bb_instance = MagicMock()
        mock_bb_instance._session = MagicMock()
        mock_bb_instance._session.proxies = {}
        mock_bb_instance._session.headers = {}
        mock_bitbucket.return_value = mock_bb_instance

        client = BitbucketClient(basic_auth_config)

        assert client.config == basic_auth_config
        mock_bitbucket.assert_called_once_with(
            url="https://api.bitbucket.org/2.0",
            username="test@example.com",
            password="app_password",
            cloud=True,
            verify_ssl=True,
        )
        mock_ssl_config.assert_called_once()

    @patch("mcp_atlassian.bitbucket.client.Bitbucket")
    @patch("mcp_atlassian.bitbucket.client.configure_ssl_verification")
    def test_init_pat_server(self, mock_ssl_config, mock_bitbucket, pat_config):
        """Test initialization with PAT for server."""
        mock_bb_instance = MagicMock()
        mock_bb_instance._session = MagicMock()
        mock_bb_instance._session.proxies = {}
        mock_bb_instance._session.headers = {}
        mock_bitbucket.return_value = mock_bb_instance

        client = BitbucketClient(pat_config)

        assert client.config == pat_config
        mock_bitbucket.assert_called_once_with(
            url="https://bitbucket.company.com",
            cloud=False,
            verify_ssl=True,
            token="pat_token",  # PAT goes in token field
        )
        mock_ssl_config.assert_called_once()

    @patch("mcp_atlassian.bitbucket.client.Bitbucket")
    @patch("mcp_atlassian.bitbucket.client.configure_ssl_verification")
    @patch("mcp_atlassian.bitbucket.client.configure_oauth_session")
    @patch("mcp_atlassian.bitbucket.client.Session")
    def test_init_oauth(
        self,
        mock_session,
        mock_oauth_config,
        mock_ssl_config,
        mock_bitbucket,
        oauth_config,
    ):
        """Test initialization with OAuth."""
        mock_session_instance = MagicMock()
        mock_session.return_value = mock_session_instance
        mock_oauth_config.return_value = True

        mock_bb_instance = MagicMock()
        mock_bb_instance._session = mock_session_instance
        mock_bitbucket.return_value = mock_bb_instance

        client = BitbucketClient(oauth_config)

        assert client.config == oauth_config
        mock_session.assert_called_once()
        mock_oauth_config.assert_called_once_with(
            mock_session_instance, oauth_config.oauth_config
        )

        expected_url = "https://api.atlassian.com/ex/bitbucket/cloud_id"
        mock_bitbucket.assert_called_once_with(
            url=expected_url, session=mock_session_instance, cloud=True, verify_ssl=True
        )

    @patch("mcp_atlassian.bitbucket.client.configure_oauth_session")
    @patch("mcp_atlassian.bitbucket.client.Session")
    def test_init_oauth_missing_cloud_id(
        self, mock_session, mock_oauth_config, oauth_config
    ):
        """Test OAuth initialization fails with missing cloud_id."""
        oauth_config.oauth_config.cloud_id = None

        with pytest.raises(
            ValueError, match="OAuth authentication requires a valid cloud_id"
        ):
            BitbucketClient(oauth_config)

    @patch("mcp_atlassian.bitbucket.client.configure_oauth_session")
    @patch("mcp_atlassian.bitbucket.client.Session")
    def test_init_oauth_session_config_fails(
        self, mock_session, mock_oauth_config, oauth_config
    ):
        """Test OAuth initialization fails when session configuration fails."""
        mock_session_instance = MagicMock()
        mock_session.return_value = mock_session_instance
        mock_oauth_config.return_value = False

        with pytest.raises(
            MCPAtlassianAuthenticationError, match="Failed to configure OAuth session"
        ):
            BitbucketClient(oauth_config)

    @patch("mcp_atlassian.bitbucket.client.BitbucketConfig")
    @patch("mcp_atlassian.bitbucket.client.Bitbucket")
    @patch("mcp_atlassian.bitbucket.client.configure_ssl_verification")
    def test_init_without_config_uses_env(
        self, mock_ssl_config, mock_bitbucket, mock_config_class
    ):
        """Test initialization without config uses environment variables."""
        mock_config_instance = MagicMock()
        mock_config_instance.auth_type = "basic"
        mock_config_instance.url = "https://api.bitbucket.org/2.0"
        mock_config_instance.username = "test@example.com"
        mock_config_instance.app_password = "password"
        mock_config_instance.is_cloud = True
        mock_config_instance.ssl_verify = True
        mock_config_class.from_env.return_value = mock_config_instance

        mock_bb_instance = MagicMock()
        mock_bb_instance._session = MagicMock()
        mock_bitbucket.return_value = mock_bb_instance

        client = BitbucketClient()

        mock_config_class.from_env.assert_called_once()
        assert client.config == mock_config_instance

    @patch("mcp_atlassian.bitbucket.client.Bitbucket")
    @patch("mcp_atlassian.bitbucket.client.configure_ssl_verification")
    def test_ssl_verification_disabled(self, mock_ssl_config, mock_bitbucket):
        """Test client with SSL verification disabled."""
        config = BitbucketConfig(
            url="https://api.bitbucket.org/2.0",
            auth_type="basic",
            username="test@example.com",
            app_password="password",
            ssl_verify=False,
        )

        mock_bb_instance = MagicMock()
        mock_bb_instance._session = MagicMock()
        mock_bb_instance._session.proxies = {}
        mock_bb_instance._session.headers = {}
        mock_bitbucket.return_value = mock_bb_instance

        client = BitbucketClient(config)

        mock_bitbucket.assert_called_once_with(
            url="https://api.bitbucket.org/2.0",
            username="test@example.com",
            password="password",
            cloud=True,
            verify_ssl=False,
        )

    @patch("mcp_atlassian.bitbucket.client.Bitbucket")
    @patch("mcp_atlassian.bitbucket.client.configure_ssl_verification")
    def test_proxy_configuration(self, mock_ssl_config, mock_bitbucket):
        """Test client with proxy configuration."""
        config = BitbucketConfig(
            url="https://api.bitbucket.org/2.0",
            auth_type="basic",
            username="test@example.com",
            app_password="password",
            http_proxy="http://proxy:8080",
            https_proxy="https://proxy:8080",
            no_proxy="localhost,127.0.0.1",
        )

        mock_bb_instance = MagicMock()
        mock_session = MagicMock()
        mock_session.proxies = {}
        mock_session.headers = {}
        mock_bb_instance._session = mock_session
        mock_bitbucket.return_value = mock_bb_instance

        client = BitbucketClient(config)

        # Check that proxies were configured
        expected_proxies = {"http": "http://proxy:8080", "https": "https://proxy:8080"}
        # Check the final state of proxies instead of mocking the update call
        assert mock_session.proxies == expected_proxies

    @patch("mcp_atlassian.bitbucket.client.Bitbucket")
    @patch("mcp_atlassian.bitbucket.client.configure_ssl_verification")
    def test_socks_proxy_configuration(self, mock_ssl_config, mock_bitbucket):
        """Test client with SOCKS proxy configuration."""
        config = BitbucketConfig(
            url="https://api.bitbucket.org/2.0",
            auth_type="basic",
            username="test@example.com",
            app_password="password",
            socks_proxy="socks5://proxy:1080",
        )

        mock_bb_instance = MagicMock()
        mock_session = MagicMock()
        mock_session.proxies = {}
        mock_session.headers = {}
        mock_bb_instance._session = mock_session
        mock_bitbucket.return_value = mock_bb_instance

        client = BitbucketClient(config)

        # Check that SOCKS proxy was configured
        expected_proxies = {
            "http": "socks5://proxy:1080",
            "https": "socks5://proxy:1080",
        }
        # Check the final state of proxies instead of mocking the update call
        assert mock_session.proxies == expected_proxies

    @patch("mcp_atlassian.bitbucket.client.Bitbucket")
    @patch("mcp_atlassian.bitbucket.client.configure_ssl_verification")
    def test_custom_headers_configuration(self, mock_ssl_config, mock_bitbucket):
        """Test client with custom headers configuration."""
        config = BitbucketConfig(
            url="https://api.bitbucket.org/2.0",
            auth_type="basic",
            username="test@example.com",
            app_password="password",
            custom_headers={"X-Custom": "value"},
        )

        mock_bb_instance = MagicMock()
        mock_session = MagicMock()
        mock_session.proxies = {}
        mock_session.headers = {}
        mock_bb_instance._session = mock_session
        mock_bitbucket.return_value = mock_bb_instance

        client = BitbucketClient(config)

        # Check that custom headers were configured
        # Check the final state of headers instead of mocking the update call
        assert "X-Custom" in mock_session.headers
        assert mock_session.headers["X-Custom"] == "value"

    def test_client_has_bitbucket_attribute(self, basic_auth_config):
        """Test that client has bitbucket attribute after initialization."""
        with patch("mcp_atlassian.bitbucket.client.Bitbucket") as mock_bitbucket:
            mock_bb_instance = MagicMock()
            mock_bb_instance._session = MagicMock()
            mock_bitbucket.return_value = mock_bb_instance

            with patch("mcp_atlassian.bitbucket.client.configure_ssl_verification"):
                client = BitbucketClient(basic_auth_config)

            assert hasattr(client, "bitbucket")
            assert client.bitbucket == mock_bb_instance

    def test_client_logging_basic_auth(self, basic_auth_config):
        """Test that appropriate logging occurs for basic auth."""
        with patch("mcp_atlassian.bitbucket.client.Bitbucket") as mock_bitbucket:
            mock_bb_instance = MagicMock()
            mock_bb_instance._session = MagicMock()
            mock_bitbucket.return_value = mock_bb_instance

            with patch("mcp_atlassian.bitbucket.client.configure_ssl_verification"):
                with patch("mcp_atlassian.bitbucket.client.logger") as mock_logger:
                    client = BitbucketClient(basic_auth_config)

                    # Should log debug messages
                    assert mock_logger.debug.called

    def test_client_logging_pat_auth(self, pat_config):
        """Test that appropriate logging occurs for PAT auth."""
        with patch("mcp_atlassian.bitbucket.client.Bitbucket") as mock_bitbucket:
            mock_bb_instance = MagicMock()
            mock_bb_instance._session = MagicMock()
            mock_bitbucket.return_value = mock_bb_instance

            with patch("mcp_atlassian.bitbucket.client.configure_ssl_verification"):
                with patch("mcp_atlassian.bitbucket.client.logger") as mock_logger:
                    client = BitbucketClient(pat_config)

                    # Should log debug messages with masked PAT
                    assert mock_logger.debug.called
                    # Verify PAT is masked in logs
                    log_calls = [
                        call.args[0] for call in mock_logger.debug.call_args_list
                    ]
                    pat_logged_directly = any(
                        "pat_token" in str(call) for call in log_calls
                    )
                    assert not pat_logged_directly, "PAT should be masked in logs"

    def test_get_pull_request_activities_cloud_success(self, basic_auth_config):
        """Test successful retrieval of pull request activities for cloud."""
        with patch("mcp_atlassian.bitbucket.client.Bitbucket") as mock_bitbucket:
            with patch("mcp_atlassian.bitbucket.client.configure_ssl_verification"):
                mock_bb_instance = MagicMock()
                mock_bb_instance._session = MagicMock()
                mock_bb_instance._session.proxies = {}
                mock_bb_instance._session.headers = {}
                mock_bb_instance.get.return_value = {
                    "values": [{"id": 1, "content": "test comment"}]
                }
                mock_bitbucket.return_value = mock_bb_instance

                client = BitbucketClient(basic_auth_config)
                result = client.get_pull_request_activities("workspace", "repo", 1)

                assert result == [{"id": 1, "content": "test comment"}]
                mock_bb_instance.get.assert_called_once_with(
                    "repositories/workspace/repo/pullrequests/1/activities"
                )

    def test_get_pull_request_activities_server_success(self, pat_config):
        """Test successful retrieval of pull request activities for server."""
        with patch("mcp_atlassian.bitbucket.client.Bitbucket") as mock_bitbucket:
            with patch("mcp_atlassian.bitbucket.client.configure_ssl_verification"):
                mock_bb_instance = MagicMock()
                mock_bb_instance._session = MagicMock()
                mock_bb_instance._session.proxies = {}
                mock_bb_instance._session.headers = {}
                mock_bb_instance.get.return_value = [
                    {"id": 1, "content": "test comment"}
                ]
                mock_bitbucket.return_value = mock_bb_instance

                client = BitbucketClient(pat_config)
                result = client.get_pull_request_activities("workspace", "repo", 1)

                assert result == [{"id": 1, "content": "test comment"}]
                mock_bb_instance.get.assert_called_once_with(
                    "projects/workspace/repos/repo/pull-requests/1/activities"
                )

    def test_get_pull_request_activities_empty_response(self, basic_auth_config):
        """Test pull request activities with empty response."""
        with patch("mcp_atlassian.bitbucket.client.Bitbucket") as mock_bitbucket:
            with patch("mcp_atlassian.bitbucket.client.configure_ssl_verification"):
                mock_bb_instance = MagicMock()
                mock_bb_instance._session = MagicMock()
                mock_bb_instance._session.proxies = {}
                mock_bb_instance._session.headers = {}
                mock_bb_instance.get.return_value = None
                mock_bitbucket.return_value = mock_bb_instance

                client = BitbucketClient(basic_auth_config)
                result = client.get_pull_request_activities("workspace", "repo", 1)

                assert result == []

    def test_get_pull_request_activities_exception_handling(self, basic_auth_config):
        """Test exception handling in get_pull_request_activities."""
        with patch("mcp_atlassian.bitbucket.client.Bitbucket") as mock_bitbucket:
            with patch("mcp_atlassian.bitbucket.client.configure_ssl_verification"):
                mock_bb_instance = MagicMock()
                mock_bb_instance._session = MagicMock()
                mock_bb_instance._session.proxies = {}
                mock_bb_instance._session.headers = {}
                mock_bb_instance.get.side_effect = Exception("API error")
                mock_bitbucket.return_value = mock_bb_instance

                client = BitbucketClient(basic_auth_config)

                with pytest.raises(Exception) as exc_info:
                    client.get_pull_request_activities("workspace", "repo", 1)

                assert "API error" in str(exc_info.value)
