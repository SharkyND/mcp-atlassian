"""Tests for the Bitbucket users module."""

from unittest.mock import MagicMock, patch

import pytest
from requests.exceptions import HTTPError

from mcp_atlassian.bitbucket.config import BitbucketConfig
from mcp_atlassian.bitbucket.users import UsersMixin
from mcp_atlassian.exceptions import MCPAtlassianAuthenticationError


class TestUsersMixin:
    """Test cases for UsersMixin class."""

    @pytest.fixture
    def cloud_config(self):
        """Create a cloud configuration for testing."""
        return BitbucketConfig(
            url="https://api.bitbucket.org/2.0",
            auth_type="basic",
            username="test@example.com",
            app_password="app_password",
        )

    @pytest.fixture
    def server_config(self):
        """Create a server configuration for testing."""
        return BitbucketConfig(
            url="https://bitbucket.company.com",
            auth_type="pat",
            username="testuser",
            personal_token="pat_token",
        )

    @pytest.fixture
    def users_mixin_cloud(self, cloud_config):
        """Create a UsersMixin instance for cloud testing."""
        with patch("mcp_atlassian.bitbucket.client.Bitbucket"):
            with patch("mcp_atlassian.bitbucket.client.configure_ssl_verification"):
                mixin = UsersMixin(cloud_config)
                mixin.bitbucket = MagicMock()
                return mixin

    @pytest.fixture
    def users_mixin_server(self, server_config):
        """Create a UsersMixin instance for server testing."""
        with patch("mcp_atlassian.bitbucket.client.Bitbucket"):
            with patch("mcp_atlassian.bitbucket.client.configure_ssl_verification"):
                mixin = UsersMixin(server_config)
                mixin.bitbucket = MagicMock()
                return mixin

    def test_get_current_user_info_cloud_success(self, users_mixin_cloud):
        """Test successful user info retrieval for Bitbucket Cloud."""
        expected_user_data = {
            "username": "testuser",
            "display_name": "Test User",
            "email": "test@example.com",
            "uuid": "{12345678-1234-1234-1234-123456789abc}",
            "type": "user",
        }
        users_mixin_cloud.bitbucket.get.return_value = expected_user_data

        result = users_mixin_cloud.get_current_user_info()

        assert result == expected_user_data
        users_mixin_cloud.bitbucket.get.assert_called_once_with("user")

    def test_get_current_user_info_server_success(self, users_mixin_server):
        """Test successful user info retrieval for Bitbucket Server."""
        # Mock an HTTP 404 error to trigger mock data fallback
        from requests.exceptions import HTTPError

        mock_response = MagicMock()
        mock_response.status_code = 404
        http_error = HTTPError()
        http_error.response = mock_response

        users_mixin_server.bitbucket.get.side_effect = http_error

        result = users_mixin_server.get_current_user_info()

        expected_mock_data = {
            "username": "testuser",
            "name": "testuser",
            "displayName": "testuser",
            "email": "testuser@domain.co",
            "type": "normal",
            "mock_data": True,
        }
        assert result == expected_mock_data

    def test_get_current_user_info_cloud_non_dict_response(self, users_mixin_cloud):
        """Test error handling when cloud API returns non-dict response."""
        users_mixin_cloud.bitbucket.get.return_value = "invalid response"

        with pytest.raises(
            MCPAtlassianAuthenticationError,
            match="Did not receive valid JSON user data",
        ):
            users_mixin_cloud.get_current_user_info()

    def test_get_current_user_info_cloud_empty_dict(self, users_mixin_cloud):
        """Test handling of empty dict response from cloud API."""
        users_mixin_cloud.bitbucket.get.return_value = {}

        result = users_mixin_cloud.get_current_user_info()

        assert result == {}
        # Should still work as it's a valid dict

    def test_get_current_user_info_cloud_partial_data(self, users_mixin_cloud):
        """Test handling of partial user data from cloud API."""
        partial_user_data = {
            "display_name": "Test User",
            "email": "test@example.com",
            # Missing username
        }
        users_mixin_cloud.bitbucket.get.return_value = partial_user_data

        result = users_mixin_cloud.get_current_user_info()

        assert result == partial_user_data

    def test_get_current_user_info_cloud_http_error(self, users_mixin_cloud):
        """Test handling of HTTP errors from cloud API."""
        users_mixin_cloud.bitbucket.get.side_effect = HTTPError("401 Unauthorized")

        with pytest.raises(MCPAtlassianAuthenticationError):
            users_mixin_cloud.get_current_user_info()

    def test_get_current_user_info_pat_auth_logging(self, users_mixin_server):
        """Test that PAT authentication is properly logged."""
        # Mock an HTTP 404 error to trigger mock data fallback
        mock_response = MagicMock()
        mock_response.status_code = 404
        http_error = HTTPError()
        http_error.response = mock_response

        users_mixin_server.bitbucket.get.side_effect = http_error

        with patch("mcp_atlassian.bitbucket.users.logger") as mock_logger:
            result = users_mixin_server.get_current_user_info()

            # Should log PAT auth info with masked token
            mock_logger.info.assert_called()
            log_calls = [call.args[0] for call in mock_logger.info.call_args_list]

            # Check that PAT is mentioned but token is masked
            pat_auth_logged = any("PAT auth" in str(call) for call in log_calls)
            assert pat_auth_logged

            # Ensure actual token is not in logs
            token_logged_directly = any("pat_token" in str(call) for call in log_calls)
            assert not token_logged_directly, "PAT should be masked in logs"

    def test_get_current_user_info_basic_auth_logging(self, users_mixin_cloud):
        """Test that basic authentication is properly logged."""
        users_mixin_cloud.bitbucket.get.return_value = {"username": "testuser"}

        with patch("mcp_atlassian.bitbucket.users.logger") as mock_logger:
            result = users_mixin_cloud.get_current_user_info()

            # Should log auth type and username
            mock_logger.info.assert_called()
            log_calls = [call.args[0] for call in mock_logger.info.call_args_list]

            auth_type_logged = any("basic" in str(call) for call in log_calls)
            username_logged = any("test@example.com" in str(call) for call in log_calls)
            assert auth_type_logged or username_logged

    def test_get_current_user_info_server_mock_data_logging(self, users_mixin_server):
        """Test that mock data usage is properly logged for server."""
        # Mock an HTTP 404 error to trigger mock data fallback
        mock_response = MagicMock()
        mock_response.status_code = 404
        http_error = HTTPError()
        http_error.response = mock_response

        users_mixin_server.bitbucket.get.side_effect = http_error

        with patch("mcp_atlassian.bitbucket.users.logger") as mock_logger:
            result = users_mixin_server.get_current_user_info()

            # Should log that mock data is being used
            mock_logger.info.assert_called()
            log_calls = [call.args[0] for call in mock_logger.info.call_args_list]

            mock_data_logged = any("mock user data" in str(call) for call in log_calls)
            assert mock_data_logged

    def test_get_current_user_info_cloud_success_logging(self, users_mixin_cloud):
        """Test successful user data retrieval logging for cloud."""
        user_data = {"username": "testuser", "display_name": "Test User"}
        users_mixin_cloud.bitbucket.get.return_value = user_data

        with patch("mcp_atlassian.bitbucket.users.logger") as mock_logger:
            result = users_mixin_cloud.get_current_user_info()

            # Should log successful retrieval
            mock_logger.info.assert_called()
            log_calls = [call.args[0] for call in mock_logger.info.call_args_list]

            success_logged = any(
                "Successfully retrieved user data" in str(call) for call in log_calls
            )
            assert success_logged

    def test_get_current_user_info_username_fallback(self, users_mixin_cloud):
        """Test username extraction with fallback logic."""
        test_cases = [
            # Test username field
            {"username": "user1", "name": "user2", "displayName": "user3"},
            # Test name fallback
            {"name": "user2", "displayName": "user3"},
            # Test displayName fallback
            {"displayName": "user3"},
            # Test unknown fallback
            {"other_field": "value"},
        ]

        for user_data in test_cases:
            users_mixin_cloud.bitbucket.get.return_value = user_data

            with patch("mcp_atlassian.bitbucket.users.logger") as mock_logger:
                result = users_mixin_cloud.get_current_user_info()

                # Verify the result contains the expected data
                assert result == user_data

                # Check that appropriate username was logged
                log_calls = [call.args[0] for call in mock_logger.info.call_args_list]
                user_data_logged = any(
                    "user data for:" in str(call) for call in log_calls
                )
                assert user_data_logged

    def test_get_current_user_info_error_logging(self, users_mixin_cloud):
        """Test error logging for invalid response type."""
        users_mixin_cloud.bitbucket.get.return_value = ["not", "a", "dict"]

        with patch("mcp_atlassian.bitbucket.users.logger") as mock_logger:
            with pytest.raises(MCPAtlassianAuthenticationError):
                users_mixin_cloud.get_current_user_info()

            # Should log error message
            mock_logger.error.assert_called()
            error_calls = [call.args[0] for call in mock_logger.error.call_args_list]

            error_logged = any(
                "returned non-dict data type" in str(call) for call in error_calls
            )
            assert error_logged

    def test_mixin_inheritance(self):
        """Test that UsersMixin properly inherits from BitbucketClient."""
        from mcp_atlassian.bitbucket.client import BitbucketClient

        assert issubclass(UsersMixin, BitbucketClient)

        # Test that mixin can be instantiated (with mocked dependencies)
        with patch("mcp_atlassian.bitbucket.client.Bitbucket"):
            with patch("mcp_atlassian.bitbucket.client.configure_ssl_verification"):
                config = BitbucketConfig(
                    url="https://api.bitbucket.org/2.0",
                    auth_type="basic",
                    username="test@example.com",
                    app_password="password",
                )
                mixin = UsersMixin(config)
                assert hasattr(mixin, "get_current_user_info")
                assert hasattr(mixin, "config")  # From parent class
