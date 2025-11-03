"""Tests for the Xray user module."""

from unittest.mock import MagicMock, patch

import pytest
from requests.exceptions import HTTPError

from mcp_atlassian.exceptions import MCPAtlassianAuthenticationError
from mcp_atlassian.Xray.config import XrayConfig
from mcp_atlassian.Xray.user import MixUsers


class TestMixUsers:
    """Tests for the MixUsers class."""

    @pytest.fixture
    def xray_config_basic(self):
        """Create a basic Xray config for testing."""
        return XrayConfig(
            url="https://test.atlassian.net",
            auth_type="basic",
            username="test_user",
            api_token="test_token",
        )

    @pytest.fixture
    def xray_config_pat(self):
        """Create a PAT Xray config for testing."""
        return XrayConfig(
            url="https://xray.example.com",
            auth_type="pat",
            personal_token="test_personal_token",
        )

    @pytest.fixture
    def users_mixin_basic(self, xray_config_basic):
        """Create a MixUsers instance with basic auth for testing."""
        with patch("mcp_atlassian.Xray.user.XrayClient.__init__", return_value=None):
            mixin = MixUsers()
            mixin.config = xray_config_basic
            mixin.xray = MagicMock()
            return mixin

    @pytest.fixture
    def users_mixin_pat(self, xray_config_pat):
        """Create a MixUsers instance with PAT auth for testing."""
        with patch("mcp_atlassian.Xray.user.XrayClient.__init__", return_value=None):
            mixin = MixUsers()
            mixin.config = xray_config_pat
            mixin.xray = MagicMock()
            return mixin

    @pytest.fixture
    def mock_user_data(self):
        """Mock user data returned from Jira API."""
        return {
            "accountId": "5b10ac8d82e05b22cc7d4ef5",
            "displayName": "Test User",
            "emailAddress": "test@example.com",
            "name": "testuser",
            "active": True,
            "avatarUrls": {
                "48x48": "https://avatar.example.com/48x48/test.png",
                "24x24": "https://avatar.example.com/24x24/test.png",
                "16x16": "https://avatar.example.com/16x16/test.png",
                "32x32": "https://avatar.example.com/32x32/test.png",
            },
        }

    def test_get_current_user_info_success_basic_auth(
        self, users_mixin_basic, mock_user_data
    ):
        """Test successful user info retrieval with basic auth."""
        # Mock successful API call
        users_mixin_basic.xray.get.return_value = mock_user_data

        # Call the method
        result = users_mixin_basic.get_current_user_info()

        # Verify the result
        assert result == mock_user_data
        users_mixin_basic.xray.get.assert_called_once_with("rest/api/2/myself")

    def test_get_current_user_info_success_pat_auth(
        self, users_mixin_pat, mock_user_data
    ):
        """Test successful user info retrieval with PAT auth."""
        # Mock successful API call
        users_mixin_pat.xray.get.return_value = mock_user_data

        # Call the method
        result = users_mixin_pat.get_current_user_info()

        # Verify the result
        assert result == mock_user_data
        users_mixin_pat.xray.get.assert_called_once_with("rest/api/2/myself")

    def test_get_current_user_info_fallback_to_test_status(self, users_mixin_basic):
        """Test fallback to test/status endpoint when myself endpoint fails."""
        # Mock the first call to fail with 404
        http_error = HTTPError()
        http_error.response = MagicMock()
        http_error.response.status_code = 404

        # Mock the fallback call to succeed
        mock_test_statuses = [{"name": "PASS"}, {"name": "FAIL"}]

        users_mixin_basic.xray.get.side_effect = [http_error, mock_test_statuses]

        # Call the method
        result = users_mixin_basic.get_current_user_info()

        # Verify the result is mock data
        assert result["accountId"] == "test_user"
        assert result["displayName"] == "(test_user)"
        assert result["emailAddress"] == "test_user@domain.co"
        assert result["active"] is True
        assert result["mock_data"] is True

        # Verify both API calls were made
        assert users_mixin_basic.xray.get.call_count == 2
        users_mixin_basic.xray.get.assert_any_call("rest/api/2/myself")
        users_mixin_basic.xray.get.assert_any_call("rest/raven/1.0/test/status")

    def test_get_current_user_info_fallback_to_test_status_401(self, users_mixin_basic):
        """Test fallback to test/status endpoint when myself endpoint returns 401."""
        # Mock the first call to fail with 401
        http_error = HTTPError()
        http_error.response = MagicMock()
        http_error.response.status_code = 401

        # Mock the fallback call to succeed
        mock_test_statuses = [{"name": "PASS"}]

        users_mixin_basic.xray.get.side_effect = [http_error, mock_test_statuses]

        # Call the method
        result = users_mixin_basic.get_current_user_info()

        # Verify the result is mock data
        assert result["mock_data"] is True
        assert result["accountId"] == "test_user"

    def test_get_current_user_info_fallback_to_test_status_403(self, users_mixin_basic):
        """Test fallback to test/status endpoint when myself endpoint returns 403."""
        # Mock the first call to fail with 403
        http_error = HTTPError()
        http_error.response = MagicMock()
        http_error.response.status_code = 403

        # Mock the fallback call to succeed
        mock_test_statuses = [{"name": "TODO"}]

        users_mixin_basic.xray.get.side_effect = [http_error, mock_test_statuses]

        # Call the method
        result = users_mixin_basic.get_current_user_info()

        # Verify the result is mock data
        assert result["mock_data"] is True

    def test_get_current_user_info_fallback_empty_response(self, users_mixin_basic):
        """Test that fallback fails when test/status returns empty response."""
        # Mock the first call to fail with 404
        http_error = HTTPError()
        http_error.response = MagicMock()
        http_error.response.status_code = 404

        # Mock the fallback call to return empty response
        users_mixin_basic.xray.get.side_effect = [http_error, []]

        # Call the method and expect it to raise MCPAtlassianAuthenticationError
        with pytest.raises(
            MCPAtlassianAuthenticationError,
            match="Xray authentication failed: 404 - verify access",
        ):
            users_mixin_basic.get_current_user_info()

    def test_get_current_user_info_fallback_validation_error(self, users_mixin_basic):
        """Test that fallback fails when test/status raises an exception."""
        # Mock the first call to fail with 404
        http_error = HTTPError()
        http_error.response = MagicMock()
        http_error.response.status_code = 404

        # Mock the fallback call to raise an exception
        users_mixin_basic.xray.get.side_effect = [
            http_error,
            Exception("Validation failed"),
        ]

        # Call the method and expect it to raise MCPAtlassianAuthenticationError
        with pytest.raises(
            MCPAtlassianAuthenticationError,
            match="Xray authentication failed: 404 - verify access",
        ):
            users_mixin_basic.get_current_user_info()

    def test_get_current_user_info_non_dict_response(self, users_mixin_basic):
        """Test handling of non-dict response from user endpoint."""
        # Mock API call to return non-dict data
        users_mixin_basic.xray.get.return_value = "invalid response"

        # Call the method and expect MCPAtlassianAuthenticationError
        with pytest.raises(
            MCPAtlassianAuthenticationError, match="Did not receive valid JSON"
        ):
            users_mixin_basic.get_current_user_info()

    def test_get_current_user_info_http_error_500(self, users_mixin_basic):
        """Test handling of HTTP 500 error (not in fallback codes)."""
        # Mock HTTP 500 error
        http_error = HTTPError()
        http_error.response = MagicMock()
        http_error.response.status_code = 500

        users_mixin_basic.xray.get.side_effect = http_error

        # Call the method and expect MCPAtlassianAuthenticationError
        with pytest.raises(
            MCPAtlassianAuthenticationError, match="Xray authentication failed"
        ):
            users_mixin_basic.get_current_user_info()

    def test_get_current_user_info_http_error_no_response(self, users_mixin_basic):
        """Test handling of HTTP error without response object."""
        # Mock HTTP error without response
        http_error = HTTPError("Network error")
        http_error.response = None

        users_mixin_basic.xray.get.side_effect = http_error

        # Call the method and expect MCPAtlassianAuthenticationError
        with pytest.raises(
            MCPAtlassianAuthenticationError, match="Xray API call failed with HTTPError"
        ):
            users_mixin_basic.get_current_user_info()

    def test_get_current_user_info_unexpected_error(self, users_mixin_basic):
        """Test handling of unexpected non-HTTP errors."""
        # Mock unexpected error
        users_mixin_basic.xray.get.side_effect = ValueError("Unexpected error")

        # Call the method and expect MCPAtlassianAuthenticationError
        with pytest.raises(
            MCPAtlassianAuthenticationError, match="Xray user info retrieval failed"
        ):
            users_mixin_basic.get_current_user_info()

    def test_get_current_user_info_username_extraction(self, users_mixin_basic):
        """Test username extraction from different fields."""
        test_cases = [
            # displayName present
            {
                "displayName": "Display User",
                "name": "name_user",
                "accountId": "account_123",
            },
            # displayName missing, name present
            {"name": "name_user", "accountId": "account_123"},
            # displayName and name missing, accountId present
            {"accountId": "account_123"},
            # All missing, should default to "unknown"
            {},
        ]

        expected_usernames = ["Display User", "name_user", "account_123", "unknown"]

        for mock_data in test_cases:
            users_mixin_basic.xray.get.return_value = mock_data
            result = users_mixin_basic.get_current_user_info()
            assert result == mock_data
            # Note: The username is only used for logging, not returned in the result

    def test_get_current_user_info_mock_data_logging(self, users_mixin_basic):
        """Test that mock data is properly logged."""
        # Mock the first call to fail with 404
        http_error = HTTPError()
        http_error.response = MagicMock()
        http_error.response.status_code = 404

        # Mock the fallback call to succeed
        mock_test_statuses = [{"name": "PASS"}]

        users_mixin_basic.xray.get.side_effect = [http_error, mock_test_statuses]

        with patch("mcp_atlassian.Xray.user.logger") as mock_logger:
            result = users_mixin_basic.get_current_user_info()

            # Verify mock data was created and logged
            assert result["mock_data"] is True
            mock_logger.info.assert_any_call(
                "Xray token validated via test/status endpoint. Using mock data for user: test_user"
            )

    def test_get_current_user_info_pat_auth_logging(
        self, users_mixin_pat, mock_user_data
    ):
        """Test that PAT auth is properly logged."""
        users_mixin_pat.xray.get.return_value = mock_user_data

        with patch("mcp_atlassian.Xray.user.logger") as mock_logger:
            result = users_mixin_pat.get_current_user_info()

            # Verify PAT logging - the actual masked format from mask_sensitive function
            mock_logger.info.assert_any_call(
                "Xray PAT auth - PAT (masked): test***********oken"
            )

    def test_get_current_user_info_other_auth_logging(
        self, users_mixin_basic, mock_user_data
    ):
        """Test that other auth types are properly logged."""
        users_mixin_basic.xray.get.return_value = mock_user_data

        with patch("mcp_atlassian.Xray.user.logger") as mock_logger:
            result = users_mixin_basic.get_current_user_info()

            # Verify auth type logging
            mock_logger.info.assert_any_call("Xray auth type: basic")

    def test_get_current_user_info_real_user_data_logging(
        self, users_mixin_basic, mock_user_data
    ):
        """Test that real user data success is properly logged."""
        users_mixin_basic.xray.get.return_value = mock_user_data

        with patch("mcp_atlassian.Xray.user.logger") as mock_logger:
            result = users_mixin_basic.get_current_user_info()

            # Verify success logging
            mock_logger.info.assert_any_call(
                "Successfully retrieved real user data from Jira API"
            )
            mock_logger.info.assert_any_call(
                "Successfully retrieved user data for: Test User"
            )
