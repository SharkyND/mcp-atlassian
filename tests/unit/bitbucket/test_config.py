"""Tests for the Bitbucket configuration module."""

import os
from unittest.mock import patch

import pytest

from mcp_atlassian.bitbucket.config import BitbucketConfig
from mcp_atlassian.utils.oauth import OAuthConfig


class TestBitbucketConfig:
    """Test cases for BitbucketConfig class."""

    def test_config_creation_with_basic_auth_cloud(self):
        """Test creating a config with basic auth for Bitbucket Cloud."""
        config = BitbucketConfig(
            url="https://api.bitbucket.org/2.0",
            auth_type="basic",
            username="test@example.com",
            app_password="test_password",
        )

        assert config.url == "https://api.bitbucket.org/2.0"
        assert config.auth_type == "basic"
        assert config.username == "test@example.com"
        assert config.app_password == "test_password"
        assert config.ssl_verify is True

    def test_config_creation_with_pat_server(self):
        """Test creating a config with PAT for Bitbucket Server."""
        config = BitbucketConfig(
            url="https://bitbucket.company.com",
            auth_type="pat",
            personal_token="pat_token",
        )

        assert config.url == "https://bitbucket.company.com"
        assert config.auth_type == "pat"
        assert config.personal_token == "pat_token"
        assert config.username is None
        assert config.app_password is None

    def test_config_creation_with_oauth(self):
        """Test creating a config with OAuth."""
        oauth_config = OAuthConfig(
            client_id="client_id",
            client_secret="client_secret",
            redirect_uri="http://localhost:8080/callback",
            scope="read",
            cloud_id="cloud_id",
        )

        config = BitbucketConfig(
            url="https://api.bitbucket.org/2.0",
            auth_type="oauth",
            oauth_config=oauth_config,
        )

        assert config.url == "https://api.bitbucket.org/2.0"
        assert config.auth_type == "oauth"
        assert config.oauth_config == oauth_config

    def test_config_ssl_verify_false(self):
        """Test config with SSL verification disabled."""
        config = BitbucketConfig(
            url="https://bitbucket.company.com",
            auth_type="pat",
            personal_token="pat_token",
            ssl_verify=False,
        )

        assert config.ssl_verify is False

    @patch.dict(
        os.environ,
        {
            "BITBUCKET_URL": "https://api.bitbucket.org/2.0",
            "BITBUCKET_USERNAME": "test@example.com",
            "BITBUCKET_APP_PASSWORD": "test_password",
        },
    )
    def test_from_env_basic_auth_cloud(self):
        """Test creating config from environment variables with basic auth."""
        config = BitbucketConfig.from_env()

        assert config.url == "https://api.bitbucket.org/2.0"
        assert config.auth_type == "basic"
        assert config.username == "test@example.com"
        assert config.app_password == "test_password"

    @patch.dict(
        os.environ,
        {
            "BITBUCKET_URL": "https://bitbucket.company.com",
            "BITBUCKET_USERNAME": "testuser",
            "BITBUCKET_PERSONAL_TOKEN": "pat_token",
        },
    )
    def test_from_env_pat_server(self):
        """Test creating config from environment variables with PAT."""
        config = BitbucketConfig.from_env()

        assert config.url == "https://bitbucket.company.com"
        assert config.auth_type == "pat"
        assert config.personal_token == "pat_token"
        assert config.username == "testuser"  # PAT requires username for Bitbucket

    @patch.dict(
        os.environ,
        {
            "BITBUCKET_URL": "https://api.bitbucket.org/2.0",
            "ATLASSIAN_OAUTH_ENABLE": "true",
            "ATLASSIAN_OAUTH_CLIENT_ID": "client_id",
            "ATLASSIAN_OAUTH_CLIENT_SECRET": "client_secret",
            "ATLASSIAN_OAUTH_REDIRECT_URI": "http://localhost:8080/callback",
            "ATLASSIAN_OAUTH_SCOPE": "read",
            "ATLASSIAN_OAUTH_CLOUD_ID": "cloud_id",
        },
    )
    def test_from_env_oauth(self):
        """Test creating config from environment variables with OAuth."""
        config = BitbucketConfig.from_env()

        assert config.url == "https://api.bitbucket.org/2.0"
        assert config.auth_type == "oauth"
        assert config.oauth_config is not None
        assert config.oauth_config.client_id == "client_id"

    @patch.dict(os.environ, {}, clear=True)
    def test_from_env_missing_url_raises_error(self):
        """Test that missing URL raises ValueError."""
        with pytest.raises(ValueError, match="Missing required BITBUCKET_URL"):
            BitbucketConfig.from_env()

    @patch.dict(os.environ, {"BITBUCKET_URL": "https://api.bitbucket.org/2.0"})
    def test_from_env_missing_credentials_raises_error(self):
        """Test that missing credentials raises ValueError."""
        with pytest.raises(
            ValueError,
            match="For Bitbucket Cloud, either provide.*BITBUCKET_PERSONAL_TOKEN.*or.*BITBUCKET_USERNAME.*BITBUCKET_APP_PASSWORD",
        ):
            BitbucketConfig.from_env()

    @patch.dict(
        os.environ,
        {
            "BITBUCKET_URL": "https://api.bitbucket.org/2.0",
            "BITBUCKET_USERNAME": "test@example.com",
            # Missing app_password
        },
    )
    def test_from_env_incomplete_basic_auth_raises_error(self):
        """Test that incomplete basic auth credentials raises ValueError."""
        with pytest.raises(
            ValueError,
            match="For Bitbucket Cloud, either provide.*BITBUCKET_PERSONAL_TOKEN.*or.*BITBUCKET_USERNAME.*BITBUCKET_APP_PASSWORD",
        ):
            BitbucketConfig.from_env()

    @patch.dict(
        os.environ,
        {
            "BITBUCKET_URL": "https://api.bitbucket.org/2.0",
            "BITBUCKET_SSL_VERIFY": "false",
        },
    )
    def test_from_env_ssl_verify_false(self):
        """Test SSL verification disabled from environment."""
        with pytest.raises(ValueError):  # Will still fail due to missing auth
            BitbucketConfig.from_env()

    def test_is_cloud_url_detection(self):
        """Test cloud URL detection."""
        cloud_config = BitbucketConfig(
            url="https://bitbucket.org/workspace/repo",  # This should be detected as cloud
            auth_type="basic",
            username="test@example.com",
            app_password="password",
        )

        server_config = BitbucketConfig(
            url="https://bitbucket.company.com", auth_type="pat", personal_token="token"
        )

        assert cloud_config.is_cloud
        assert not server_config.is_cloud

    def test_config_repr(self):
        """Test string representation of config."""
        config = BitbucketConfig(
            url="https://api.bitbucket.org/2.0",
            auth_type="basic",
            username="test@example.com",
            app_password="password",
        )

        repr_str = repr(config)
        assert "BitbucketConfig" in repr_str
        assert "https://api.bitbucket.org/2.0" in repr_str
        assert "basic" in repr_str
        # Note: BitbucketConfig is a dataclass and shows all fields in repr

    def test_is_auth_configured(self):
        """Test authentication configuration check."""
        # Test basic auth configured
        config = BitbucketConfig(
            url="https://api.bitbucket.org/2.0",
            auth_type="basic",
            username="test@example.com",
            app_password="password",
        )
        assert config.is_auth_configured()

        # Test PAT configured
        config = BitbucketConfig(
            url="https://bitbucket.company.com", auth_type="pat", personal_token="token"
        )
        assert config.is_auth_configured()

        # Test auth not configured
        config = BitbucketConfig(url="https://api.bitbucket.org/2.0", auth_type="basic")
        assert not config.is_auth_configured()

    def test_verify_ssl_property(self):
        """Test the verify_ssl compatibility property."""
        config = BitbucketConfig(
            url="https://api.bitbucket.org/2.0",
            auth_type="basic",
            username="test@example.com",
            app_password="password",
            ssl_verify=False,
        )

        # Both ssl_verify attribute and verify_ssl property should work
        assert config.ssl_verify is False
        assert config.verify_ssl is False

    def test_oauth_cloud_detection(self):
        """Test cloud detection for OAuth configurations."""
        oauth_config = OAuthConfig(
            client_id="client_id",
            client_secret="client_secret",
            redirect_uri="http://localhost:8080/callback",
            scope="read",
            cloud_id="cloud_id",
        )

        config = BitbucketConfig(
            url="https://api.bitbucket.org/2.0",
            auth_type="oauth",
            oauth_config=oauth_config,
        )

        # OAuth with cloud_id should always be detected as cloud
        assert config.is_cloud
