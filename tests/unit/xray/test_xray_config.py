"""Tests for the Xray config module."""

import os
from unittest.mock import patch

import pytest

from mcp_atlassian.jira.config import JiraConfig
from mcp_atlassian.utils.oauth import BYOAccessTokenOAuthConfig, OAuthConfig
from mcp_atlassian.xray.config import XrayConfig


def test_from_env_uses_jira_pat_config():
    """Xray config should reuse Jira PAT configuration."""
    with patch.dict(
        os.environ,
        {
            "JIRA_URL": "https://jira.example.com",
            "JIRA_PERSONAL_TOKEN": "test_personal_token",
            "JIRA_SSL_VERIFY": "false",
        },
        clear=True,
    ):
        config = XrayConfig.from_env()

    assert config.url == "https://jira.example.com"
    assert config.auth_type == "pat"
    assert config.personal_token == "test_personal_token"
    assert config.username is None
    assert config.api_token is None
    assert config.ssl_verify is False


def test_from_env_uses_jira_basic_config():
    """Xray config should reuse Jira basic auth configuration."""
    with patch.dict(
        os.environ,
        {
            "JIRA_URL": "https://jira.example.com",
            "JIRA_USERNAME": "jira_user",
            "JIRA_API_TOKEN": "jira_token",
        },
        clear=True,
    ):
        config = XrayConfig.from_env()

    assert config.url == "https://jira.example.com"
    assert config.auth_type == "basic"
    assert config.username == "jira_user"
    assert config.api_token == "jira_token"
    assert config.personal_token is None


def test_from_env_missing_jira_url():
    """from_env should surface Jira URL requirement."""
    with patch.dict(os.environ, {}, clear=True):
        with pytest.raises(
            ValueError, match="Missing required JIRA_URL environment variable"
        ):
            XrayConfig.from_env()


def test_from_env_cloud_url_rejected():
    """Cloud Jira URLs should be rejected for Xray for Jira."""
    with patch.dict(
        os.environ,
        {
            "JIRA_URL": "https://company.atlassian.net",
            "JIRA_USERNAME": "user",
            "JIRA_API_TOKEN": "token",
        },
        clear=True,
    ):
        with pytest.raises(
            ValueError,
            match="Xray is not supported in Atlassian Cloud.*company.atlassian.net",
        ):
            XrayConfig.from_env()


def test_from_env_projects_filter_and_headers():
    """Projects filter and custom headers should mirror Jira values."""
    with patch.dict(
        os.environ,
        {
            "JIRA_URL": "https://jira.example.com",
            "JIRA_USERNAME": "jira_user",
            "JIRA_API_TOKEN": "jira_token",
            "JIRA_PROJECTS_FILTER": "PROJ1,PROJ2",
            "JIRA_CUSTOM_HEADERS": "X-Trace-Id=abc123,X-Env=staging",
        },
        clear=True,
    ):
        config = XrayConfig.from_env()

    assert config.projects_filter == "PROJ1,PROJ2"
    assert config.custom_headers == {"X-Trace-Id": "abc123", "X-Env": "staging"}


def test_from_env_reuses_jira_proxy_settings():
    """Proxy overrides should reuse Jira proxy environment variables."""
    with patch.dict(
        os.environ,
        {
            "JIRA_URL": "https://jira.example.com",
            "JIRA_PERSONAL_TOKEN": "test_personal_token",
            "JIRA_HTTP_PROXY": "http://jira-proxy.example.com:8080",
            "JIRA_HTTPS_PROXY": "https://jira-proxy.example.com:8443",
            "JIRA_SOCKS_PROXY": "socks5://user:pass@jira-proxy.example.com:1080",
            "JIRA_NO_PROXY": "localhost,127.0.0.1",
        },
        clear=True,
    ):
        config = XrayConfig.from_env()

    assert config.http_proxy == "http://jira-proxy.example.com:8080"
    assert config.https_proxy == "https://jira-proxy.example.com:8443"
    assert config.socks_proxy == "socks5://user:pass@jira-proxy.example.com:1080"
    assert config.no_proxy == "localhost,127.0.0.1"


def test_from_jira_config_rejects_oauth():
    """Xray should reject Jira OAuth configs."""
    oauth_jira_config = JiraConfig(
        url="https://jira.example.com",
        auth_type="oauth",
        username=None,
        api_token=None,
        personal_token=None,
        oauth_config=None,
    )

    with pytest.raises(
        ValueError, match="Xray for Jira does not support OAuth authentication."
    ):
        XrayConfig.from_jira_config(oauth_jira_config)


def test_from_jira_config_clones_values():
    """Xray config should mirror Jira config values."""
    jira_config = JiraConfig(
        url="https://jira.example.com",
        auth_type="basic",
        username="jira_user",
        api_token="jira_token",
        personal_token=None,
        oauth_config=None,
        ssl_verify=False,
        projects_filter="PROJ-1,PROJ-2",
        http_proxy="http://proxy.example.com:8080",
        https_proxy="https://proxy.example.com:8443",
        no_proxy="localhost",
        socks_proxy="socks5://proxy.example.com:1080",
        custom_headers={"X-Env": "staging"},
    )

    xray_config = XrayConfig.from_jira_config(jira_config)

    assert xray_config.url == jira_config.url
    assert xray_config.auth_type == jira_config.auth_type
    assert xray_config.username == "jira_user"
    assert xray_config.api_token == "jira_token"
    assert xray_config.ssl_verify is False
    assert xray_config.projects_filter == "PROJ-1,PROJ-2"
    assert xray_config.http_proxy == "http://proxy.example.com:8080"
    assert xray_config.custom_headers == {"X-Env": "staging"}


def test_is_cloud_property():
    """Validate cloud detection rules."""
    config = XrayConfig(
        url="https://example.atlassian.net",
        auth_type="basic",
        username="user",
        api_token="token",
    )
    assert config.is_cloud is True

    config = XrayConfig(
        url="https://jira.example.com",
        auth_type="pat",
        personal_token="token",
    )
    assert config.is_cloud is False

    config = XrayConfig(
        url="http://127.0.0.1:8080",
        auth_type="pat",
        personal_token="token",
    )
    assert config.is_cloud is False

    oauth_config = BYOAccessTokenOAuthConfig(cloud_id="cloud-id", access_token="token")
    config = XrayConfig(url=None, auth_type="oauth", oauth_config=oauth_config)
    assert config.is_cloud is True


def test_is_auth_configured_basic_and_pat():
    """Ensure auth configuration validation for basic and PAT."""
    basic_config = XrayConfig(
        url="https://jira.example.com",
        auth_type="basic",
        username="user",
        api_token="token",
    )
    assert basic_config.is_auth_configured() is True

    missing_user = XrayConfig(
        url="https://jira.example.com",
        auth_type="basic",
        username=None,
        api_token="token",
    )
    assert missing_user.is_auth_configured() is False

    pat_config = XrayConfig(
        url="https://jira.example.com",
        auth_type="pat",
        personal_token="token",
    )
    assert pat_config.is_auth_configured() is True

    missing_pat = XrayConfig(
        url="https://jira.example.com",
        auth_type="pat",
        personal_token=None,
    )
    assert missing_pat.is_auth_configured() is False


def test_is_auth_configured_oauth_modes():
    """Validate oauth branches for completeness."""
    oauth_config = OAuthConfig(
        client_id="client",
        client_secret="secret",
        redirect_uri="http://localhost:8080/callback",
        scope="read:jira",
        access_token=None,
        refresh_token=None,
        expires_at=None,
        cloud_id="cloud-id",
    )
    config = XrayConfig(
        url="https://api.atlassian.com",
        auth_type="oauth",
        oauth_config=oauth_config,
    )
    assert config.is_auth_configured() is True

    byo_config = BYOAccessTokenOAuthConfig(cloud_id="cloud-id", access_token="token")
    config = XrayConfig(
        url="https://api.atlassian.com",
        auth_type="oauth",
        oauth_config=byo_config,
    )
    assert config.is_auth_configured() is True

    minimal_oauth = OAuthConfig(
        client_id=None,
        client_secret=None,
        redirect_uri=None,
        scope=None,
        access_token=None,
        refresh_token=None,
        expires_at=None,
        cloud_id="cloud-id",
    )
    config = XrayConfig(
        url="https://api.atlassian.com",
        auth_type="oauth",
        oauth_config=minimal_oauth,
    )
    assert config.is_auth_configured() is True

    config = XrayConfig(
        url="https://api.atlassian.com",
        auth_type="oauth",
        oauth_config=None,
    )
    assert config.is_auth_configured() is False


def test_verify_ssl_property():
    """Ensure verify_ssl mirrors ssl_verify."""
    config = XrayConfig(
        url="https://jira.example.com",
        auth_type="basic",
        username="user",
        api_token="token",
        ssl_verify=False,
    )
    assert config.verify_ssl is False
    assert config.ssl_verify is False

    config.ssl_verify = True
    assert config.verify_ssl is True


def test_from_env_ssl_verify_variations():
    """Check SSL verify env parsing via Jira settings."""
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
        ("", True),
    ]

    for ssl_value, expected in test_cases:
        with patch.dict(
            os.environ,
            {
                "JIRA_URL": "https://jira.example.com",
                "JIRA_PERSONAL_TOKEN": "test_token",
                "JIRA_SSL_VERIFY": ssl_value,
            },
            clear=True,
        ):
            config = XrayConfig.from_env()
            assert config.ssl_verify is expected, f"Failed for SSL value: '{ssl_value}'"
