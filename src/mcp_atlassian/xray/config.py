"""Configuration module for Xray API interactions."""

import logging
from dataclasses import dataclass
from typing import Literal

from ..jira.config import JiraConfig
from ..utils.oauth import BYOAccessTokenOAuthConfig, OAuthConfig
from ..utils.urls import is_atlassian_cloud_url


@dataclass
class XrayConfig:
    """Xray API configuration.

    Handles authentication for Xray Cloud and Server/Data Center:
    - Cloud: username/API token (basic auth) or OAuth 2.0 (3LO)
    - Server/DC: personal access token or basic auth
    """

    url: str  # Base URL for Xray
    auth_type: Literal["basic", "pat", "oauth"]  # Authentication type
    username: str | None = None  # Email or username (Cloud)
    api_token: str | None = None  # API token (Cloud)
    personal_token: str | None = None  # Personal access token (Server/DC)
    oauth_config: OAuthConfig | BYOAccessTokenOAuthConfig | None = None
    ssl_verify: bool = True  # Whether to verify SSL certificates
    projects_filter: str | None = None  # List of project keys to filter searches
    http_proxy: str | None = None  # HTTP proxy URL
    https_proxy: str | None = None  # HTTPS proxy URL
    no_proxy: str | None = None  # Comma-separated list of hosts to bypass proxy
    socks_proxy: str | None = None  # SOCKS proxy URL (optional)
    custom_headers: dict[str, str] | None = None  # Custom HTTP headers

    @property
    def is_cloud(self) -> bool:
        """Check if this is a cloud instance.

        Returns:
            True if this is a cloud instance (atlassian.net), False otherwise.
            Localhost URLs are always considered non-cloud (Server/Data Center).
        """
        # Multi-Cloud OAuth mode: URL might be None, but we use api.atlassian.com
        if (
            self.auth_type == "oauth"
            and self.oauth_config
            and self.oauth_config.cloud_id
        ):
            # OAuth with cloud_id uses api.atlassian.com which is always Cloud
            return True

        # For other auth types, check the URL
        return is_atlassian_cloud_url(self.url) if self.url else False

    @property
    def verify_ssl(self) -> bool:
        """Compatibility property for old code.

        Returns:
            The ssl_verify value
        """
        return self.ssl_verify

    @classmethod
    def from_env(cls) -> "XrayConfig":
        """Create configuration from Jira environment variables.

        Returns:
            XrayConfig with values from Jira environment variables

        Raises:
            ValueError: If required environment variables are missing or invalid
        """
        jira_config = JiraConfig.from_env()
        return cls.from_jira_config(jira_config)

    @classmethod
    def from_jira_config(cls, jira_config: JiraConfig) -> "XrayConfig":
        """Create an Xray configuration from an existing Jira configuration.

        Args:
            jira_config: Base Jira configuration to mirror for Xray.

        Returns:
            XrayConfig that reuses Jira URL, authentication, and proxy settings.

        Raises:
            ValueError: If Jira config is using unsupported auth for Xray or a
                Cloud URL.
        """
        if is_atlassian_cloud_url(jira_config.url):
            error_msg = (
                f"Xray is not supported in Atlassian Cloud. "
                f"Cloud URL detected: {jira_config.url}. "
                f"Xray for Jira is only available on Server/Data Center "
                f"deployments. Please use a Server/Data Center URL instead."
            )
            raise ValueError(error_msg)

        if jira_config.auth_type == "oauth":
            error_msg = (
                "Xray for Jira does not support OAuth authentication. "
                "Use Jira basic (username/API token) or PAT credentials."
            )
            raise ValueError(error_msg)

        # Reuse Jira's proxy overrides and custom headers for Xray
        return cls(
            url=jira_config.url,
            auth_type=jira_config.auth_type,
            username=jira_config.username,
            api_token=jira_config.api_token,
            personal_token=jira_config.personal_token,
            oauth_config=None,
            ssl_verify=jira_config.ssl_verify,
            projects_filter=jira_config.projects_filter,
            http_proxy=jira_config.http_proxy,
            https_proxy=jira_config.https_proxy,
            no_proxy=jira_config.no_proxy,
            socks_proxy=jira_config.socks_proxy,
            custom_headers=jira_config.custom_headers,
        )

    def is_auth_configured(self) -> bool:
        """Check if the current authentication configuration is complete and valid for making API calls.

        Returns:
            bool: True if authentication is fully configured, False otherwise.
        """
        logger = logging.getLogger("mcp-atlassian.Xray.config")
        if self.auth_type == "oauth":
            # Handle different OAuth configuration types
            if self.oauth_config:
                # Full OAuth configuration (traditional mode)
                if isinstance(self.oauth_config, OAuthConfig):
                    if (
                        self.oauth_config.client_id
                        and self.oauth_config.client_secret
                        and self.oauth_config.redirect_uri
                        and self.oauth_config.scope
                        and self.oauth_config.cloud_id
                    ):
                        return True
                    # Minimal OAuth configuration (user-provided tokens mode)
                    # This is valid if we have oauth_config but missing client credentials
                    # In this case, we expect authentication to come from user-provided headers
                    elif (
                        not self.oauth_config.client_id
                        and not self.oauth_config.client_secret
                    ):
                        logger.debug(
                            "Minimal OAuth config detected - expecting user-provided tokens via headers"
                        )
                        return True
                # Bring Your Own Access Token mode
                elif isinstance(self.oauth_config, BYOAccessTokenOAuthConfig):
                    if self.oauth_config.cloud_id and self.oauth_config.access_token:
                        return True

            # Partial configuration is invalid
            logger.warning("Incomplete OAuth configuration detected")
            return False
        elif self.auth_type == "pat":
            return bool(self.personal_token)
        elif self.auth_type == "basic":
            return bool(self.username and self.api_token)
        logger.warning(
            f"Unknown or unsupported auth_type: {self.auth_type} in XrayConfig"
        )
        return False
