"""Configuration module for Bitbucket API interactions."""

import os
from dataclasses import dataclass
from typing import Literal

from ..utils.env import get_custom_headers, is_env_ssl_verify
from ..utils.oauth import (
    BYOAccessTokenOAuthConfig,
    OAuthConfig,
    get_oauth_config_from_env,
)
from ..utils.urls import is_atlassian_cloud_url


@dataclass
class BitbucketConfig:
    """Bitbucket API configuration.

    Handles authentication for Bitbucket Cloud and Server/Data Center:
    - Cloud: username/app password (basic auth) or OAuth 2.0 (3LO)
    - Server/DC: personal access token or basic auth
    """

    url: str  # Base URL for Bitbucket
    auth_type: Literal["basic", "pat", "oauth"]  # Authentication type
    username: str | None = None  # Email or username (Cloud)
    app_password: str | None = None  # App password (Cloud)
    personal_token: str | None = None  # Personal access token (Server/DC)
    oauth_config: OAuthConfig | BYOAccessTokenOAuthConfig | None = None
    ssl_verify: bool = True  # Whether to verify SSL certificates
    workspaces_filter: str | None = None  # List of workspace names to filter searches
    http_proxy: str | None = None  # HTTP proxy URL
    https_proxy: str | None = None  # HTTPS proxy URL
    no_proxy: str | None = None  # Comma-separated list of hosts to bypass proxy
    socks_proxy: str | None = None  # SOCKS proxy URL (optional)
    custom_headers: dict[str, str] | None = None  # Custom HTTP headers

    @property
    def is_cloud(self) -> bool:
        """Check if this is a cloud instance.

        Returns:
            True if this is a cloud instance, False otherwise.
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

        # For other auth types, use shared utility function for consistency
        # Note: Bitbucket uses bitbucket.org, but we need consistent detection logic
        return is_atlassian_cloud_url(self.url) if self.url else False

    @property
    def verify_ssl(self) -> bool:
        """Compatibility property for old code.

        Returns:
            The ssl_verify value
        """
        return self.ssl_verify

    def is_auth_configured(self) -> bool:
        """Check if authentication is properly configured.

        Returns:
            True if authentication is configured, False otherwise.
        """
        if self.auth_type == "oauth":
            return bool(self.oauth_config)
        elif self.auth_type == "pat":
            return bool(self.personal_token)
        elif self.auth_type == "basic":
            return bool(self.username and self.app_password)
        return False

    @classmethod
    def from_env(cls) -> "BitbucketConfig":
        """Create configuration from environment variables.

        Returns:
            BitbucketConfig with values from environment variables

        Raises:
            ValueError: If required environment variables are missing or invalid
        """
        url = os.getenv("BITBUCKET_URL")
        if not url and not os.getenv("ATLASSIAN_OAUTH_ENABLE"):
            error_msg = "Missing required BITBUCKET_URL environment variable"
            raise ValueError(error_msg)

        # Determine authentication type based on available environment variables
        username = os.getenv("BITBUCKET_USERNAME")
        app_password = os.getenv("BITBUCKET_APP_PASSWORD")
        personal_token = os.getenv("BITBUCKET_PERSONAL_TOKEN")

        # Check for OAuth configuration
        oauth_config = get_oauth_config_from_env()

        # Check if this is a cloud instance
        is_cloud = is_atlassian_cloud_url(url)

        if oauth_config:
            # OAuth is available - could be full config or minimal config for user-provided tokens
            auth_type = "oauth"
        elif personal_token:
            auth_type = "pat"
        elif is_cloud:
            if username and app_password:
                auth_type = "basic"
            else:
                error_msg = (
                    "For Bitbucket Cloud, either provide BITBUCKET_PERSONAL_TOKEN for PAT auth, "
                    "BITBUCKET_USERNAME and BITBUCKET_APP_PASSWORD for basic auth, or configure OAuth"
                )
                raise ValueError(error_msg)
        else:
            if username and app_password:
                auth_type = "basic"
            else:
                error_msg = (
                    "For Bitbucket Server/Data Center, provide either "
                    "BITBUCKET_PERSONAL_TOKEN for PAT auth, or BITBUCKET_USERNAME "
                    "and BITBUCKET_APP_PASSWORD for basic auth"
                )
                raise ValueError(error_msg)

        return cls(
            url=url or "",
            auth_type=auth_type,  # type: ignore[arg-type]
            username=username,
            app_password=app_password,
            personal_token=personal_token,
            oauth_config=oauth_config,
            ssl_verify=is_env_ssl_verify("BITBUCKET_SSL_VERIFY"),
            workspaces_filter=os.getenv("BITBUCKET_WORKSPACES_FILTER"),
            http_proxy=os.getenv("BITBUCKET_HTTP_PROXY", os.getenv("HTTP_PROXY")),
            https_proxy=os.getenv("BITBUCKET_HTTPS_PROXY", os.getenv("HTTPS_PROXY")),
            no_proxy=os.getenv("BITBUCKET_NO_PROXY", os.getenv("NO_PROXY")),
            socks_proxy=os.getenv("BITBUCKET_SOCKS_PROXY", os.getenv("SOCKS_PROXY")),
            custom_headers=get_custom_headers("BITBUCKET_CUSTOM_HEADERS"),
        )
