"""Base client module for Bitbucket API interactions."""

import logging

from atlassian import Bitbucket
from requests import Session

from mcp_atlassian.exceptions import MCPAtlassianAuthenticationError
from mcp_atlassian.utils.logging import (
    get_masked_session_headers,
    mask_sensitive,
)
from mcp_atlassian.utils.oauth import configure_oauth_session
from mcp_atlassian.utils.ssl import configure_ssl_verification

from .config import BitbucketConfig

# Configure logging
logger = logging.getLogger("mcp-bitbucket")


class BitbucketClient:
    """Base client for Bitbucket API interactions."""

    config: BitbucketConfig

    def __init__(self, config: BitbucketConfig | None = None) -> None:
        """Initialize the Bitbucket client with configuration options.

        Args:
            config: Optional configuration object (will use env vars if not provided)

        Raises:
            ValueError: If configuration is invalid or required credentials are missing
            MCPAtlassianAuthenticationError: If OAuth authentication fails
        """
        # Load configuration from environment variables if not provided
        self.config = config or BitbucketConfig.from_env()

        # Initialize the Bitbucket client based on auth type
        if self.config.auth_type == "oauth":
            if not self.config.oauth_config or not self.config.oauth_config.cloud_id:
                error_msg = "OAuth authentication requires a valid cloud_id"
                raise ValueError(error_msg)

            # Create a session for OAuth
            session = Session()

            # Configure the session with OAuth authentication
            if not configure_oauth_session(session, self.config.oauth_config):
                error_msg = "Failed to configure OAuth session"
                raise MCPAtlassianAuthenticationError(error_msg)

            # The Bitbucket API URL with OAuth is different
            api_url = f"https://api.atlassian.com/ex/bitbucket/{self.config.oauth_config.cloud_id}"

            # Initialize Bitbucket with the session
            self.bitbucket = Bitbucket(
                url=api_url,
                session=session,
                cloud=True,  # OAuth is only for Cloud
                verify_ssl=self.config.ssl_verify,
            )
        elif self.config.auth_type == "pat":
            logger.debug(
                f"Initializing Bitbucket client with PAT as Basic auth password. "
                f"URL: {self.config.url}, Username: {self.config.username}, "
                f"PAT (masked): {mask_sensitive(str(self.config.personal_token))}"
            )
            self.bitbucket = Bitbucket(
                url=self.config.url,
                cloud=self.config.is_cloud,
                verify_ssl=self.config.ssl_verify,
                token=self.config.personal_token,
            )

        else:  # basic auth
            logger.debug(
                f"Initializing Bitbucket client with Basic auth. "
                f"URL: {self.config.url}, Username: {self.config.username}, "
                f"App Password present: {bool(self.config.app_password)}, "
                f"Is Cloud: {self.config.is_cloud}"
            )
            self.bitbucket = Bitbucket(
                url=self.config.url,
                username=self.config.username,
                password=self.config.app_password,
                cloud=self.config.is_cloud,
                verify_ssl=self.config.ssl_verify,
            )
            logger.debug(
                f"Bitbucket client initialized. Session headers (Authorization masked): "
                f"{get_masked_session_headers(dict(self.bitbucket._session.headers))}"
            )

        # Configure SSL verification using the shared utility
        configure_ssl_verification(
            service_name="Bitbucket",
            url=self.config.url,
            session=self.bitbucket._session,
            ssl_verify=self.config.ssl_verify,
        )

        # Proxy configuration
        proxies = {}
        if self.config.http_proxy:
            proxies["http"] = self.config.http_proxy
        if self.config.https_proxy:
            proxies["https"] = self.config.https_proxy
        if self.config.socks_proxy:
            proxies["http"] = self.config.socks_proxy
            proxies["https"] = self.config.socks_proxy

        if proxies:
            self.bitbucket._session.proxies.update(proxies)
            logger.debug(f"Configured proxies: {proxies}")

        # Configure no_proxy
        if self.config.no_proxy:
            self.bitbucket._session.trust_env = False
            logger.debug(f"Configured no_proxy: {self.config.no_proxy}")

        # Add custom headers
        if self.config.custom_headers:
            self.bitbucket._session.headers.update(self.config.custom_headers)
            logger.debug(
                f"Added custom headers: {get_masked_session_headers(self.config.custom_headers)}"
            )
