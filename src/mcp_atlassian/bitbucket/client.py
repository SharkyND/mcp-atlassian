"""Base client module for Bitbucket API interactions."""

import logging
from typing import Any

from atlassian import Bitbucket
from requests import Session
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from mcp_atlassian.exceptions import MCPAtlassianAuthenticationError
from mcp_atlassian.utils.logging import (
    get_masked_session_headers,
)
from mcp_atlassian.utils.oauth import configure_oauth_session
from mcp_atlassian.utils.ssl import configure_ssl_verification
from mcp_atlassian.utils.ssrf_adapter import mount_ssrf_pinning
from mcp_atlassian.utils.urls import make_ssrf_redirect_hook

from .cloud import BitbucketCloudClient
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

        # Bitbucket Cloud and Server/Data Center use different API dialects.
        # Cloud always uses the native REST 2.0 adapter; the third-party client
        # remains in place for Server/Data Center compatibility.
        if self.config.is_cloud:
            session = Session()
            retry = Retry(
                total=3,
                connect=3,
                read=3,
                status=3,
                backoff_factor=0.5,
                status_forcelist=(429, 500, 502, 503, 504),
                allowed_methods=frozenset({"GET", "HEAD", "OPTIONS"}),
                respect_retry_after_header=True,
            )
            adapter = HTTPAdapter(max_retries=retry)
            session.mount("https://", adapter)
            session.mount("http://", adapter)
            if self.config.auth_type == "oauth":
                if not self.config.oauth_config:
                    error_msg = "OAuth authentication requires OAuth configuration"
                    raise ValueError(error_msg)
                if not configure_oauth_session(session, self.config.oauth_config):
                    error_msg = "Failed to configure OAuth session"
                    raise MCPAtlassianAuthenticationError(error_msg)
            elif self.config.auth_type == "pat":
                session.headers["Authorization"] = (
                    f"Bearer {self.config.personal_token}"
                )
            else:
                session.auth = (
                    self.config.username or "",
                    self.config.cloud_api_token or "",
                )

            self.bitbucket = BitbucketCloudClient(
                session=session,
                url=self.config.url,
            )
            logger.debug(
                "Initialized native Bitbucket Cloud REST 2.0 client with %s auth",
                self.config.auth_type,
            )
        elif self.config.auth_type == "pat":
            logger.debug(
                f"Initializing Bitbucket client with PAT as Basic auth password. "
                f"URL: {self.config.url}, Username: {self.config.username}, "
                "PAT authentication selected"
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
                f"Password present: {bool(self.config.app_password)}, "
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
                "Bitbucket client initialized. Session headers "
                f"(Authorization masked): {get_masked_session_headers(dict(self.bitbucket._session.headers))}"
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
            logger.debug("Configured Bitbucket proxies for: %s", list(proxies))

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

        # Protect every HTTP request, including direct Cloud calls and stdio.
        self.bitbucket._session.hooks["response"].append(make_ssrf_redirect_hook())
        mount_ssrf_pinning(self.bitbucket._session)

    def get_pull_request_activities(
        self, workspace: str, repository: str, pull_request_id: int
    ) -> list[dict[str, Any]]:
        """Get comments for a pull request.

        Args:
            workspace: Workspace name (Cloud) or project key (Server/DC)
            repository: Repository name
            pull_request_id: Pull request ID

        Returns:
            List of comment dictionaries
        """
        try:
            if self.config.is_cloud:
                return self.bitbucket.get_pull_request_activities(
                    workspace, repository, pull_request_id
                )

            endpoint = (
                f"projects/{workspace}/repos/{repository}/pull-requests/"
                f"{pull_request_id}/activities"
            )

            response = self.bitbucket.get(endpoint)

            # Handle paginated response
            if isinstance(response, dict) and "values" in response:
                return response["values"]
            elif isinstance(response, list):
                return response
            else:
                return []
        except Exception as e:
            logger.error(
                f"Failed to get pull request comments for {workspace}/{repository}/PR-{pull_request_id}: {e}"
            )
            raise
