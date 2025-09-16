"""Base client module for Bitbucket API interactions."""

import logging
from typing import Any

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
            # For Bitbucket, PAT should be used as password in Basic Auth, not as token
            self.bitbucket = Bitbucket(
                url=self.config.url,
                username=self.config.username,  # Username is required for PAT auth
                password=self.config.personal_token,  # PAT goes in password field
                cloud=self.config.is_cloud,
                verify_ssl=self.config.ssl_verify,
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

    # def get_workspaces(self) -> list[dict[str, Any]]:
    #     """Get list of accessible workspaces.
    #
    #     Returns:
    #         List of workspace dictionaries
    #     """
    #     try:
    #         if self.config.is_cloud:
    #             # For Bitbucket Cloud, use workspaces endpoint
    #             raw_workspaces = self.bitbucket.get("workspaces")
    #             if isinstance(raw_workspaces, dict) and "values" in raw_workspaces:
    #                 raw_workspaces = raw_workspaces["values"]
    #             elif not isinstance(raw_workspaces, list):
    #                 raw_workspaces = []
    #         else:
    #             # For Bitbucket Server/DC, use projects endpoint
    #             raw_workspaces = self.bitbucket.project_list()
    #
    #         # Apply workspace filtering if configured
    #         if self.config.workspaces_filter:
    #             allowed_workspaces = [
    #                 ws.strip() for ws in self.config.workspaces_filter.split(",")
    #             ]
    #             filtered_workspaces = []
    #             for workspace in raw_workspaces:
    #                 # Check workspace name/slug/uuid depending on the platform
    #                 workspace_id = (
    #                     workspace.get("uuid")
    #                     or workspace.get("name")
    #                     or workspace.get("key")
    #                     or workspace.get("slug")
    #                 )
    #                 if workspace_id and workspace_id in allowed_workspaces:
    #                     filtered_workspaces.append(workspace)
    #             logger.debug(
    #                 f"Filtered workspaces from {len(raw_workspaces)} to {len(filtered_workspaces)} based on filter: {self.config.workspaces_filter}"
    #             )
    #             return filtered_workspaces
    #
    #         return raw_workspaces
    #     except Exception as e:
    #         logger.error(f"Failed to get workspaces: {e}")
    #         raise
    #
    #

    # def get_file_content(
    #     self, workspace: str, repository: str, path: str, branch: str = "main"
    # ) -> str:
    #     """Get file content from repository.
    #
    #     Args:
    #         workspace: Workspace name (Cloud) or project key (Server/DC)
    #         repository: Repository name
    #         path: File path in repository
    #         branch: Branch name (default: main)
    #
    #     Returns:
    #         File content as string
    #     """
    #     try:
    #         return self.bitbucket.get_content_of_file(
    #             workspace, repository, path, branch
    #         )
    #     except Exception as e:
    #         logger.error(
    #             f"Failed to get file content for {workspace}/{repository}/{path}: {e}"
    #         )
    #         raise
    #

    # def get_pull_request_commits(
    #     self, workspace: str, repository: str, pull_request_id: int
    # ) -> list[dict[str, Any]]:
    #     """Get commits for a pull request.
    #
    #     Args:
    #         workspace: Workspace name (Cloud) or project key (Server/DC)
    #         repository: Repository name
    #         pull_request_id: Pull request ID
    #
    #     Returns:
    #         List of commit dictionaries
    #     """
    #     try:
    #         # Use the generic get method with the appropriate endpoint
    #         if self.config.is_cloud:
    #             # Bitbucket Cloud API 2.0
    #             endpoint = f"repositories/{workspace}/{repository}/pullrequests/{pull_request_id}/commits"
    #         else:
    #             # Bitbucket Server/DC API 1.0
    #             endpoint = f"projects/{workspace}/repos/{repository}/pull-requests/{pull_request_id}/commits"
    #
    #         response = self.bitbucket.get(endpoint)
    #
    #         # Handle paginated response
    #         if isinstance(response, dict) and "values" in response:
    #             return response["values"]
    #         elif isinstance(response, list):
    #             return response
    #         else:
    #             return []
    #     except Exception as e:
    #         logger.error(
    #             f"Failed to get pull request commits for {workspace}/{repository}/PR-{pull_request_id}: {e}"
    #         )
    #         raise
    #
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
            # Use the generic get method with the appropriate endpoint
            if self.config.is_cloud:
                # Bitbucket Cloud API 2.0
                endpoint = f"repositories/{workspace}/{repository}/pullrequests/{pull_request_id}/activities"
            else:
                # Bitbucket Server/DC API 1.0
                endpoint = f"projects/{workspace}/repos/{repository}/pull-requests/{pull_request_id}/activities"

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

    #
    # def get_file(
    #     self, workspace: str, repository: str, path: str, branch: str = "main"
    # ) -> dict[str, Any]:
    #     """Get file metadata and content from repository.
    #
    #     Args:
    #         workspace: Workspace name (Cloud) or project key (Server/DC)
    #         repository: Repository name
    #         path: File path in repository
    #         branch: Branch name (default: main)
    #
    #     Returns:
    #         File metadata dictionary
    #     """
    #     try:
    #         # Use the generic get method with the appropriate endpoint
    #         if self.config.is_cloud:
    #             # Bitbucket Cloud API 2.0
    #             endpoint = f"repositories/{workspace}/{repository}/src/{branch}/{path}"
    #         else:
    #             # Bitbucket Server/DC API 1.0
    #             endpoint = (
    #                 f"projects/{workspace}/repos/{repository}/browse/{path}?at={branch}"
    #             )
    #
    #         return self.bitbucket.get(endpoint)
    #     except Exception as e:
    #         logger.error(
    #             f"Failed to get file metadata for {workspace}/{repository}/{path}: {e}"
    #         )
    #         raise
    #
    # def get_directory_content(
    #     self, workspace: str, repository: str, path: str = "", branch: str = "main"
    # ) -> list[dict[str, Any]]:
    #     """Get directory contents from repository.
    #
    #     Args:
    #         workspace: Workspace name (Cloud) or project key (Server/DC)
    #         repository: Repository name
    #         path: Directory path in repository (empty for root)
    #         branch: Branch name (default: main)
    #
    #     Returns:
    #         List of directory content dictionaries
    #     """
    #     try:
    #         if self.config.is_cloud:
    #             endpoint = f"repositories/{workspace}/{repository}/src/{branch}/{path}"
    #         else:
    #             endpoint = (
    #                 f"projects/{workspace}/repos/{repository}/browse/{path}?at={branch}"
    #             )
    #
    #         response = self.bitbucket.get(endpoint)
    #
    #         if isinstance(response, dict) and "values" in response:
    #             return response["values"]
    #         elif isinstance(response, list):
    #             return response
    #         else:
    #             return []
    #     except Exception as e:
    #         logger.error(
    #             f"Failed to get directory content for {workspace}/{repository}/{path}: {e}"
    #         )
    #         raise
