"""Module for Bitbucket pull request operations."""

import logging
from typing import Any

from requests.exceptions import HTTPError

from ..exceptions import MCPAtlassianAuthenticationError
from ..models.bitbucket.common import BitbucketPullRequest
from .client import BitbucketClient
from .constants import PR_STATES

logger = logging.getLogger("mcp-bitbucket")


class PullRequestsMixin(BitbucketClient):
    """Mixin for Bitbucket pull request operations.

    This mixin provides methods for retrieving and working with Bitbucket pull requests,
    including PR details, filtering by state, and related operations.
    """

    def get_all_pull_requests(
        self, workspace: str, repository: str, state: str = "OPEN"
    ) -> list[BitbucketPullRequest]:
        """
        Get list of pull requests as model objects.

        Args:
            workspace: Workspace name (Cloud) or project key (Server/DC)
            repository: Repository name
            state: PR state (OPEN, MERGED, DECLINED, SUPERSEDED)

        Returns:
            List of BitbucketPullRequest objects

        Raises:
            MCPAtlassianAuthenticationError: If authentication fails with the Bitbucket API (401/403)
        """
        try:
            # Validate state
            if state not in PR_STATES.values():
                logger.warning(f"Invalid PR state '{state}', using 'OPEN' instead")
                state = "OPEN"

            # Use the base class method that returns raw dictionaries
            raw_prs = self.bitbucket.get_pull_requests(workspace, repository, state)
            return [BitbucketPullRequest.from_api_response(pr) for pr in raw_prs]
        except HTTPError as http_err:
            if http_err.response is not None and http_err.response.status_code in [
                401,
                403,
            ]:
                error_msg = (
                    f"Authentication failed for Bitbucket API ({http_err.response.status_code}). "
                    "Token may be expired or invalid. Please verify credentials."
                )
                logger.error(error_msg)
                raise MCPAtlassianAuthenticationError(error_msg) from http_err
            else:
                logger.error(f"HTTP error during API call: {http_err}", exc_info=False)
                raise http_err
        except Exception as e:
            error_msg = (
                f"Error getting pull requests for {workspace}/{repository}: {str(e)}"
            )
            logger.error(error_msg)
            msg = f"Error getting pull requests: {str(e)}"
            raise Exception(msg) from e

    def get_pull_request(
        self, workspace: str, repository: str, pull_request_id: int
    ) -> BitbucketPullRequest:
        """
        Get detailed information about a specific pull request.

        Args:
            workspace: Workspace name (Cloud) or project key (Server/DC)
            repository: Repository name
            pull_request_id: Pull request ID

        Returns:
            BitbucketPullRequest object

        Raises:
            MCPAtlassianAuthenticationError: If authentication fails with the Bitbucket API (401/403)
        """
        try:
            pr_data = self.bitbucket.get_pull_request(
                workspace, repository, pull_request_id
            )
            return BitbucketPullRequest.from_api_response(pr_data)
        except HTTPError as http_err:
            if http_err.response is not None and http_err.response.status_code in [
                401,
                403,
            ]:
                error_msg = (
                    f"Authentication failed for Bitbucket API ({http_err.response.status_code}). "
                    "Token may be expired or invalid. Please verify credentials."
                )
                logger.error(error_msg)
                raise MCPAtlassianAuthenticationError(error_msg) from http_err
            else:
                logger.error(f"HTTP error during API call: {http_err}", exc_info=False)
                raise http_err
        except Exception as e:
            error_msg = f"Error getting pull request {pull_request_id} for {workspace}/{repository}: {str(e)}"
            logger.error(error_msg)
            msg = f"Error getting pull request: {str(e)}"
            raise Exception(msg) from e

    def get_pull_request_commits(
        self, workspace: str, repository: str, pull_request_id: int
    ) -> list[dict[str, Any]]:
        """
        Get commits associated with a pull request.

        Args:
            workspace: Workspace name (Cloud) or project key (Server/DC)
            repository: Repository name
            pull_request_id: Pull request ID

        Returns:
            List of commit data

        Raises:
            MCPAtlassianAuthenticationError: If authentication fails with the Bitbucket API (401/403)
        """
        try:
            # Use the base class method that implements the actual API call
            return self.bitbucket.get_pull_requests_commits(
                workspace, repository, pull_request_id
            )
        except HTTPError as http_err:
            if http_err.response is not None and http_err.response.status_code in [
                401,
                403,
            ]:
                error_msg = (
                    f"Authentication failed for Bitbucket API ({http_err.response.status_code}). "
                    "Token may be expired or invalid. Please verify credentials."
                )
                logger.error(error_msg)
                raise MCPAtlassianAuthenticationError(error_msg) from http_err
            else:
                logger.error(f"HTTP error during API call: {http_err}", exc_info=False)
                raise http_err
        except Exception as e:
            error_msg = f"Error getting commits for PR {pull_request_id} in {workspace}/{repository}: {str(e)}"
            logger.error(error_msg)
            msg = f"Error getting PR commits: {str(e)}"
            raise Exception(msg) from e

    def get_pull_requests(
        self, workspace: str, repository: str, state: str = "OPEN"
    ) -> list[dict[str, Any]]:
        """Get list of pull requests.

        Args:
            workspace: Workspace name (Cloud) or project key (Server/DC)
            repository: Repository name
            state: PR state (OPEN, MERGED, DECLINED)

        Returns:
            List of pull request dictionaries
        """
        try:
            return self.bitbucket.get_pull_requests(workspace, repository, state=state)
        except HTTPError as http_err:
            if http_err.response is not None and http_err.response.status_code in [
                401,
                403,
            ]:
                error_msg = (
                    f"Authentication failed for Bitbucket API ({http_err.response.status_code}). "
                    "Token may be expired or invalid. Please verify credentials."
                )
                logger.error(error_msg)
                raise MCPAtlassianAuthenticationError(error_msg) from http_err
            else:
                logger.error(f"HTTP error during API call: {http_err}", exc_info=False)
                raise http_err
        except Exception as e:
            error_msg = (
                f"Error getting pull requests in {workspace}/{repository}: {str(e)}"
            )
            logger.error(error_msg)
            msg = f"Error getting PRs: {str(e)}"
            raise Exception(msg) from e

    def get_pull_request_activities(
        self, workspace: str, repository: str, pull_request_id: int
    ) -> list[dict[str, Any]]:
        """
        Get comments for a pull request.

        Args:
            workspace: Workspace name (Cloud) or project key (Server/DC)
            repository: Repository name
            pull_request_id: Pull request ID

        Returns:
            List of comment data

        Raises:
            MCPAtlassianAuthenticationError: If authentication fails with the Bitbucket API (401/403)
        """
        try:
            return super().get_pull_request_activities(
                workspace, repository, pull_request_id
            )
        except HTTPError as http_err:
            if http_err.response is not None and http_err.response.status_code in [
                401,
                403,
            ]:
                error_msg = (
                    f"Authentication failed for Bitbucket API ({http_err.response.status_code}). "
                    "Token may be expired or invalid. Please verify credentials."
                )
                logger.error(error_msg)
                raise MCPAtlassianAuthenticationError(error_msg) from http_err
            else:
                logger.error(f"HTTP error during API call: {http_err}", exc_info=False)
                raise http_err
        except Exception as e:
            error_msg = f"Error getting comments for PR {pull_request_id} in {workspace}/{repository}: {str(e)}"
            logger.error(error_msg)
            msg = f"Error getting PR comments: {str(e)}"
            raise Exception(msg) from e

    def create_pull_request(
        self, workspace: str, repository: str, pr_data: dict[str, Any]
    ) -> dict[str, Any]:
        """
        Create a new pull request.

        Args:
            workspace: Workspace name (Cloud) or project key (Server/DC)
            repository: Repository name
            pr_data: Pull request data including title, description, source, and destination

        Returns:
            Created pull request data

        Raises:
            MCPAtlassianAuthenticationError: If authentication fails with the Bitbucket API (401/403)
        """
        try:
            return self.bitbucket.create_pull_request(workspace, repository, pr_data)
        except HTTPError as http_err:
            if http_err.response is not None and http_err.response.status_code in [
                401,
                403,
            ]:
                error_msg = (
                    f"Authentication failed for Bitbucket API ({http_err.response.status_code}). "
                    "Token may be expired or invalid. Please verify credentials."
                )
                logger.error(error_msg)
                raise MCPAtlassianAuthenticationError(error_msg) from http_err
            else:
                logger.error(f"HTTP error during API call: {http_err}", exc_info=False)
                raise http_err
        except Exception as e:
            error_msg = (
                f"Error creating pull request in {workspace}/{repository}: {str(e)}"
            )
            logger.error(error_msg)
            msg = f"Error creating pull request: {str(e)}"
            raise Exception(msg) from e

    def add_pull_request_comment(
        self,
        workspace: str,
        repository: str,
        pull_request_id: int,
        comment_data: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Add a comment to a pull request.

        Args:
            workspace: Workspace name (Cloud) or project key (Server/DC)
            repository: Repository name
            pull_request_id: Pull request ID
            comment_data: Comment data including content

        Returns:
            Created comment data

        Raises:
            MCPAtlassianAuthenticationError: If authentication fails with the Bitbucket API (401/403)
        """
        try:
            return self.bitbucket.add_pull_request_comment(
                workspace, repository, pull_request_id, comment_data
            )
        except HTTPError as http_err:
            if http_err.response is not None and http_err.response.status_code in [
                401,
                403,
            ]:
                error_msg = (
                    f"Authentication failed for Bitbucket API ({http_err.response.status_code}). "
                    "Token may be expired or invalid. Please verify credentials."
                )
                logger.error(error_msg)
                raise MCPAtlassianAuthenticationError(error_msg) from http_err
            else:
                logger.error(f"HTTP error during API call: {http_err}", exc_info=False)
                raise http_err
        except Exception as e:
            error_msg = f"Error adding comment to PR {pull_request_id} in {workspace}/{repository}: {str(e)}"
            logger.error(error_msg)
            msg = f"Error adding PR comment: {str(e)}"
            raise Exception(msg) from e

    def add_pull_request_blocker_comment(
        self,
        workspace: str,
        repository: str,
        pull_request_id: int,
        comment: str,
        severity: str = None,
    ) -> dict[str, Any]:
        """
        Add a blocker comment on a pull request.
        Args:
            workspace: Workspace name (Cloud) or project key (Server/DC)
            repository: Repository name
            pull_request_id: Pull request ID
            comment: Comment data including content
            severity: Severity of the blocker. The severity must be one of: [NORMAL, BLOCKER], or it can be omitted.

        Returns:
            Created comment data

        Raises:
            MCPAtlassianAuthenticationError: If authentication fails with the Bitbucket API (401/403)
        """
        try:
            return self.bitbucket.add_pull_request_blocker_comment(
                workspace, repository, pull_request_id, comment, severity=severity
            )
        except HTTPError as http_err:
            if http_err.response is not None and http_err.response.status_code in [
                401,
                403,
            ]:
                error_msg = (
                    f"Authentication failed for Bitbucket API ({http_err.response.status_code}). "
                    "Token may be expired or invalid. Please verify credentials."
                )
                logger.error(error_msg)
                raise MCPAtlassianAuthenticationError(error_msg) from http_err
            else:
                logger.error(f"HTTP error during API call: {http_err}", exc_info=False)
                raise http_err
        except Exception as e:
            error_msg = f"Error adding blocker comment to PR {pull_request_id} in {workspace}/{repository}: {str(e)}"
            logger.error(error_msg)
            msg = f"Error blocker adding PR comment: {str(e)}"
            raise Exception(msg) from e
