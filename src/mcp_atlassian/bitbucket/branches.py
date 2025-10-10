"""Module for Bitbucket branch operations."""

import logging
from typing import Any

from requests.exceptions import HTTPError

from ..exceptions import MCPAtlassianAuthenticationError
from ..models.bitbucket.common import BitbucketBranch, BitbucketCommit, CommitChanges
from .client import BitbucketClient
from .constants import DEFAULT_BRANCH_NAMES

logger = logging.getLogger("mcp-bitbucket")


class BranchesMixin(BitbucketClient):
    """Mixin for Bitbucket branch operations.

    This mixin provides methods for retrieving and working with Bitbucket branches,
    including branch details, commits, and default branch detection.
    """

    def get_all_branches(
        self, workspace: str, repository: str
    ) -> list[BitbucketBranch]:
        """
        Get list of branches for a repository as model objects.

        Args:
            workspace: Workspace name (Cloud) or project key (Server/DC)
            repository: Repository name

        Returns:
            List of BitbucketBranch objects

        Raises:
            MCPAtlassianAuthenticationError: If authentication fails with the Bitbucket API (401/403)
        """
        try:
            # Use the base class method that returns raw dictionaries
            raw_branches = self.bitbucket.get_branches(workspace, repository)
            return [
                BitbucketBranch.from_api_response(branch) for branch in raw_branches
            ]
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
            error_msg = f"Error getting branches for {workspace}/{repository}: {str(e)}"
            logger.error(error_msg)
            raise Exception(f"Error getting branches: {str(e)}") from e

    def get_branches(
        self,
        workspace: str,
        repository: str,
        base: str = None,
        branch_filter: str = None,
        start: int = 0,
        limit: int = None,
    ) -> list[BitbucketBranch]:
        """Get list of branches for a repository.

        Args:
            workspace: Workspace name (Cloud) or project key (Server/DC)
            repository: Repository name,
            base:
            branch_filter:
            start:
            limit:

        Returns:
            List of branch dictionaries
        """
        try:
            return [
                BitbucketBranch.from_api_response(i)
                for i in self.bitbucket.get_branches(
                    workspace,
                    repository,
                    base=base,
                    filter=branch_filter,
                    start=start,
                    limit=limit,
                )
            ]
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
            error_msg = f"Error getting brnches for {workspace}/{repository}: {str(e)}"
            logger.error(error_msg)
            raise Exception(f"Error getting branches: {str(e)}") from e

    def get_default_branch(
        self, workspace: str, repository: str
    ) -> BitbucketBranch | None:
        """
        Get the default branch for a repository.

        Args:
            workspace: Workspace name (Cloud) or project key (Server/DC)
            repository: Repository name

        Returns:
            BitbucketBranch object for the default branch, or None if not found

        Raises:
            MCPAtlassianAuthenticationError: If authentication fails with the Bitbucket API (401/403)
        """
        try:
            # Try to get default branch info from the repository
            try:
                default_branch_data = self.bitbucket.get_default_branch(
                    workspace, repository
                )
                return BitbucketBranch.from_api_response(default_branch_data)
            except HTTPError as http_err:
                # Re-raise HTTPErrors so they can be handled by the outer try-catch
                if http_err.response is not None and http_err.response.status_code in [
                    401,
                    403,
                ]:
                    raise http_err
                # For other HTTP errors, fall back to alternative methods
                branches = self.get_all_branches(workspace, repository)
                for default_name in DEFAULT_BRANCH_NAMES:
                    for branch in branches:
                        if branch.name == default_name:
                            return branch
                # If no common default found, return the first branch
                return branches[0] if branches else None
            except Exception:
                # For non-HTTP errors, fall back to alternative methods
                branches = self.get_all_branches(workspace, repository)
                for default_name in DEFAULT_BRANCH_NAMES:
                    for branch in branches:
                        if branch.name == default_name:
                            return branch
                # If no common default found, return the first branch
                return branches[0] if branches else None
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
                f"Error getting default branch for {workspace}/{repository}: {str(e)}"
            )
            logger.error(error_msg)
            raise Exception(f"Error getting default branch: {str(e)}") from e

    def get_commits(
        self,
        workspace: str,
        repository: str,
        limit: int = 25,
        until: str = None,
        since: str = None,
    ) -> list[BitbucketCommit]:
        """
        Get commit history for a repository branch.

        Args:
            workspace: Workspace name (Cloud) or project key (Server/DC)
            repository: Repository name
            limit: Maximum number of commits to return (default: 25)
            until: The commit ID or ref (inclusively) to retrieve commits before
            since: The commit ID or ref (inclusively) to retrieve commits after
        Returns:
            List of BitbucketCommit objects

        Raises:
            MCPAtlassianAuthenticationError: If authentication fails with the Bitbucket API (401/403)
        """
        try:
            raw_commits = self.bitbucket.get_commits(
                workspace, repository, limit=limit, until=until, since=since
            )
            return [BitbucketCommit.from_api_response(commit) for commit in raw_commits]
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
            error_msg = f"Error getting commits for {workspace}/{repository} : {str(e)}"
            logger.error(error_msg)
            raise Exception(f"Error getting commits: {str(e)}") from e

    def get_commit_changes(
        self,
        workspace: str,
        repository: str,
        commit_id: str,
        merges: str = "include",
        hash_newest: str = None,
    ) -> CommitChanges:
        """
        Get changes for a specific commit in a repository.

        Args:
            workspace: Workspace name (Cloud) or project key (Server/DC)
            repository: Repository name
            hash_newest: Latest hash of the commit to fetch.
            merges: Filter merges ('include', 'exclude', 'only')
            commit_id: Specific commit ID to get changes for

        Returns:
            List of change dictionaries

        Raises:
            MCPAtlassianAuthenticationError: If authentication fails with the Bitbucket API (401/403)
        """
        try:
            changes = self.bitbucket.get_commit_changes(
                project_key=workspace,
                repository_slug=repository,
                hash_newest=hash_newest,
                merges=merges,
                commit_id=commit_id,
            )
            print(changes)
            return CommitChanges.from_api_response(changes)
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
                f"Error getting commit changes for {workspace}/{repository}: {str(e)}"
            )
            logger.error(error_msg)
            raise Exception(f"Error getting commit changes: {str(e)}") from e

    def create_branch(
        self, workspace: str, repository: str, branch_data: dict[str, Any]
    ) -> dict[str, Any]:
        """
        Create a new branch in a repository.

        Args:
            workspace: Workspace name (Cloud) or project key (Server/DC)
            repository: Repository name
            branch_data: Branch data including name and target

        Returns:
            Created branch data

        Raises:
            MCPAtlassianAuthenticationError: If authentication fails with the Bitbucket API (401/403)
        """
        try:
            name = branch_data.get("name", "")
            start_point = None

            # First, try to get start_point from branch_data
            if "target" in branch_data:
                target = branch_data["target"]
                if isinstance(target, dict) and "branch" in target:
                    branch_info = target["branch"]
                    if isinstance(branch_info, dict) and "name" in branch_info:
                        start_point = branch_info["name"]

            # If no start_point specified, get the repository's default branch
            if not start_point:
                default_branch = self.get_default_branch(workspace, repository)
                start_point = default_branch.name if default_branch else "main"
            return self.bitbucket.create_branch(
                workspace, repository, name, start_point
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
            error_msg = f"Error creating branch in {workspace}/{repository}: {str(e)}"
            logger.error(error_msg)
            raise Exception(f"Error creating branch: {str(e)}") from e
