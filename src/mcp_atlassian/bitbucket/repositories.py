"""Module for Bitbucket repository operations."""

import logging
from typing import Any

from requests.exceptions import HTTPError

from ..exceptions import MCPAtlassianAuthenticationError
from ..models.bitbucket.common import BitbucketRepository
from .client import BitbucketClient

logger = logging.getLogger("mcp-bitbucket")


class RepositoriesMixin(BitbucketClient):
    """Mixin for Bitbucket repository operations.

    This mixin provides methods for retrieving and working with Bitbucket repositories,
    including repository details, file content, and directory listings.
    """

    def get_all_repositories(
        self, workspace: str | None = None
    ) -> list[BitbucketRepository]:
        """
        Get list of repositories as model objects.

        Args:
            workspace: Workspace name (Cloud) or project key (Server/DC)

        Returns:
            List of BitbucketRepository objects, filtered by workspaces_filter if configured

        Raises:
            MCPAtlassianAuthenticationError: If authentication fails with the Bitbucket API (401/403)
        """
        try:
            # Use the base class method that returns raw dictionaries
            raw_repos = self.bitbucket.get_repositories(workspace)
            return raw_repos
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
            error_msg = f"Error getting repositories: {str(e)}"
            logger.error(error_msg)
            raise Exception(f"Error getting repositories: {str(e)}") from e

    def get_repository_info(
        self, workspace: str, repository: str
    ) -> BitbucketRepository:
        """
        Get detailed information about a specific repository.

        Args:
            workspace: Workspace name or project key
            repository: Repository name

        Returns:
            BitbucketRepository object

        Raises:
            MCPAtlassianAuthenticationError: If authentication fails with the Bitbucket API (401/403)
        """
        try:
            repo_data = self.bitbucket.get_repo(workspace, repository)
            return BitbucketRepository.from_api_response(repo_data)
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
                f"Error getting repository info for {workspace}/{repository}: {str(e)}"
            )
            logger.error(error_msg)
            raise Exception(f"Error getting repository info: {str(e)}") from e

    def get_file_content(
        self, workspace: str, repository: str, path: str, branch: str = "main"
    ) -> bytes:
        """
        Get file content from repository.

        Args:
            workspace: Workspace name (Cloud) or project key (Server/DC)
            repository: Repository name
            path: File path in repository
            branch: Branch name (default: main)

        Returns:
            File content as string

        Raises:
            MCPAtlassianAuthenticationError: If authentication fails with the Bitbucket API (401/403)
        """
        try:

            return self.bitbucket.get_content_of_file(workspace, repository, path, branch)
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
            error_msg = f"Error getting file content for {workspace}/{repository}/{path}: {str(e)}"
            logger.error(error_msg)
            raise Exception(f"Error getting file content: {str(e)}") from e

    def get_directory_content(
        self, workspace: str, repository: str, path: str = "", branch: str = "main"
    ) -> list[dict[str, Any]]:
        """
        List the contents of a directory in a repository.

        Args:
            workspace: Workspace name (Cloud) or project key (Server/DC)
            repository: Repository name
            path: Directory path in the repository (empty for root)
            branch: Branch name (default: main)

        Returns:
            List of directory contents

        Raises:
            MCPAtlassianAuthenticationError: If authentication fails with the Bitbucket API (401/403)
        """
        try:
            return self.bitbucket.get_directory_content(workspace, repository, path, branch)
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
            error_msg = f"Error getting directory content for {workspace}/{repository}/{path}: {str(e)}"
            logger.error(error_msg)
            raise Exception(f"Error getting directory content: {str(e)}") from e

    def upload_file(
        self, workspace: str, repository: str, content: str, message: str, branch: str, filename: str
    ) -> dict[str, Any]:
        """
        Upload or update a file in a repository.

        Args:
            workspace: Workspace name (Cloud) or project key (Server/DC)
            repository: Repository name
            content: file content
            message: commit message
            branch: branch where file will be created
            filename: path of the file

        Returns:
            Created commit data

        Raises:
            MCPAtlassianAuthenticationError: If authentication fails with the Bitbucket API (401/403)
        """
        try:

            return self.bitbucket.upload_file(
                workspace, repository, str(content), message, branch, filename
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
            error_msg = f"Error uploading file to {workspace}/{repository}: {str(e)}"
            logger.error(error_msg)
            raise Exception(f"Error uploading file: {str(e)}") from e


    def update_file(
        self, workspace: str, repository: str, content, message, branch, filename, source_commit_id
    ) -> dict[str, Any]:
        """
        Update a file in a repository.

        Args:
            workspace: Workspace name (Cloud) or project key (Server/DC)
            repository: Repository name
            content: The file contents to replace with.
            message: Commit message
            branch: Existing branch to update the file on.
            filename: Name of the file to update. It must exist.
            source_commit_id: A previous commit ID must be provided when editing an existing file to prevent concurrent modifications.

        Returns:
            Created commit data

        Raises:
            MCPAtlassianAuthenticationError: If authentication fails with the Bitbucket API (401/403)
        """
        try:
            return self.bitbucket.update_file(workspace, repository,
                                              str(content), message, branch, filename, source_commit_id)
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
            error_msg = f"Error uploading file to {workspace}/{repository}: {str(e)}"
            logger.error(error_msg)
            raise Exception(f"Error uploading file: {str(e)}") from e
