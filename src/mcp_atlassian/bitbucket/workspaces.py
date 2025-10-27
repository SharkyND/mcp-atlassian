"""Module for Bitbucket workspace operations."""

import logging

from requests.exceptions import HTTPError

from ..exceptions import MCPAtlassianAuthenticationError
from ..models.bitbucket.common import BitbucketWorkspace
from .client import BitbucketClient

logger = logging.getLogger("mcp-bitbucket")


class WorkspacesMixin(BitbucketClient):
    """Mixin for Bitbucket workspace operations.

    This mixin provides methods for retrieving and working with Bitbucket workspaces,
    including workspace details and filtering based on configuration.
    """

    def get_all_workspaces(self) -> list[BitbucketWorkspace]:
        """
        Get all workspaces visible to the current user.

        Returns:
            List of BitbucketWorkspace objects, filtered by workspaces_filter if configured

        Raises:
            MCPAtlassianAuthenticationError: If authentication fails with the Bitbucket API (401/403)
        """
        try:
            raw_workspaces = self.bitbucket.project_list()

            # Convert to model objects
            workspaces = [
                BitbucketWorkspace.from_api_response(ws) for ws in raw_workspaces
            ]

            # Apply workspace filtering if configured
            if self.config.workspaces_filter:
                allowed_workspaces = [
                    ws.strip() for ws in self.config.workspaces_filter.split(",")
                ]
                filtered_workspaces = []
                for workspace in workspaces:
                    # Check workspace name, slug, or uuid
                    if (
                        workspace.name in allowed_workspaces
                        or workspace.slug in allowed_workspaces
                        or workspace.uuid in allowed_workspaces
                    ):
                        filtered_workspaces.append(workspace)
                logger.debug(
                    f"Filtered workspaces from {len(workspaces)} to {len(filtered_workspaces)} based on filter: {self.config.workspaces_filter}"
                )
                return filtered_workspaces

            return workspaces
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
            error_msg = f"Error getting workspaces: {str(e)}"
            logger.error(error_msg)
            msg = f"Error getting workspaces: {str(e)}"
            raise Exception(msg) from e

    def get_workspace_by_id(self, workspace_id: str) -> BitbucketWorkspace | None:
        """
        Get a specific workspace by its ID.

        Args:
            workspace_id: The workspace ID, name, or slug

        Returns:
            BitbucketWorkspace object or None if not found

        Raises:
            MCPAtlassianAuthenticationError: If authentication fails with the Bitbucket API (401/403)
        """
        try:
            workspaces = self.get_all_workspaces()
            for workspace in workspaces:
                if (
                    workspace.uuid == workspace_id
                    or workspace.name == workspace_id
                    or workspace.slug == workspace_id
                ):
                    return workspace
            return None
        except Exception as e:
            error_msg = f"Error getting workspace {workspace_id}: {str(e)}"
            logger.error(error_msg)
            msg = f"Error getting workspace: {str(e)}"
            raise Exception(msg) from e
