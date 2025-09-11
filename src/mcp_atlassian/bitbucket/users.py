"""Users mixin for Bitbucket API interactions."""

import logging
from typing import Any

from requests.exceptions import HTTPError

from mcp_atlassian.exceptions import MCPAtlassianAuthenticationError
from mcp_atlassian.utils.logging import mask_sensitive

from .client import BitbucketClient

logger = logging.getLogger(__name__)


class UsersMixin(BitbucketClient):
    """Mixin for Bitbucket user operations."""

    def get_current_user_info(self) -> dict[str, Any]:
        """
        Retrieve details for the currently authenticated user by calling Bitbucket's user endpoint.

        Returns:
            dict[str, Any]: The user details as returned by the API.

        Raises:
            MCPAtlassianAuthenticationError: If authentication fails or the response is not valid user data.
        """
        if self.config.auth_type == "pat":
            logger.info(
                f"Bitbucket PAT auth - Username: {self.config.username}, PAT (masked): {mask_sensitive(self.config.personal_token)}"
            )
        else:
            logger.info(
                f"Bitbucket auth type: {self.config.auth_type}, Username: {self.config.username}"
            )

        try:
            if self.config.is_cloud:
                user_data = self.bitbucket.get("user")
            else:
                try:
                    user_data = self.bitbucket.get("/plugins/servlet/applinks/whoami")
                except Exception as e:
                    logger.info(f"Bitbucket Server/DC whoami endpoint failed: {e}")
                    logger.info(
                        "Creating mock user data from configured username since whoami endpoint is not accessible"
                    )
                    # Create a mock user data dict using the configured username
                    # If username is wrong, downstream API calls will fail with proper errors
                    user_data = {
                        "username": self.config.username,
                        "name": self.config.username,
                        "displayName": self.config.username,
                        "email": f"{self.config.username}@its.jnj.com",
                        "type": "normal",
                        "mock_data": True,
                    }

            if not isinstance(user_data, dict):
                logger.error(
                    f"Bitbucket user endpoint returned non-dict data type: {type(user_data)}. "
                    f"Response text (partial): {str(user_data)[:500]}"
                )
                raise MCPAtlassianAuthenticationError(
                    "Bitbucket token validation failed: Did not receive valid JSON user data from user endpoint."
                )

            username = (
                user_data.get("username")
                or user_data.get("name")
                or user_data.get("displayName")
                or "unknown"
            )
            if user_data.get("mock_data"):
                logger.info(
                    f"Using mock user data for username: {username} (actual validation will happen on API calls)"
                )
            else:
                logger.info(f"Successfully retrieved user data for: {username}")
            return user_data

        except HTTPError as http_err:
            if http_err.response is not None and http_err.response.status_code in [
                401,
                403,
            ]:
                logger.warning(
                    f"Bitbucket authentication failed with HTTP {http_err.response.status_code}. "
                    f"Check that username and PAT are correct and have proper permissions."
                )
                raise MCPAtlassianAuthenticationError(
                    f"Bitbucket authentication failed: {http_err.response.status_code} - verify username and PAT"
                ) from http_err
            logger.error(
                f"HTTPError when calling Bitbucket user endpoint: {http_err}",
                exc_info=True,
            )
            raise MCPAtlassianAuthenticationError(
                f"Bitbucket API call failed with HTTPError: {http_err}"
            ) from http_err
        except Exception as e:
            logger.error(
                f"Unexpected error fetching current Bitbucket user details: {e}",
                exc_info=True,
            )
            raise MCPAtlassianAuthenticationError(
                f"Bitbucket user info retrieval failed: {e}"
            ) from e
