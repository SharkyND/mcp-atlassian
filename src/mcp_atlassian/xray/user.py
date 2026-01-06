"""Users mixin for Xray API interactions."""

import logging
from typing import Any

from requests.exceptions import HTTPError

from mcp_atlassian.exceptions import MCPAtlassianAuthenticationError
from mcp_atlassian.utils.logging import mask_sensitive

from .client import XrayClient

logger = logging.getLogger(__name__)


class MixUsers(XrayClient):
    """Mixin for Xray user operations."""

    def get_current_user_info(self) -> dict[str, Any]:
        """
        Retrieve details for the currently authenticated user by calling Xray's
        user endpoint.

        Returns:
            dict[str, Any]: The user details as returned by the API.

        Raises:
            MCPAtlassianAuthenticationError: If authentication fails or the
                response is not valid user data.
        """
        if self.config.auth_type == "pat":
            logger.info(
                f"Xray PAT auth - PAT (masked): "
                f"{mask_sensitive(self.config.personal_token)}"
            )
        else:
            logger.info(f"Xray auth type: {self.config.auth_type}")

        try:
            try:
                user_data = self.xray.get("rest/api/2/myself")
                logger.info("Successfully retrieved real user data from Jira API")
            except HTTPError as err:
                if err.response is not None and err.response.status_code in (
                    404,
                    401,
                    403,
                ):
                    logger.warning(
                        f"Xray 'myself' endpoint failed with {err.response.status_code}. "
                        "Attempting alternative validation."
                    )
                    try:
                        test_statuses = self.xray.get("rest/raven/1.0/test/status")
                        if test_statuses:
                            # If successful, create mock data based on config
                            username = self.config.username
                            user_data = {
                                "accountId": f"{username}",
                                "displayName": f"({username})",
                                "emailAddress": f"{username}@domain.co",
                                "active": True,
                                "mock_data": True,
                            }
                            logger.info(
                                f"Xray token validated via test/status endpoint. "
                                f"Using mock data for user: {username}"
                            )
                        else:
                            raise ValueError(
                                "Empty response from Xray test/status endpoint"
                            )
                    except Exception as validation_err:
                        logger.error(f"Xray token validation failed: {validation_err}")
                        raise err from validation_err
                else:
                    raise err

            if not isinstance(user_data, dict):
                logger.error(
                    f"Xray user endpoint returned non-dict data type: "
                    f"{type(user_data)}. "
                    f"Response text (partial): {str(user_data)[:500]}"
                )
                raise MCPAtlassianAuthenticationError(
                    "Xray token validation failed: Did not receive valid JSON "
                    "user data from user endpoint."
                )

            username = (
                user_data.get("displayName")
                or user_data.get("name")
                or user_data.get("accountId")
                or "unknown"
            )
            if user_data.get("mock_data"):
                logger.info(
                    f"Using mock user data for username: {username} "
                    "(actual validation will happen on API calls)"
                )
            else:
                logger.info(f"Successfully retrieved user data for: {username}")
            return user_data

        except HTTPError as http_err:
            if http_err.response is not None:
                logger.warning(
                    f"Xray authentication failed with HTTP "
                    f"{http_err.response.status_code}. "
                    f"Check that access is correct and have proper permissions."
                )
                msg = (
                    f"Xray authentication failed: "
                    f"{http_err.response.status_code} - verify access"
                )
                raise MCPAtlassianAuthenticationError(msg) from http_err
            logger.error(
                f"HTTPError when calling Xray user endpoint: {http_err}",
                exc_info=True,
            )
            msg = f"Xray API call failed with HTTPError: {http_err}"
            raise MCPAtlassianAuthenticationError(msg) from http_err
        except Exception as e:
            logger.error(
                f"Unexpected error fetching current Xray user details: {e}",
                exc_info=True,
            )
            msg = f"Xray user info retrieval failed: {e}"
            raise MCPAtlassianAuthenticationError(msg) from e
