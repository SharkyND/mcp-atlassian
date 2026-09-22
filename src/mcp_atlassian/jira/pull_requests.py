"""Module for Jira pull request operations."""

import logging
from typing import Any

from requests.exceptions import HTTPError

from ..exceptions import MCPAtlassianAuthenticationError
from .client import JiraClient

logger = logging.getLogger("mcp-jira")


class PullRequestsMixin(JiraClient):
    """Mixin for retrieving Bitbucket pull requests linked to Jira issues."""

    def get_issue_related_pull_requests(
        self,
        issue_key: str,
        exclude_statuses: list[str] | None = None,
    ) -> dict[str, Any]:
        """
        Get Bitbucket pull requests linked to a Jira issue.

        Args:
            issue_key: Jira issue key (e.g., PROJ-123)
            exclude_statuses: Pull request statuses to omit. Defaults to ["DECLINED"].

        Returns:
            Jira development status response containing filtered pull requests

        Raises:
            MCPAtlassianAuthenticationError: If authentication fails with the Jira API
            Exception: If there is an error retrieving pull requests
        """
        try:
            statuses_to_exclude = {
                status.strip().upper()
                for status in (
                    exclude_statuses if exclude_statuses is not None else ["DECLINED"]
                )
                if status.strip()
            }

            issue = self.jira.get_issue(issue_key, fields="id")
            if not isinstance(issue, dict) or not issue.get("id"):
                msg = f"Issue {issue_key} was not found"
                logger.error(msg)
                raise ValueError(msg)

            response = self.jira.get(
                "rest/dev-status/1.0/issue/detail",
                params={
                    "issueId": str(issue["id"]),
                    "applicationType": "bitbucket" if self.config.is_cloud else "stash",
                    "dataType": "pullrequest",
                },
            )
            if not isinstance(response, dict):
                msg = (
                    "Unexpected return value from Jira development status API: "
                    f"{type(response)}"
                )
                logger.error(msg)
                raise TypeError(msg)

            if statuses_to_exclude:
                for detail in response.get("detail", []):
                    if not isinstance(detail, dict):
                        continue
                    pull_requests = detail.get("pullRequests")
                    if isinstance(pull_requests, list):
                        detail["pullRequests"] = [
                            pull_request
                            for pull_request in pull_requests
                            if not isinstance(pull_request, dict)
                            or str(pull_request.get("status", "")).upper()
                            not in statuses_to_exclude
                        ]
            return response
        except HTTPError as http_err:
            if http_err.response is not None and http_err.response.status_code in (
                401,
                403,
            ):
                error_msg = (
                    f"Authentication failed for Jira API "
                    f"({http_err.response.status_code}). "
                    "Token may be expired or invalid. Please verify credentials."
                )
                logger.error(error_msg)
                raise MCPAtlassianAuthenticationError(error_msg) from http_err
            logger.error(f"HTTP error during API call: {http_err}", exc_info=False)
            raise http_err
        except Exception as e:
            logger.error(
                f"Error getting pull requests for Jira issue '{issue_key}': {str(e)}"
            )
            msg = f"Error getting pull requests: {str(e)}"
            raise Exception(msg) from e
