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
            ValueError: If the issue does not exist
            TypeError: If the development status API returns an unexpected type
            MCPAtlassianAuthenticationError: If Jira rejects the request with a
                401 (bad credentials) or 403 (missing "View Development Tools"
                permission)
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
                status_code = http_err.response.status_code
                detail = self._extract_error_detail(http_err)
                # The dev-status API returns 403 when the account lacks the
                # "View Development Tools" permission, which is this endpoint's
                # most common failure and is not a credential problem.
                if status_code == 403 or "permission" in detail.lower():
                    error_msg = (
                        f"Permission denied for Jira API ({status_code}). This "
                        "usually means the account lacks the 'View Development "
                        "Tools' permission required to read linked pull requests. "
                        f"Server response: {detail}"
                    )
                else:
                    error_msg = (
                        f"Authentication failed for Jira API ({status_code}). "
                        "Token may be expired or invalid. Please verify "
                        f"credentials. Server response: {detail}"
                    )
                logger.error(error_msg)
                raise MCPAtlassianAuthenticationError(error_msg) from http_err
            logger.error(f"HTTP error during API call: {http_err}", exc_info=False)
            raise http_err
        except (ValueError, TypeError, MCPAtlassianAuthenticationError):
            # Already specific and logged at the raise site; re-raise as-is so
            # callers can distinguish them from unexpected failures below.
            raise
        except Exception as e:
            logger.error(
                f"Error getting pull requests for Jira issue '{issue_key}': {str(e)}"
            )
            msg = f"Error getting pull requests: {str(e)}"
            raise Exception(msg) from e
