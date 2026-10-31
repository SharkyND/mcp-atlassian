"""Module for Jira search operations."""

import logging
from typing import Any

import requests
from requests.exceptions import HTTPError

from ..exceptions import MCPAtlassianAuthenticationError
from ..models.jira import JiraSearchResult
from .client import JiraClient
from .constants import DEFAULT_READ_JIRA_FIELDS
from .protocols import IssueOperationsProto

logger = logging.getLogger("mcp-jira")


class SearchMixin(JiraClient, IssueOperationsProto):
    """Mixin for Jira search operations."""

    def search_issues(
        self,
        jql: str,
        fields: list[str] | tuple[str, ...] | set[str] | str | None = None,
        start: int = 0,
        limit: int = 50,
        expand: str | None = None,
        projects_filter: str | None = None,
    ) -> JiraSearchResult:
        """
        Search for issues using JQL (Jira Query Language).

        Args:
            jql: JQL query string
            fields: Fields to return (comma-separated string, list, tuple, set, or "*all")
            start: Starting index if number of issues is greater than the limit
                  Note: This parameter is ignored in Cloud environments and results will always
                  start from the first page.
            limit: Maximum issues to return
            expand: Optional items to expand (comma-separated)
            projects_filter: Optional comma-separated list of project keys to filter by, overrides config

        Returns:
            JiraSearchResult object containing issues and metadata (total, start_at, max_results)

        Raises:
            MCPAtlassianAuthenticationError: If authentication fails with the Jira API (401/403)
            Exception: If there is an error searching for issues
        """
        try:
            # Use projects_filter parameter if provided, otherwise fall back to config
            filter_to_use = projects_filter or self.config.projects_filter

            # Apply projects filter if present
            if filter_to_use:
                # Split projects filter by commas and handle possible whitespace
                projects = [p.strip() for p in filter_to_use.split(",")]

                # Build the project filter query part
                if len(projects) == 1:
                    project_query = f'project = "{projects[0]}"'
                else:
                    quoted_projects = [f'"{p}"' for p in projects]
                    projects_list = ", ".join(quoted_projects)
                    project_query = f"project IN ({projects_list})"

                # Add the project filter to existing query
                if not jql:
                    # Empty JQL - just use project filter
                    jql = project_query
                elif jql.strip().upper().startswith("ORDER BY"):
                    # JQL starts with ORDER BY - prepend project filter
                    jql = f"{project_query} {jql}"
                elif "project = " not in jql and "project IN" not in jql:
                    # Only add if not already filtering by project
                    jql = f"({jql}) AND {project_query}"

                logger.info(f"Applied projects filter to query: {jql}")

            # Convert fields to proper format if it's a list/tuple/set
            fields_param: str | None
            if fields is None:  # Use default if None
                fields_param = ",".join(DEFAULT_READ_JIRA_FIELDS)
            elif isinstance(fields, list | tuple | set):
                fields_param = ",".join(fields)
            else:
                fields_param = fields

            if self.config.is_cloud:
                # Jira Cloud: the legacy POST /rest/api/2/search endpoint has
                # been removed by Atlassian. Use the enhanced JQL API (which
                # itself POSTs to /rest/api/3/search/jql and therefore also
                # avoids URL-length limits for large queries).
                actual_total = -1
                try:
                    # Call 1: The enhanced JQL API reports no total, so ask for an
                    # approximate count. It may lag behind recent changes.
                    count_response = self.jira.post(
                        self.jira.resource_url("search/approximate-count"),
                        json={"jql": jql},
                    )

                    if (
                        isinstance(count_response, dict)
                        and "count" in count_response
                    ):
                        try:
                            actual_total = int(count_response["count"])
                        except (ValueError, TypeError):
                            logger.warning(
                                f"Could not parse 'count' from approximate count "
                                f"response for JQL: {jql}. Received: "
                                f"{count_response.get('count')}"
                            )
                    else:
                        logger.warning(
                            f"Could not retrieve approximate count for JQL: {jql}. "
                            f"Response type: {type(count_response)}"
                        )
                except Exception as count_err:
                    logger.warning(
                        f"Error fetching approximate count for JQL '{jql}': "
                        f"{str(count_err)}"
                    )

                # Call 2: Get the actual issues using the enhanced method
                issues_response_list = self.jira.enhanced_jql_get_list_of_tickets(
                    jql, fields=fields_param, limit=limit, expand=expand
                )

                if not isinstance(issues_response_list, list):
                    msg = (
                        "Unexpected return value type from "
                        "`jira.enhanced_jql_get_list_of_tickets`: "
                        f"{type(issues_response_list)}"
                    )
                    logger.error(msg)
                    raise TypeError(msg)

                response_dict_for_model = {
                    "issues": issues_response_list,
                    "total": actual_total,
                }

                search_result = JiraSearchResult.from_api_response(
                    response_dict_for_model,
                    base_url=self.config.url,
                    requested_fields=fields_param,
                )
                return search_result

            # Jira Server/DC: use POST on /rest/api/2/search to avoid URL length
            # limits with large queries (e.g. 150-180 AND/OR clauses). The body
            # has no practical length limit unlike GET query parameters.
            response = self._jql_search_post(
                jql=jql,
                fields_param=fields_param,
                start=start,
                limit=limit,
                expand=expand,
            )

            search_result = JiraSearchResult.from_api_response(
                response,
                base_url=self.config.url,
                requested_fields=fields_param,
            )
            return search_result

        except HTTPError as http_err:
            if http_err.response is not None and http_err.response.status_code in [
                401,
                403,
            ]:
                error_msg = (
                    f"Authentication failed for Jira API ({http_err.response.status_code}). "
                    "Token may be expired or invalid. Please verify credentials."
                )
                logger.error(error_msg)
                raise MCPAtlassianAuthenticationError(error_msg) from http_err
            else:
                logger.error(f"HTTP error during API call: {http_err}", exc_info=False)
                raise http_err
        except Exception as e:
            logger.error(f"Error searching issues with JQL '{jql}': {str(e)}")
            msg = f"Error searching issues: {str(e)}"
            raise Exception(msg) from e

    def _jql_search_post(
        self,
        jql: str,
        fields_param: str | None,
        start: int,
        limit: int,
        expand: str | None,
    ) -> dict[str, Any]:
        """Execute a JQL search using HTTP POST to avoid URL length limits.

        Used for Jira Server/DC, where ``POST /rest/api/2/search`` remains
        supported. It accepts all search parameters in the JSON body, which
        sidesteps the URL query-string length limits that cause GET requests
        with large JQL strings (≥ ~150 AND/OR clauses) to fail with HTTP
        414/400 errors.

        Args:
            jql: JQL query string (may be arbitrarily long).
            fields_param: Comma-separated field list, "*all", or None for default.
            start: Zero-based starting offset for pagination.
            limit: Maximum number of issues to return.
            expand: Optional comma-separated list of items to expand.

        Returns:
            Raw dict response from /rest/api/2/search containing ``issues``,
            ``total``, ``startAt``, and ``maxResults``.
        """
        max_results = min(limit, 50)

        body: dict[str, Any] = {
            "jql": jql,
            "startAt": start,
            "maxResults": max_results,
        }

        if fields_param:
            if fields_param == "*all":
                body["fields"] = ["*all"]
            else:
                body["fields"] = [
                    f.strip() for f in fields_param.split(",") if f.strip()
                ]

        if expand:
            body["expand"] = [e.strip() for e in expand.split(",") if e.strip()]

        url = self.jira.resource_url("search")
        logger.debug("JQL POST search to %s (jql length=%d)", url, len(jql))
        response = self.jira.post(url, json=body)

        if not isinstance(response, dict):
            msg = f"Unexpected response type from JQL POST search: {type(response)}"
            logger.error(msg)
            raise TypeError(msg)

        return response

    def get_board_issues(
        self,
        board_id: str,
        jql: str,
        fields: str | None = None,
        start: int = 0,
        limit: int = 50,
        expand: str | None = None,
    ) -> JiraSearchResult:
        """
        Get all issues linked to a specific board.

        Args:
            board_id: The ID of the board
            jql: JQL query string
            fields: Fields to return (comma-separated string or "*all")
            start: Starting index
            limit: Maximum issues to return
            expand: Optional items to expand (comma-separated)

        Returns:
            JiraSearchResult object containing board issues and metadata

        Raises:
            Exception: If there is an error getting board issues
        """
        try:
            # Determine fields_param
            fields_param = fields
            if fields_param is None:
                fields_param = ",".join(DEFAULT_READ_JIRA_FIELDS)

            response = self.jira.get_issues_for_board(
                board_id=board_id,
                jql=jql,
                fields=fields_param,
                start=start,
                limit=limit,
                expand=expand,
            )
            if not isinstance(response, dict):
                msg = f"Unexpected return value type from `jira.get_issues_for_board`: {type(response)}"
                logger.error(msg)
                raise TypeError(msg)

            # Convert the response to a search result model
            search_result = JiraSearchResult.from_api_response(
                response, base_url=self.config.url, requested_fields=fields_param
            )
            return search_result
        except requests.HTTPError as e:
            logger.error(
                f"Error searching issues for board with JQL '{board_id}': {str(e.response.content)}"
            )
            msg = (
                f"Error searching issues for board with JQL: {str(e.response.content)}"
            )
            raise Exception(msg) from e
        except Exception as e:
            logger.error(f"Error searching issues for board with JQL '{jql}': {str(e)}")
            msg = f"Error searching issues for board with JQL {str(e)}"
            raise Exception(msg) from e

    def get_sprint_issues(
        self,
        sprint_id: str,
        fields: str | None = None,
        start: int = 0,
        limit: int = 50,
    ) -> JiraSearchResult:
        """
        Get all issues linked to a specific sprint.

        Args:
            sprint_id: The ID of the sprint
            fields: Fields to return (comma-separated string or "*all")
            start: Starting index
            limit: Maximum issues to return

        Returns:
            JiraSearchResult object containing sprint issues and metadata

        Raises:
            Exception: If there is an error getting board issues
        """
        try:
            # Determine fields_param
            fields_param = fields
            if fields_param is None:
                fields_param = ",".join(DEFAULT_READ_JIRA_FIELDS)

            response = self.jira.get_sprint_issues(
                sprint_id=sprint_id,
                start=start,
                limit=limit,
            )
            if not isinstance(response, dict):
                msg = f"Unexpected return value type from `jira.get_sprint_issues`: {type(response)}"
                logger.error(msg)
                raise TypeError(msg)

            # Convert the response to a search result model
            search_result = JiraSearchResult.from_api_response(
                response, base_url=self.config.url, requested_fields=fields_param
            )
            return search_result
        except requests.HTTPError as e:
            logger.error(
                f"Error searching issues for sprint '{sprint_id}': {str(e.response.content)}"
            )
            msg = f"Error searching issues for sprint: {str(e.response.content)}"
            raise Exception(msg) from e
        except Exception as e:
            logger.error(f"Error searching issues for sprint: {sprint_id}': {str(e)}")
            msg = f"Error searching issues for sprint: {str(e)}"
            raise Exception(msg) from e
