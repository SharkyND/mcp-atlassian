"""Module for Jira workflow operations."""

import logging
from typing import Any, NoReturn

from requests.exceptions import HTTPError

from ..exceptions import MCPAtlassianAuthenticationError
from .client import JiraClient

logger = logging.getLogger("mcp-jira")

# Well-known workflow status property keys
KNOWN_STATUS_PROPERTY_KEYS = {
    "jira.issue.editable",
    "jira.permission.edit.denied",
    "jira.permission.link.denied",
    "jira.permission.subtask.link.denied",
    "jira.permission.attach.denied",
    "jira.permission.assign.denied",
    "jira.permission.resolve.denied",
    "jira.permission.comment.denied",
    "jira.permission.delete.denied",
    "jira.permission.worklog.denied",
    "jira.permission.move.denied",
}

# Jira mypermissions key -> workflow-style denied key used in this tool output.
PERMISSION_KEY_TO_DENIED_PROPERTY = {
    "EDIT_ISSUES": "jira.permission.edit.denied",
    "LINK_ISSUES": "jira.permission.link.denied",
    "CREATE_ATTACHMENTS": "jira.permission.attach.denied",
    "ADD_COMMENTS": "jira.permission.comment.denied",
    "ASSIGN_ISSUES": "jira.permission.assign.denied",
    "RESOLVE_ISSUES": "jira.permission.resolve.denied",
    "DELETE_ISSUES": "jira.permission.delete.denied",
    "WORK_ON_ISSUES": "jira.permission.worklog.denied",
}


class WorkflowsMixin(JiraClient):
    """Mixin for Jira workflow operations."""

    # ------------------------------------------------------------------ #
    # Workflow listing                                                      #
    # ------------------------------------------------------------------ #

    def get_all_workflows(self) -> list[dict[str, Any]]:
        """
        Get all workflows (requires admin permissions on Server/DC).

        Returns:
            List of workflow dictionaries

        Raises:
            MCPAtlassianAuthenticationError: If authentication fails (401/403)
            Exception: On other API errors
        """
        try:
            result = self.jira.get_all_workflows()
            if isinstance(result, list):
                return result
            # Some versions return a dict with a list inside
            if isinstance(result, dict):
                return result.get("values", [result])
            return []
        except HTTPError as http_err:
            self._raise_auth_error_or_reraise(http_err, "getting all workflows")
        except Exception as e:
            msg = f"Error getting all workflows: {e}"
            logger.error(msg)
            raise Exception(msg) from e

    def get_workflows_paginated(
        self,
        start_at: int = 0,
        max_results: int = 50,
        workflow_name: str | None = None,
        expand: str | None = None,
    ) -> dict[str, Any]:
        """
                Search workflows with pagination.

                API strategy by deployment type:

                - Cloud: use Jira Cloud paginated endpoint via
                    ``jira.get_workflows_paginated`` (``/rest/api/2/workflow/search``)
                - Server/Data Center: use Jira DC endpoint
                    ``/rest/api/2/workflow`` and then apply pagination/filtering locally
                    to return a consistent response shape

        Expand options (comma-separated):
            - ``transitions``                    include transitions
            - ``transitions.rules``              include transition rules
            - ``statuses``                       include statuses
            - ``statuses.properties``            include status properties
              (e.g. ``jira.permission.edit.denied``, ``jira.issue.editable``)

        Args:
            start_at: Page offset (0-based)
            max_results: Max items per page
            workflow_name: Optional name filter
            expand: Comma-separated expand fields

        Returns:
            Raw paginated response dict with ``values``, ``total``, etc.

        Raises:
            MCPAtlassianAuthenticationError: On 401/403
            Exception: On other errors
        """
        try:
            if self.config.is_cloud:
                result = self.jira.get_workflows_paginated(
                    start_at=start_at,
                    max_results=max_results,
                    workflow_name=workflow_name,
                    expand=expand,
                )
                return result if isinstance(result, dict) else {}

            # Data Center / Server path:
            # Use explicit DC endpoint and normalize output to paginated shape.
            raw = self.jira.get(self.jira.resource_url("workflow"))

            if isinstance(raw, list):
                workflows = raw
            elif isinstance(raw, dict):
                workflows = raw.get("values", [raw])
            else:
                workflows = []

            if workflow_name:
                workflows = [
                    wf
                    for wf in workflows
                    if isinstance(wf, dict) and wf.get("name") == workflow_name
                ]

            total = len(workflows)
            page = workflows[start_at : start_at + max_results]
            return {
                "startAt": start_at,
                "maxResults": max_results,
                "total": total,
                "isLast": (start_at + max_results) >= total,
                "values": page,
            }
        except HTTPError as http_err:
            self._raise_auth_error_or_reraise(http_err, "getting paginated workflows")
        except Exception as e:
            msg = f"Error getting paginated workflows: {e}"
            logger.error(msg)
            raise Exception(msg) from e

    def get_workflow_paginated(
        self,
        start_at: int = 0,
        max_results: int = 50,
        workflow_name: str | None = None,
        expand: str | None = None,
    ) -> dict[str, Any]:
        """Backward-compatible alias for :meth:`get_workflows_paginated`.

        This keeps compatibility with older callers that used the singular
        method name.
        """
        return self.get_workflows_paginated(
            start_at=start_at,
            max_results=max_results,
            workflow_name=workflow_name,
            expand=expand,
        )

    # ------------------------------------------------------------------ #
    # Workflow transition properties                                        #
    # ------------------------------------------------------------------ #

    def get_workflow_properties(
        self,
        workflow_name: str,
        transition_id: int | str,
        workflow_mode: str = "live",
        key: str | None = None,
    ) -> list[dict[str, Any]]:
        """
        Get properties set on a workflow transition.

        Jira Data Center exposes properties via transition endpoints:
        ``/rest/api/2/workflow/transitions/{transitionId}/properties``.
        Properties are key-value pairs attached to a specific transition.

        Args:
            workflow_name: The workflow name
            transition_id: Transition ID within the workflow
            workflow_mode: ``live`` (default) or ``draft``
            key: Optional property key filter

        Returns:
            List of ``{"key": ..., "value": ...}`` dicts

        Raises:
            MCPAtlassianAuthenticationError: On 401/403
            Exception: On other errors
        """
        try:
            url = f"workflow/transitions/{transition_id}/properties"
            params: dict[str, Any] = {"workflowName": workflow_name}
            if workflow_mode:
                params["workflowMode"] = workflow_mode
            if key:
                params["key"] = key
            result = self.jira.get(self.jira.resource_url(url), params=params)
            if isinstance(result, list):
                return result
            if isinstance(result, dict):
                # Key-filtered responses are usually a single object.
                return [result]
            return []
        except HTTPError as http_err:
            self._raise_auth_error_or_reraise(
                http_err,
                f"getting properties for workflow '{workflow_name}'",
            )
        except Exception as e:
            msg = f"Error getting properties for workflow '{workflow_name}': {e}"
            logger.error(msg)
            raise Exception(msg) from e

    # ------------------------------------------------------------------ #
    # Workflow status properties (permission / editability flags)           #
    # ------------------------------------------------------------------ #

    def get_workflow_status_properties(
        self,
        workflow_name: str | None = None,
    ) -> list[dict[str, Any]]:
        """
        Get statuses and their associated properties for one or all workflows.

        This retrieves status-level properties such as:
        - ``jira.issue.editable``           – whether the issue is editable
        - ``jira.permission.edit.denied``   – blocks the *Edit Issue* permission
        - ``jira.permission.link.denied``   – blocks the *Link Issue* permission
        - ``jira.permission.attach.denied`` – blocks the *Attach Files* permission
        - ``jira.permission.comment.denied``– blocks the *Add Comment* permission
        - (and other ``jira.permission.*`` keys)

        On Jira Cloud, uses the paginated workflows API with
        ``expand=statuses.properties``. On Server/DC, uses
        ``/rest/api/2/workflow`` with the same expand param.

        Args:
            workflow_name: Optional workflow name to filter results

        Returns:
            List of dicts, one per workflow:
            ::

                [
                  {
                    "workflow_name": "...",
                    "statuses": [
                      {
                        "id": "...",
                        "name": "...",
                        "properties": {
                          "jira.issue.editable": "true",
                          "jira.permission.edit.denied": "...",
                          ...
                        }
                      },
                      ...
                    ]
                  },
                  ...
                ]

        Raises:
            MCPAtlassianAuthenticationError: On 401/403
            Exception: On other errors
        """
        try:
            if self.config.is_cloud:
                expand = "statuses,statuses.properties"
                raw = self.jira.get_workflows_paginated(
                    workflow_name=workflow_name,
                    expand=expand,
                )
                workflows_list = raw.get("values", []) if isinstance(raw, dict) else []
            else:
                # Jira Data Center commonly returns the workflow list at this route,
                # while the expand form does not reliably include statuses/statuses.properties.
                # Use the workflow list endpoint and filter locally so we preserve the
                # actual workflow objects returned by the server.
                raw = self.get_all_workflows()
                workflows_list = raw if isinstance(raw, list) else []

                if workflow_name:
                    workflows_list = [
                        wf
                        for wf in workflows_list
                        if isinstance(wf, dict) and wf.get("name") == workflow_name
                    ]

            return self._parse_workflow_status_properties(workflows_list)
        except HTTPError as http_err:
            self._raise_auth_error_or_reraise(
                http_err, "getting workflow status properties"
            )
        except Exception as e:
            msg = f"Error getting workflow status properties: {e}"
            logger.error(msg)
            raise Exception(msg) from e

    def check_issue_workflow_permissions(self, issue_key: str) -> dict[str, Any]:
        """
        Check workflow-based permission properties for an issue's current status.

        Retrieves the status properties set on the *current* status of the issue
        in its project workflow, including keys like:

        - ``jira.issue.editable``
        - ``jira.permission.edit.denied``
        - ``jira.permission.link.denied``

        Args:
            issue_key: Jira issue key (e.g. ``PROJ-123``)

        Returns:
            Dict with:
            - ``issue_key``: the issue key
            - ``current_status``: name of current status
            - ``status_properties``: dict of property key → value for the current status
                        - ``is_editable``: bool | None – explicit editability when properties are
                            available, otherwise ``None`` (undetermined)
                        - ``evaluation_status``: ``"determined"`` or
                            ``"missing_status_properties"``
            - ``denied_permissions``: list of permission keys that are denied

        Raises:
            MCPAtlassianAuthenticationError: On 401/403
            Exception: On other errors
        """
        try:
            # 1. Get the issue to find project key and current status name
            issue_data = self.jira.issue(issue_key, fields="status,project,issuetype")
            if not isinstance(issue_data, dict):
                msg = f"Unexpected response for issue {issue_key}"
                raise ValueError(msg)

            fields = issue_data.get("fields", {})
            current_status_name: str = fields.get("status", {}).get("name", "") or ""
            current_status_id: str = fields.get("status", {}).get("id", "") or ""
            project_key: str = fields.get("project", {}).get("key", "") or ""

            # 2. Get workflow status properties
            #    (filtered by project workflow if possible)
            all_wf_statuses = self.get_workflow_status_properties()

            # 3. Find the matching status across workflows relevant to this project
            status_properties: dict[str, str] = {}
            for wf in all_wf_statuses:
                for status in wf.get("statuses", []):
                    name_match = status.get("name") == current_status_name
                    id_match = status.get("id") == current_status_id
                    if name_match or id_match:
                        status_properties = status.get("properties", {})
                        break
                if status_properties:
                    break

            # 4. Evaluate editability and denied permissions.
            # When DC workflow payload doesn't include status properties,
            # use Jira effective permissions for the specific issue.
            if status_properties:
                is_editable = self._evaluate_editability(status_properties)
                evaluation_status = "determined_workflow_properties"
                denied_permissions = [
                    k
                    for k, v in status_properties.items()
                    if k.startswith("jira.permission.") and v in ("true", "True", "1")
                ]
            else:
                (
                    is_editable,
                    denied_permissions,
                    evaluation_status,
                ) = self._get_effective_issue_permissions(issue_key)

            return {
                "issue_key": issue_key,
                "project_key": project_key,
                "current_status": current_status_name,
                "status_id": current_status_id,
                "status_properties": status_properties,
                "is_editable": is_editable,
                "evaluation_status": evaluation_status,
                "denied_permissions": denied_permissions,
            }
        except HTTPError as http_err:
            self._raise_auth_error_or_reraise(
                http_err,
                f"checking workflow permissions for issue {issue_key}",
            )
        except Exception as e:
            msg = f"Error checking workflow permissions for issue {issue_key}: {e}"
            logger.error(msg)
            raise Exception(msg) from e

    # ------------------------------------------------------------------ #
    # Private helpers                                                       #
    # ------------------------------------------------------------------ #

    def _raise_auth_error_or_reraise(
        self, http_err: HTTPError, context: str
    ) -> NoReturn:
        """Re-raise auth errors as MCPAtlassianAuthenticationError; re-raise others."""
        if http_err.response is not None and http_err.response.status_code in (
            401,
            403,
        ):
            msg = (
                f"Authentication failed while {context} "
                f"({http_err.response.status_code}). "
                "Token may be expired or invalid. Please verify credentials."
            )
            logger.error(msg)
            raise MCPAtlassianAuthenticationError(msg) from http_err
        logger.error(f"HTTP error while {context}: {http_err}", exc_info=False)
        raise http_err

    @staticmethod
    def _parse_workflow_status_properties(
        workflows_list: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """
        Extract status properties from a raw workflow list response.

        Handles both Cloud (``get_workflows_paginated``) and Server/DC
        (``get_all_workflows``) response shapes.
        """
        result: list[dict[str, Any]] = []
        for wf in workflows_list:
            if not isinstance(wf, dict):
                continue

            wf_name = wf.get("name") or wf.get("id") or "unknown"
            raw_statuses: list[dict[str, Any]] = wf.get("statuses", [])

            parsed_statuses: list[dict[str, Any]] = []
            for st in raw_statuses:
                if not isinstance(st, dict):
                    continue

                # Status properties live under "properties" key (Cloud)
                # or under "properties.property" (Server/DC XML-derived)
                props: dict[str, str] = {}

                raw_props = st.get("properties", {})
                if isinstance(raw_props, dict):
                    for k, v in raw_props.items():
                        props[k] = str(v)
                elif isinstance(raw_props, list):
                    # Server/DC sometimes returns [{"key": ..., "value": ...}]
                    for item in raw_props:
                        if isinstance(item, dict) and "key" in item:
                            props[item["key"]] = str(item.get("value", ""))

                parsed_statuses.append(
                    {
                        "id": st.get("id") or st.get("statusId", ""),
                        "name": st.get("name", ""),
                        "properties": props,
                    }
                )

            # If Jira returns the workflow without embedded statuses, keep the
            # workflow entry so callers can still see which workflows were found.
            # This mirrors the actual Server/DC response shape we observed.
            if not parsed_statuses:
                result.append(
                    {
                        "workflow_name": wf_name,
                        "statuses": [],
                    }
                )
                continue

            result.append(
                {
                    "workflow_name": wf_name,
                    "statuses": parsed_statuses,
                }
            )
        return result

    @staticmethod
    def _evaluate_editability(props: dict[str, str]) -> bool | None:
        """
        Return explicit editability state from workflow status properties.

        Logic:
        - If ``jira.issue.editable`` is present, use its value (``"true"`` → editable).
        - If ``jira.permission.edit.denied`` is ``"true"`` the issue is NOT editable.
        - If neither property is present, returns ``None`` (undetermined).
        """
        if "jira.issue.editable" in props:
            return props["jira.issue.editable"].lower() in ("true", "1", "yes")
        if "jira.permission.edit.denied" in props:
            denied = props["jira.permission.edit.denied"].lower()
            return denied not in ("true", "1", "yes")
        return None

    def _get_effective_issue_permissions(
        self,
        issue_key: str,
    ) -> tuple[bool | None, list[str], str]:
        """Fetch effective permissions for an issue from Jira.

        Returns:
            (is_editable, denied_permissions, evaluation_status)
        """
        permissions_param = ",".join(PERMISSION_KEY_TO_DENIED_PROPERTY.keys())
        raw = self.jira.get(
            self.jira.resource_url("mypermissions"),
            params={"issueKey": issue_key, "permissions": permissions_param},
        )

        if not isinstance(raw, dict):
            return None, [], "missing_status_properties"

        permissions = raw.get("permissions", {})
        if not isinstance(permissions, dict):
            return None, [], "missing_status_properties"
        if not permissions:
            return None, [], "missing_status_properties"

        denied_permissions: list[str] = []
        is_editable: bool | None = None

        for jira_key, denied_key in PERMISSION_KEY_TO_DENIED_PROPERTY.items():
            node = permissions.get(jira_key, {})
            if not isinstance(node, dict):
                continue

            has_permission = node.get("havePermission")
            if has_permission is False:
                denied_permissions.append(denied_key)

            if jira_key == "EDIT_ISSUES" and isinstance(has_permission, bool):
                is_editable = has_permission

        return is_editable, denied_permissions, "determined_permissions_api"
