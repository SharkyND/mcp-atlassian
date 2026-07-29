"""Tests for the Jira WorkflowsMixin."""

from unittest.mock import MagicMock, PropertyMock, patch

import pytest
from requests.exceptions import HTTPError

from mcp_atlassian.exceptions import MCPAtlassianAuthenticationError
from mcp_atlassian.jira import JiraFetcher
from mcp_atlassian.jira.workflows import WorkflowsMixin

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _http_error(status_code: int) -> HTTPError:
    """Create a minimal HTTPError with the given status code."""
    response = MagicMock()
    response.status_code = status_code
    err = HTTPError(response=response)
    return err


# ---------------------------------------------------------------------------
# Fixture
# ---------------------------------------------------------------------------


@pytest.fixture()
def wf_mixin(jira_fetcher: JiraFetcher) -> JiraFetcher:
    """Return the shared JiraFetcher (which includes WorkflowsMixin)."""
    return jira_fetcher


# ---------------------------------------------------------------------------
# get_all_workflows
# ---------------------------------------------------------------------------


class TestGetAllWorkflows:
    def test_returns_list(self, wf_mixin):
        wf_mixin.jira.get_all_workflows.return_value = [
            {"name": "Software Simplified Workflow", "default": True},
            {"name": "Classic Default Workflow", "default": False},
        ]
        result = wf_mixin.get_all_workflows()
        assert isinstance(result, list)
        assert len(result) == 2
        assert result[0]["name"] == "Software Simplified Workflow"

    def test_returns_empty_list_on_empty_response(self, wf_mixin):
        wf_mixin.jira.get_all_workflows.return_value = []
        assert wf_mixin.get_all_workflows() == []

    def test_handles_dict_response_with_values_key(self, wf_mixin):
        wf_mixin.jira.get_all_workflows.return_value = {"values": [{"name": "WF1"}]}
        result = wf_mixin.get_all_workflows()
        assert result == [{"name": "WF1"}]

    def test_raises_auth_error_on_401(self, wf_mixin):
        wf_mixin.jira.get_all_workflows.side_effect = _http_error(401)
        with pytest.raises(MCPAtlassianAuthenticationError):
            wf_mixin.get_all_workflows()

    def test_raises_auth_error_on_403(self, wf_mixin):
        wf_mixin.jira.get_all_workflows.side_effect = _http_error(403)
        with pytest.raises(MCPAtlassianAuthenticationError):
            wf_mixin.get_all_workflows()

    def test_raises_generic_exception_on_other_http_error(self, wf_mixin):
        wf_mixin.jira.get_all_workflows.side_effect = _http_error(500)
        with pytest.raises(HTTPError):
            wf_mixin.get_all_workflows()

    def test_raises_exception_on_unexpected_error(self, wf_mixin):
        wf_mixin.jira.get_all_workflows.side_effect = RuntimeError("boom")
        with pytest.raises(Exception, match="Error getting all workflows"):
            wf_mixin.get_all_workflows()


# ---------------------------------------------------------------------------
# get_workflows_paginated
# ---------------------------------------------------------------------------


class TestGetWorkflowsPaginated:
    def test_returns_dict(self, wf_mixin):
        expected = {"values": [{"name": "WF1"}], "total": 1}
        wf_mixin.jira.get_workflows_paginated.return_value = expected
        result = wf_mixin.get_workflows_paginated()
        assert result == expected

    def test_passes_params(self, wf_mixin):
        wf_mixin.jira.get_workflows_paginated.return_value = {}
        wf_mixin.get_workflows_paginated(
            start_at=10,
            max_results=25,
            workflow_name="My Workflow",
            expand="statuses,statuses.properties",
        )
        wf_mixin.jira.get_workflows_paginated.assert_called_once_with(
            start_at=10,
            max_results=25,
            workflow_name="My Workflow",
            expand="statuses,statuses.properties",
        )

    def test_returns_empty_dict_on_non_dict_response(self, wf_mixin):
        wf_mixin.jira.get_workflows_paginated.return_value = None
        assert wf_mixin.get_workflows_paginated() == {}

    def test_raises_auth_error_on_401(self, wf_mixin):
        wf_mixin.jira.get_workflows_paginated.side_effect = _http_error(401)
        with pytest.raises(MCPAtlassianAuthenticationError):
            wf_mixin.get_workflows_paginated()

    def test_datacenter_uses_workflow_endpoint_and_paginates(self, wf_mixin):
        wf_mixin.jira.resource_url.return_value = "http://dc/rest/api/2/workflow"
        wf_mixin.jira.get.return_value = [
            {"name": "WF-1"},
            {"name": "WF-2"},
            {"name": "WF-3"},
        ]

        config_cls = type(wf_mixin.config)
        with patch.object(
            config_cls, "is_cloud", new_callable=PropertyMock, return_value=False
        ):
            result = wf_mixin.get_workflows_paginated(start_at=1, max_results=1)

        assert result["startAt"] == 1
        assert result["maxResults"] == 1
        assert result["total"] == 3
        assert result["isLast"] is False
        assert result["values"] == [{"name": "WF-2"}]
        wf_mixin.jira.resource_url.assert_called_once_with("workflow")
        wf_mixin.jira.get.assert_called_once_with("http://dc/rest/api/2/workflow")
        wf_mixin.jira.get_workflows_paginated.assert_not_called()

    def test_datacenter_applies_workflow_name_filter(self, wf_mixin):
        wf_mixin.jira.resource_url.return_value = "http://dc/rest/api/2/workflow"
        wf_mixin.jira.get.return_value = [
            {"name": "WF-1"},
            {"name": "WF-2"},
        ]

        config_cls = type(wf_mixin.config)
        with patch.object(
            config_cls, "is_cloud", new_callable=PropertyMock, return_value=False
        ):
            result = wf_mixin.get_workflows_paginated(workflow_name="WF-2")

        assert result["total"] == 1
        assert result["values"] == [{"name": "WF-2"}]

    def test_datacenter_handles_dict_response_with_values(self, wf_mixin):
        wf_mixin.jira.resource_url.return_value = "http://dc/rest/api/2/workflow"
        wf_mixin.jira.get.return_value = {"values": [{"name": "WF-1"}]}

        config_cls = type(wf_mixin.config)
        with patch.object(
            config_cls, "is_cloud", new_callable=PropertyMock, return_value=False
        ):
            result = wf_mixin.get_workflows_paginated()

        assert result["total"] == 1
        assert result["values"] == [{"name": "WF-1"}]

    def test_singular_alias_delegates_to_plural(self, wf_mixin):
        expected = {"values": [{"name": "WF1"}], "total": 1}
        wf_mixin.jira.get_workflows_paginated.return_value = expected

        result = wf_mixin.get_workflow_paginated(
            start_at=5,
            max_results=10,
            workflow_name="My Workflow",
            expand="statuses",
        )

        assert result == expected
        wf_mixin.jira.get_workflows_paginated.assert_called_once_with(
            start_at=5,
            max_results=10,
            workflow_name="My Workflow",
            expand="statuses",
        )


# ---------------------------------------------------------------------------
# get_workflow_properties
# ---------------------------------------------------------------------------


class TestGetWorkflowProperties:
    def test_returns_list(self, wf_mixin):
        expected = [{"key": "jira.field.resolution.required", "value": "true"}]
        wf_mixin.jira.get.return_value = expected
        result = wf_mixin.get_workflow_properties("My Workflow", transition_id=1)
        assert result == expected

    def test_handles_dict_response(self, wf_mixin):
        wf_mixin.jira.get.return_value = {"key": "k1", "value": "v1"}
        result = wf_mixin.get_workflow_properties("My Workflow", transition_id=1)
        assert result == [{"key": "k1", "value": "v1"}]

    def test_uses_transition_properties_endpoint(self, wf_mixin):
        wf_mixin.jira.get.return_value = []
        wf_mixin.get_workflow_properties(
            "My Workflow", transition_id=1, workflow_mode="draft"
        )
        wf_mixin.jira.resource_url.assert_called_once_with(
            "workflow/transitions/1/properties"
        )
        call_kwargs = wf_mixin.jira.get.call_args
        assert call_kwargs[1]["params"]["workflowName"] == "My Workflow"
        assert call_kwargs[1]["params"]["workflowMode"] == "draft"

    def test_raises_auth_error_on_403(self, wf_mixin):
        wf_mixin.jira.get.side_effect = _http_error(403)
        with pytest.raises(MCPAtlassianAuthenticationError):
            wf_mixin.get_workflow_properties("WF", transition_id=1)

    def test_raises_exception_on_unexpected_error(self, wf_mixin):
        wf_mixin.jira.get.side_effect = RuntimeError("nope")
        with pytest.raises(Exception, match="Error getting properties"):
            wf_mixin.get_workflow_properties("WF", transition_id=1)


# ---------------------------------------------------------------------------
# get_workflow_status_properties
# ---------------------------------------------------------------------------

SAMPLE_CLOUD_RESPONSE = {
    "values": [
        {
            "name": "My Software Workflow",
            "statuses": [
                {
                    "id": "1",
                    "name": "Open",
                    "properties": {
                        "jira.issue.editable": "true",
                    },
                },
                {
                    "id": "5",
                    "name": "Closed",
                    "properties": {
                        "jira.issue.editable": "false",
                        "jira.permission.edit.denied": "true",
                        "jira.permission.link.denied": "true",
                    },
                },
            ],
        }
    ],
    "total": 1,
}

SAMPLE_SERVER_RESPONSE = [
    {
        "name": "Classic Default Workflow",
        "statuses": [
            {
                "id": "1",
                "name": "Open",
                "properties": [
                    {"key": "jira.issue.editable", "value": "true"},
                ],
            },
        ],
    }
]


class TestGetWorkflowStatusProperties:
    def test_cloud_parses_statuses_from_paginated_response(self, wf_mixin):
        wf_mixin.jira.get_workflows_paginated.return_value = SAMPLE_CLOUD_RESPONSE
        config_cls = type(wf_mixin.config)
        with patch.object(
            config_cls, "is_cloud", new_callable=PropertyMock, return_value=True
        ):
            result = wf_mixin.get_workflow_status_properties()

        assert len(result) == 1
        wf = result[0]
        assert wf["workflow_name"] == "My Software Workflow"
        assert len(wf["statuses"]) == 2

        open_status = wf["statuses"][0]
        assert open_status["name"] == "Open"
        assert open_status["properties"]["jira.issue.editable"] == "true"

        closed_status = wf["statuses"][1]
        assert closed_status["properties"]["jira.permission.edit.denied"] == "true"
        assert closed_status["properties"]["jira.permission.link.denied"] == "true"

    def test_server_parses_statuses_from_list_response(self, wf_mixin):
        wf_mixin.jira.get_all_workflows.return_value = SAMPLE_SERVER_RESPONSE
        config_cls = type(wf_mixin.config)
        with patch.object(
            config_cls, "is_cloud", new_callable=PropertyMock, return_value=False
        ):
            result = wf_mixin.get_workflow_status_properties()

        assert len(result) == 1
        st = result[0]["statuses"][0]
        assert st["properties"]["jira.issue.editable"] == "true"

    def test_server_returns_workflow_entry_when_statuses_missing(self, wf_mixin):
        wf_mixin.jira.get_all_workflows.return_value = [
            {
                "name": "jira",
                "description": "The default Jira workflow",
                "steps": 5,
                "isDefault": True,
            }
        ]
        config_cls = type(wf_mixin.config)
        with patch.object(
            config_cls, "is_cloud", new_callable=PropertyMock, return_value=False
        ):
            result = wf_mixin.get_workflow_status_properties(workflow_name="jira")

        assert len(result) == 1
        assert result[0]["workflow_name"] == "jira"
        assert result[0]["statuses"] == []

    def test_filters_by_workflow_name_cloud(self, wf_mixin):
        wf_mixin.jira.get_workflows_paginated.return_value = {"values": []}
        config_cls = type(wf_mixin.config)
        with patch.object(
            config_cls, "is_cloud", new_callable=PropertyMock, return_value=True
        ):
            wf_mixin.get_workflow_status_properties(workflow_name="My WF")
        wf_mixin.jira.get_workflows_paginated.assert_called_once_with(
            workflow_name="My WF", expand="statuses,statuses.properties"
        )

    def test_raises_auth_error_on_401(self, wf_mixin):
        wf_mixin.jira.get_workflows_paginated.side_effect = _http_error(401)
        config_cls = type(wf_mixin.config)
        with patch.object(
            config_cls, "is_cloud", new_callable=PropertyMock, return_value=True
        ):
            with pytest.raises(MCPAtlassianAuthenticationError):
                wf_mixin.get_workflow_status_properties()


# ---------------------------------------------------------------------------
# check_issue_workflow_permissions
# ---------------------------------------------------------------------------


class TestCheckIssueWorkflowPermissions:
    def _setup_issue(self, wf_mixin, status_name="Closed", status_id="5"):
        wf_mixin.jira.issue.return_value = {
            "key": "TEST-1",
            "fields": {
                "status": {"name": status_name, "id": status_id},
                "project": {"key": "TEST"},
                "issuetype": {"name": "Bug"},
            },
        }

    def test_returns_not_editable_for_closed_issue(self, wf_mixin):
        self._setup_issue(wf_mixin, "Closed", "5")
        wf_mixin.jira.get_workflows_paginated.return_value = SAMPLE_CLOUD_RESPONSE
        config_cls = type(wf_mixin.config)
        with patch.object(
            config_cls, "is_cloud", new_callable=PropertyMock, return_value=True
        ):
            result = wf_mixin.check_issue_workflow_permissions("TEST-1")

        assert result["issue_key"] == "TEST-1"
        assert result["current_status"] == "Closed"
        assert result["is_editable"] is False
        assert "jira.permission.edit.denied" in result["denied_permissions"]
        assert "jira.permission.link.denied" in result["denied_permissions"]

    def test_returns_editable_for_open_issue(self, wf_mixin):
        self._setup_issue(wf_mixin, "Open", "1")
        wf_mixin.jira.get_workflows_paginated.return_value = SAMPLE_CLOUD_RESPONSE
        config_cls = type(wf_mixin.config)
        with patch.object(
            config_cls, "is_cloud", new_callable=PropertyMock, return_value=True
        ):
            result = wf_mixin.check_issue_workflow_permissions("TEST-1")

        assert result["is_editable"] is True
        assert result["denied_permissions"] == []

    def test_undetermined_when_no_properties_found(self, wf_mixin):
        self._setup_issue(wf_mixin, "Unknown Status", "99")
        wf_mixin.jira.get_workflows_paginated.return_value = {"values": []}
        wf_mixin.jira.get.return_value = {
            "permissions": {
                "EDIT_ISSUES": {"havePermission": True},
                "LINK_ISSUES": {"havePermission": False},
            }
        }
        config_cls = type(wf_mixin.config)
        with patch.object(
            config_cls, "is_cloud", new_callable=PropertyMock, return_value=True
        ):
            result = wf_mixin.check_issue_workflow_permissions("TEST-1")

        assert result["is_editable"] is True
        assert result["evaluation_status"] == "determined_permissions_api"
        assert "jira.permission.link.denied" in result["denied_permissions"]
        assert result["status_properties"] == {}

    def test_permissions_api_missing_payload_keeps_undetermined(self, wf_mixin):
        self._setup_issue(wf_mixin, "Unknown Status", "99")
        wf_mixin.jira.get_workflows_paginated.return_value = {"values": []}
        wf_mixin.jira.get.return_value = {}
        config_cls = type(wf_mixin.config)
        with patch.object(
            config_cls, "is_cloud", new_callable=PropertyMock, return_value=True
        ):
            result = wf_mixin.check_issue_workflow_permissions("TEST-1")

        assert result["is_editable"] is None
        assert result["evaluation_status"] == "missing_status_properties"

    def test_raises_auth_error_on_issue_fetch_401(self, wf_mixin):
        wf_mixin.jira.issue.side_effect = _http_error(401)
        with pytest.raises(MCPAtlassianAuthenticationError):
            wf_mixin.check_issue_workflow_permissions("TEST-1")

    def test_raises_exception_on_unexpected_error(self, wf_mixin):
        wf_mixin.jira.issue.side_effect = RuntimeError("db error")
        with pytest.raises(Exception, match="Error checking workflow permissions"):
            wf_mixin.check_issue_workflow_permissions("TEST-1")


# ---------------------------------------------------------------------------
# _evaluate_editability (static helper)
# ---------------------------------------------------------------------------


class TestEvaluateEditability:
    def test_editable_when_jira_issue_editable_true(self):
        props = {"jira.issue.editable": "true"}
        assert WorkflowsMixin._evaluate_editability(props) is True

    def test_not_editable_when_jira_issue_editable_false(self):
        props = {"jira.issue.editable": "false"}
        assert WorkflowsMixin._evaluate_editability(props) is False

    def test_not_editable_when_edit_denied_true(self):
        assert (
            WorkflowsMixin._evaluate_editability(
                {"jira.permission.edit.denied": "true"}
            )
            is False
        )

    def test_editable_when_edit_denied_false(self):
        assert (
            WorkflowsMixin._evaluate_editability(
                {"jira.permission.edit.denied": "false"}
            )
            is True
        )

    def test_undetermined_when_no_properties(self):
        assert WorkflowsMixin._evaluate_editability({}) is None

    def test_jira_issue_editable_takes_precedence(self):
        # jira.issue.editable=true should win even if edit.denied is set
        assert (
            WorkflowsMixin._evaluate_editability(
                {
                    "jira.issue.editable": "true",
                    "jira.permission.edit.denied": "true",
                }
            )
            is True
        )


# ---------------------------------------------------------------------------
# _parse_workflow_status_properties (static helper)
# ---------------------------------------------------------------------------


class TestParseWorkflowStatusProperties:
    def test_parses_dict_properties(self):
        raw = [
            {
                "name": "WF1",
                "statuses": [
                    {
                        "id": "1",
                        "name": "Open",
                        "properties": {"jira.issue.editable": "true"},
                    }
                ],
            }
        ]
        result = WorkflowsMixin._parse_workflow_status_properties(raw)
        assert result[0]["workflow_name"] == "WF1"
        assert result[0]["statuses"][0]["properties"]["jira.issue.editable"] == "true"

    def test_parses_list_properties(self):
        raw = [
            {
                "name": "WF2",
                "statuses": [
                    {
                        "id": "2",
                        "name": "Closed",
                        "properties": [
                            {"key": "jira.permission.edit.denied", "value": "true"}
                        ],
                    }
                ],
            }
        ]
        result = WorkflowsMixin._parse_workflow_status_properties(raw)
        props = result[0]["statuses"][0]["properties"]
        assert props["jira.permission.edit.denied"] == "true"

    def test_skips_non_dict_items(self):
        raw = ["not_a_dict", {"name": "WF3", "statuses": []}]
        result = WorkflowsMixin._parse_workflow_status_properties(raw)
        assert len(result) == 1
        assert result[0]["workflow_name"] == "WF3"

    def test_handles_empty_list(self):
        assert WorkflowsMixin._parse_workflow_status_properties([]) == []
