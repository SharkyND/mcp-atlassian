"""Unit tests for the Jira FastMCP server implementation."""

import json
import logging
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
from starlette.requests import Request

from mcp_atlassian.exceptions import MCPAtlassianAuthenticationError
from mcp_atlassian.jira import JiraFetcher
from mcp_atlassian.jira.config import JiraConfig
from mcp_atlassian.servers.context import MainAppContext
from mcp_atlassian.servers.main import AtlassianMCP
from mcp_atlassian.utils.oauth import OAuthConfig
from tests.fixtures.jira_mocks import (
    MOCK_JIRA_COMMENTS_SIMPLIFIED,
    MOCK_JIRA_ISSUE_RESPONSE_SIMPLIFIED,
    MOCK_JIRA_JQL_RESPONSE_SIMPLIFIED,
)

logger = logging.getLogger(__name__)


@pytest.fixture
def mock_jira_fetcher():
    """Create a mock JiraFetcher using predefined responses from fixtures."""
    mock_fetcher = MagicMock(spec=JiraFetcher)
    mock_fetcher.config = MagicMock()
    mock_fetcher.config.read_only = False
    mock_fetcher.config.url = "https://test.atlassian.net"
    mock_fetcher.config.projects_filter = None  # Explicitly set to None by default
    mock_fetcher.config.is_cloud = True

    mock_fetcher.search_fields.return_value = [
        {"id": "summary", "name": "Summary", "custom": False}
    ]

    project_issues_result = MagicMock()
    project_issues_result.to_simplified_dict.return_value = {
        "issues": [{"key": "PROJ-1"}],
        "total": 1,
        "start_at": 0,
        "max_results": 10,
    }
    mock_fetcher.get_project_issues.return_value = project_issues_result

    mock_fetcher.get_available_transitions.return_value = [
        {"id": "11", "name": "Start Progress"}
    ]
    mock_fetcher.get_worklogs.return_value = [
        {"author": {"displayName": "Test User"}, "timeSpent": "1h"}
    ]
    mock_fetcher.download_issue_attachments.return_value = {
        "issue": "TEST-123",
        "target_dir": "/tmp/downloads",
        "downloaded": 2,
    }

    board_mock = MagicMock()
    board_mock.to_simplified_dict.return_value = {"id": 1, "name": "Sample Board"}
    mock_fetcher.get_all_agile_boards_model.return_value = [board_mock]

    board_issues_result = MagicMock()
    board_issues_result.to_simplified_dict.return_value = {
        "issues": [{"key": "BOARD-1"}],
        "total": 1,
    }
    mock_fetcher.get_board_issues.return_value = board_issues_result

    sprint_mock = MagicMock()
    sprint_mock.to_simplified_dict.return_value = {"id": 7, "name": "Sprint 1"}
    mock_fetcher.get_all_sprints_from_board_model.return_value = [sprint_mock]

    sprint_issues_result = MagicMock()
    sprint_issues_result.to_simplified_dict.return_value = {
        "issues": [{"key": "SPR-1"}],
        "total": 1,
    }
    mock_fetcher.get_sprint_issues.return_value = sprint_issues_result

    link_type_mock = MagicMock()
    link_type_mock.to_simplified_dict.return_value = {
        "id": "100",
        "name": "Relates",
        "inward": "is related to",
        "outward": "relates to",
    }
    mock_fetcher.get_issue_link_types.return_value = [link_type_mock]

    changelog_entry = MagicMock()
    changelog_entry.to_simplified_dict.return_value = {"field": "status"}
    mock_fetcher.batch_get_changelogs.return_value = [
        SimpleNamespace(id="TEST-1", changelogs=[changelog_entry])
    ]

    updated_issue = MagicMock()
    updated_issue.to_simplified_dict.return_value = {"key": "TEST-321"}
    updated_issue.custom_fields = {"attachment_results": [{"file": "doc.txt"}]}
    mock_fetcher.update_issue.return_value = updated_issue

    transition_issue = MagicMock()
    transition_issue.to_simplified_dict.return_value = {"key": "TEST-999"}
    mock_fetcher.transition_issue.return_value = transition_issue

    mock_fetcher.add_comment.return_value = {"id": "10000", "body": "Added comment"}
    mock_fetcher.add_worklog.return_value = {"id": "worklog-1", "timeSpent": "1h"}

    linked_issue = MagicMock()
    linked_issue.to_simplified_dict.return_value = {"key": "TEST-100"}
    mock_fetcher.link_issue_to_epic.return_value = linked_issue

    mock_fetcher.create_issue_link.return_value = {"status": "LINKED"}
    mock_fetcher.create_remote_issue_link.return_value = {"id": "remote-link"}
    mock_fetcher.remove_issue_link.return_value = {"removed": True}

    sprint_obj = MagicMock()
    sprint_obj.to_simplified_dict.return_value = {"id": 77, "name": "Created Sprint"}
    mock_fetcher.create_sprint.return_value = sprint_obj

    sprint_updated_obj = MagicMock()
    sprint_updated_obj.to_simplified_dict.return_value = {
        "id": 77,
        "name": "Updated Sprint",
    }
    mock_fetcher.update_sprint.return_value = sprint_updated_obj

    mock_fetcher.create_project_version.return_value = {"id": "version-1"}

    # Configure common methods
    mock_fetcher.get_current_user_account_id.return_value = "test-account-id"
    mock_fetcher.jira = MagicMock()

    # Configure get_issue to return fixture data
    def mock_get_issue(
        issue_key,
        fields=None,
        expand=None,
        comment_limit=10,
        properties=None,
        update_history=True,
    ):
        if not issue_key:
            raise ValueError("Issue key is required")
        mock_issue = MagicMock()
        response_data = MOCK_JIRA_ISSUE_RESPONSE_SIMPLIFIED.copy()
        response_data["key"] = issue_key
        response_data["fields_queried"] = fields
        response_data["expand_param"] = expand
        response_data["comment_limit"] = comment_limit
        response_data["properties_param"] = properties
        response_data["update_history"] = update_history
        response_data["id"] = MOCK_JIRA_ISSUE_RESPONSE_SIMPLIFIED["id"]
        response_data["summary"] = MOCK_JIRA_ISSUE_RESPONSE_SIMPLIFIED["fields"][
            "summary"
        ]
        response_data["status"] = {
            "name": MOCK_JIRA_ISSUE_RESPONSE_SIMPLIFIED["fields"]["status"]["name"]
        }
        mock_issue.to_simplified_dict.return_value = response_data
        return mock_issue

    mock_fetcher.get_issue.side_effect = mock_get_issue

    # Configure get_issue_comments to return fixture data
    def mock_get_issue_comments(issue_key, limit=10):
        return MOCK_JIRA_COMMENTS_SIMPLIFIED["comments"][:limit]

    mock_fetcher.get_issue_comments.side_effect = mock_get_issue_comments

    # Configure search_issues to return fixture data
    def mock_search_issues(jql, **kwargs):
        mock_search_result = MagicMock()
        issues = []
        for issue_data in MOCK_JIRA_JQL_RESPONSE_SIMPLIFIED["issues"]:
            mock_issue = MagicMock()
            mock_issue.to_simplified_dict.return_value = issue_data
            issues.append(mock_issue)
        mock_search_result.issues = issues
        mock_search_result.total = len(issues)
        mock_search_result.start_at = kwargs.get("start", 0)
        mock_search_result.max_results = kwargs.get("limit", 50)
        mock_search_result.to_simplified_dict.return_value = {
            "total": len(issues),
            "start_at": kwargs.get("start", 0),
            "max_results": kwargs.get("limit", 50),
            "issues": [issue.to_simplified_dict() for issue in issues],
        }
        return mock_search_result

    mock_fetcher.search_issues.side_effect = mock_search_issues

    # Configure create_issue
    def mock_create_issue(
        project_key,
        summary,
        issue_type,
        description=None,
        assignee=None,
        components=None,
        **additional_fields,
    ):
        if not project_key or project_key.strip() == "":
            raise ValueError("valid project is required")
        components_list = None
        if components:
            if isinstance(components, str):
                components_list = components.split(",")
            elif isinstance(components, list):
                components_list = components
        mock_issue = MagicMock()
        response_data = {
            "key": f"{project_key}-456",
            "summary": summary,
            "description": description,
            "issue_type": {"name": issue_type},
            "status": {"name": "Open"},
            "components": [{"name": comp} for comp in components_list]
            if components_list
            else [],
            **additional_fields,
        }
        mock_issue.to_simplified_dict.return_value = response_data
        return mock_issue

    mock_fetcher.create_issue.side_effect = mock_create_issue

    # Configure batch_create_issues
    def mock_batch_create_issues(issues, validate_only=False):
        if not isinstance(issues, list):
            try:
                parsed_issues = json.loads(issues)
                if not isinstance(parsed_issues, list):
                    raise ValueError(
                        "Issues must be a list or a valid JSON array string."
                    )
                issues = parsed_issues
            except (json.JSONDecodeError, TypeError):
                raise ValueError("Issues must be a list or a valid JSON array string.")
        mock_issues = []
        for idx, issue_data in enumerate(issues, 1):
            mock_issue = MagicMock()
            mock_issue.to_simplified_dict.return_value = {
                "key": f"{issue_data['project_key']}-{idx}",
                "summary": issue_data["summary"],
                "issue_type": {"name": issue_data["issue_type"]},
                "status": {"name": "To Do"},
            }
            mock_issues.append(mock_issue)
        return mock_issues

    mock_fetcher.batch_create_issues.side_effect = mock_batch_create_issues

    # Configure get_epic_issues
    def mock_get_epic_issues(epic_key, start=0, limit=50):
        mock_issues = []
        for i in range(1, 4):
            mock_issue = MagicMock()
            mock_issue.to_simplified_dict.return_value = {
                "key": f"TEST-{i}",
                "summary": f"Epic Issue {i}",
                "issue_type": {"name": "Task" if i % 2 == 0 else "Bug"},
                "status": {"name": "To Do" if i % 2 == 0 else "In Progress"},
            }
            mock_issues.append(mock_issue)
        return mock_issues[start : start + limit]

    mock_fetcher.get_epic_issues.side_effect = mock_get_epic_issues

    # Configure get_all_projects
    def mock_get_all_projects(include_archived=False):
        projects = [
            {
                "id": "10000",
                "key": "TEST",
                "name": "Test Project",
                "description": "Project for testing",
                "lead": {"name": "admin", "displayName": "Administrator"},
                "projectTypeKey": "software",
                "archived": False,
            }
        ]
        if include_archived:
            projects.append(
                {
                    "id": "10001",
                    "key": "ARCHIVED",
                    "name": "Archived Project",
                    "description": "Archived project",
                    "lead": {"name": "admin", "displayName": "Administrator"},
                    "projectTypeKey": "software",
                    "archived": True,
                }
            )
        return projects

    # Set default side_effect to respect include_archived parameter
    mock_fetcher.get_all_projects.side_effect = mock_get_all_projects

    mock_fetcher.jira.jql.return_value = {
        "issues": [
            {
                "fields": {
                    "project": {
                        "key": "TEST",
                        "name": "Test Project",
                        "description": "Project for testing",
                    }
                }
            }
        ]
    }

    from mcp_atlassian.models.jira.common import JiraUser

    mock_user = MagicMock(spec=JiraUser)
    mock_user.to_simplified_dict.return_value = {
        "display_name": "Test User (test.profile@example.com)",
        "name": "Test User (test.profile@example.com)",
        "email": "test.profile@example.com",
        "avatar_url": "https://test.atlassian.net/avatar/test.profile@example.com",
    }
    mock_get_user_profile = MagicMock()

    def side_effect_func(identifier):
        if identifier == "nonexistent@example.com":
            raise ValueError(f"User '{identifier}' not found.")
        return mock_user

    mock_get_user_profile.side_effect = side_effect_func
    mock_fetcher.get_user_profile_by_identifier = mock_get_user_profile
    return mock_fetcher


@pytest.fixture
def mock_base_jira_config():
    """Create a mock base JiraConfig for MainAppContext using OAuth for multi-user scenario."""
    mock_oauth_config = OAuthConfig(
        client_id="server_client_id",
        client_secret="server_client_secret",
        redirect_uri="http://localhost",
        scope="read:jira-work",
        cloud_id="mock_jira_cloud_id",
    )
    return JiraConfig(
        url="https://mock-jira.atlassian.net",
        auth_type="oauth",
        oauth_config=mock_oauth_config,
    )


@pytest.fixture
def test_jira_mcp(mock_jira_fetcher, mock_base_jira_config):
    """Create a test FastMCP instance with standard configuration."""

    @asynccontextmanager
    async def test_lifespan(app: FastMCP) -> AsyncGenerator[MainAppContext, None]:
        try:
            yield MainAppContext(
                full_jira_config=mock_base_jira_config, read_only=False
            )
        finally:
            pass

    test_mcp = AtlassianMCP(name="TestJira", lifespan=test_lifespan)

    # Mount the actual jira MCP instance
    from mcp_atlassian.servers.jira import jira_mcp

    test_mcp.mount(jira_mcp, "jira")
    return test_mcp


@pytest.fixture
def no_fetcher_test_jira_mcp(mock_base_jira_config):
    """Create a test FastMCP instance that simulates missing Jira fetcher."""

    @asynccontextmanager
    async def no_fetcher_test_lifespan(
        app: FastMCP,
    ) -> AsyncGenerator[MainAppContext, None]:
        try:
            yield MainAppContext(full_jira_config=None, read_only=False)
        finally:
            pass

    test_mcp = AtlassianMCP(
        name="NoFetcherTestJira",
        lifespan=no_fetcher_test_lifespan,
    )
    # Mount the actual jira MCP instance
    from mcp_atlassian.servers.jira import jira_mcp

    test_mcp.mount(jira_mcp, "jira")
    return test_mcp


@pytest.fixture
def mock_request():
    """Provides a mock Starlette Request object with a state."""
    request = MagicMock(spec=Request)
    request.state = MagicMock()
    request.state.jira_fetcher = None
    request.state.user_atlassian_auth_type = None
    request.state.user_atlassian_token = None
    request.state.user_atlassian_email = None
    return request


class DirectJiraToolCaller:
    """Direct tool caller that bypasses FastMCP transport to avoid hanging."""

    def __init__(self, mock_jira_fetcher):
        self.mock_jira_fetcher = mock_jira_fetcher

    async def call_tool(self, tool_name: str, parameters: dict):
        """Call server tools directly without FastMCP transport."""
        from fastmcp.server.context import Context
        from starlette.requests import Request

        from mcp_atlassian.servers.jira import (
            add_comment,
            add_worklog,
            batch_create_issues,
            batch_create_versions,
            batch_get_changelogs,
            create_issue,
            create_issue_link,
            create_remote_issue_link,
            create_sprint,
            create_version,
            delete_issue,
            download_attachments,
            get_agile_boards,
            get_all_projects,
            get_board_issues,
            get_issue,
            get_link_types,
            get_project_issues,
            get_project_versions,
            get_sprint_issues,
            get_sprints_from_board,
            get_transitions,
            get_user_profile,
            get_worklog,
            link_to_epic,
            remove_issue_link,
            search,
            search_fields,
            transition_issue,
            update_issue,
            update_sprint,
        )

        # Create mock context
        mock_context = MagicMock(spec=Context)
        mock_request = MagicMock(spec=Request)
        mock_request.state = MagicMock()
        mock_context.session = {"request": mock_request}

        # Map tool names to functions
        tools = {
            "jira_get_user_profile": get_user_profile.fn,
            "jira_get_issue": get_issue.fn,
            "jira_search": search.fn,
            "jira_search_fields": search_fields.fn,
            "jira_get_project_issues": get_project_issues.fn,
            "jira_get_transitions": get_transitions.fn,
            "jira_get_worklog": get_worklog.fn,
            "jira_download_attachments": download_attachments.fn,
            "jira_get_agile_boards": get_agile_boards.fn,
            "jira_get_board_issues": get_board_issues.fn,
            "jira_get_sprints_from_board": get_sprints_from_board.fn,
            "jira_get_sprint_issues": get_sprint_issues.fn,
            "jira_get_link_types": get_link_types.fn,
            "jira_batch_get_changelogs": batch_get_changelogs.fn,
            "jira_get_project_versions": get_project_versions.fn,
            "jira_get_all_projects": get_all_projects.fn,
            "jira_create_issue": create_issue.fn,
            "jira_batch_create_issues": batch_create_issues.fn,
            "jira_update_issue": update_issue.fn,
            "jira_delete_issue": delete_issue.fn,
            "jira_add_comment": add_comment.fn,
            "jira_create_issue_link": create_issue_link.fn,
            "jira_create_version": create_version.fn,
            "jira_batch_create_versions": batch_create_versions.fn,
            "jira_add_worklog": add_worklog.fn,
            "jira_link_to_epic": link_to_epic.fn,
            "jira_create_remote_issue_link": create_remote_issue_link.fn,
            "jira_remove_issue_link": remove_issue_link.fn,
            "jira_transition_issue": transition_issue.fn,
            "jira_create_sprint": create_sprint.fn,
            "jira_update_sprint": update_sprint.fn,
        }

        if tool_name not in tools:
            raise ValueError(f"Unknown tool: {tool_name}")

        tool_fn = tools[tool_name]

        # Mock the result format to match FastMCP response structure
        class MockContent:
            def __init__(self, text):
                self.text = text
                self.type = "text"

        class MockResponse:
            def __init__(self, text):
                self.content = [MockContent(text)]

        # Call the tool function directly with parameters
        try:
            result = await tool_fn(mock_context, **parameters)
            return MockResponse(result)
        except ValueError as e:
            # Convert ValueError to ToolError for test compatibility
            from fastmcp.exceptions import ToolError

            # Extract tool name from tool_name for error formatting
            tool_short_name = tool_name.replace("jira_", "")
            error_msg = f"Error calling tool '{tool_short_name}': {str(e)}"
            raise ToolError(error_msg)


@pytest.fixture
async def jira_client(test_jira_mcp, mock_jira_fetcher, mock_request):
    """Create a direct tool caller that avoids FastMCP transport hanging."""
    with (
        patch(
            "mcp_atlassian.servers.jira.get_jira_fetcher",
            AsyncMock(return_value=mock_jira_fetcher),
        ),
        patch(
            "mcp_atlassian.servers.dependencies.get_http_request",
            return_value=mock_request,
        ),
    ):
        yield DirectJiraToolCaller(mock_jira_fetcher)


@pytest.fixture
async def no_fetcher_client_fixture(no_fetcher_test_jira_mcp, mock_request):
    """Create a client that simulates missing Jira fetcher configuration."""
    # Use direct tool caller to avoid FastMCP transport hanging
    yield DirectJiraToolCaller(None)  # No fetcher for this test case


@pytest.mark.anyio
async def test_get_issue(jira_client, mock_jira_fetcher):
    """Test the get_issue tool with fixture data."""
    response = await jira_client.call_tool(
        "jira_get_issue",
        {
            "issue_key": "TEST-123",
            "fields": "summary,description,status",
        },
    )
    assert hasattr(response, "content")
    content_list = response.content
    assert isinstance(content_list, list)
    assert len(content_list) > 0
    text_content = content_list[0]
    assert text_content.type == "text"
    content = json.loads(text_content.text)
    assert content["key"] == "TEST-123"
    assert content["summary"] == "Test Issue Summary"
    mock_jira_fetcher.get_issue.assert_called_once_with(
        issue_key="TEST-123",
        fields=["summary", "description", "status"],
        expand=None,
        comment_limit=10,
        properties=None,
        update_history=True,
    )


@pytest.mark.anyio
async def test_search(jira_client, mock_jira_fetcher):
    """Test the search tool with fixture data."""
    response = await jira_client.call_tool(
        "jira_search",
        {
            "jql": "project = TEST",
            "fields": "summary,status",
            "limit": 10,
            "start_at": 0,
        },
    )
    assert hasattr(response, "content")
    content_list = response.content
    assert isinstance(content_list, list)
    assert len(content_list) > 0
    text_content = content_list[0]
    assert text_content.type == "text"
    content = json.loads(text_content.text)
    assert isinstance(content, dict)
    assert "issues" in content
    assert isinstance(content["issues"], list)
    assert len(content["issues"]) >= 1
    assert content["issues"][0]["key"] == "PROJ-123"
    assert content["total"] > 0
    assert content["start_at"] == 0
    assert content["max_results"] == 10
    mock_jira_fetcher.search_issues.assert_called_once_with(
        jql="project = TEST",
        fields=["summary", "status"],
        limit=10,
        start=0,
        projects_filter=None,
        expand=None,
    )


@pytest.mark.anyio
async def test_search_fields_tool(jira_client, mock_jira_fetcher):
    """Test the jira_search_fields tool."""
    response = await jira_client.call_tool(
        "jira_search_fields", {"keyword": "sum", "limit": 5, "refresh": True}
    )
    mock_jira_fetcher.search_fields.assert_called_once_with(
        "sum", limit=5, refresh=True
    )
    result = json.loads(response.content[0].text)
    assert isinstance(result, list)
    assert result[0]["name"] == "Summary"


@pytest.mark.anyio
async def test_get_project_issues_tool(jira_client, mock_jira_fetcher):
    """Test jira_get_project_issues returns simplified search result."""
    response = await jira_client.call_tool(
        "jira_get_project_issues", {"project_key": "PROJ", "limit": 5, "start_at": 2}
    )
    mock_jira_fetcher.get_project_issues.assert_called_once_with(
        project_key="PROJ", start=2, limit=5
    )
    payload = json.loads(response.content[0].text)
    assert payload["total"] == 1
    assert payload["issues"][0]["key"] == "PROJ-1"


@pytest.mark.anyio
async def test_get_transitions_tool(jira_client, mock_jira_fetcher):
    """Test jira_get_transitions returns available transitions."""
    response = await jira_client.call_tool(
        "jira_get_transitions", {"issue_key": "PROJ-1"}
    )
    mock_jira_fetcher.get_available_transitions.assert_called_once_with("PROJ-1")
    data = json.loads(response.content[0].text)
    assert data[0]["name"] == "Start Progress"


@pytest.mark.anyio
async def test_get_worklog_tool(jira_client, mock_jira_fetcher):
    """Test jira_get_worklog returns worklogs."""
    response = await jira_client.call_tool("jira_get_worklog", {"issue_key": "PROJ-1"})
    mock_jira_fetcher.get_worklogs.assert_called_once_with("PROJ-1")
    payload = json.loads(response.content[0].text)
    assert payload["worklogs"][0]["timeSpent"] == "1h"


@pytest.mark.anyio
async def test_download_attachments_tool(jira_client, mock_jira_fetcher):
    """Test jira_download_attachments returns download summary."""
    response = await jira_client.call_tool(
        "jira_download_attachments",
        {"issue_key": "PROJ-1", "target_dir": "/tmp/downloads"},
    )
    mock_jira_fetcher.download_issue_attachments.assert_called_once_with(
        issue_key="PROJ-1", target_dir="/tmp/downloads"
    )
    payload = json.loads(response.content[0].text)
    assert payload["downloaded"] == 2


@pytest.mark.anyio
async def test_get_agile_boards_tool(jira_client, mock_jira_fetcher):
    """Test jira_get_agile_boards returns boards."""
    response = await jira_client.call_tool(
        "jira_get_agile_boards",
        {"board_name": "Sample", "project_key": "PROJ", "board_type": "scrum"},
    )
    mock_jira_fetcher.get_all_agile_boards_model.assert_called_once()
    boards = json.loads(response.content[0].text)
    assert boards[0]["name"] == "Sample Board"


@pytest.mark.anyio
async def test_get_board_issues_tool(jira_client, mock_jira_fetcher):
    """Test jira_get_board_issues converts field list."""
    response = await jira_client.call_tool(
        "jira_get_board_issues",
        {"board_id": "1", "jql": "project = PROJ", "fields": "summary,status"},
    )
    mock_jira_fetcher.get_board_issues.assert_called_once_with(
        board_id="1",
        jql="project = PROJ",
        fields=["summary", "status"],
        start=0,
        limit=10,
        expand="version",
    )
    data = json.loads(response.content[0].text)
    assert data["issues"][0]["key"] == "BOARD-1"


@pytest.mark.anyio
async def test_get_sprints_from_board_tool(jira_client, mock_jira_fetcher):
    """Test jira_get_sprints_from_board returns sprint list."""
    response = await jira_client.call_tool(
        "jira_get_sprints_from_board", {"board_id": "1", "state": "active"}
    )
    mock_jira_fetcher.get_all_sprints_from_board_model.assert_called_once()
    data = json.loads(response.content[0].text)
    assert data[0]["name"] == "Sprint 1"


@pytest.mark.anyio
async def test_get_sprint_issues_tool(jira_client, mock_jira_fetcher):
    """Test jira_get_sprint_issues returns issues."""
    response = await jira_client.call_tool(
        "jira_get_sprint_issues",
        {"sprint_id": "7", "fields": "summary,status", "limit": 3},
    )
    mock_jira_fetcher.get_sprint_issues.assert_called_once_with(
        sprint_id="7", fields=["summary", "status"], start=0, limit=3
    )
    payload = json.loads(response.content[0].text)
    assert payload["issues"][0]["key"] == "SPR-1"


@pytest.mark.anyio
async def test_get_link_types_tool(jira_client, mock_jira_fetcher):
    """Test jira_get_link_types returns formatted link types."""
    response = await jira_client.call_tool("jira_get_link_types", {})
    mock_jira_fetcher.get_issue_link_types.assert_called_once()
    data = json.loads(response.content[0].text)
    assert data[0]["name"] == "Relates"


@pytest.mark.anyio
async def test_batch_get_changelogs_tool(jira_client, mock_jira_fetcher):
    """Test jira_batch_get_changelogs returns changelogs."""
    response = await jira_client.call_tool(
        "jira_batch_get_changelogs",
        {"issue_ids_or_keys": ["PROJ-1"], "fields": ["status"], "limit": 1},
    )
    mock_jira_fetcher.batch_get_changelogs.assert_called_once_with(
        issue_ids_or_keys=["PROJ-1"], fields=["status"]
    )
    data = json.loads(response.content[0].text)
    assert data[0]["issue_id"] == "TEST-1"
    assert len(data[0]["changelogs"]) == 1


@pytest.mark.anyio
async def test_batch_get_changelogs_not_cloud(jira_client, mock_jira_fetcher):
    """Ensure jira_batch_get_changelogs errors on server/DC."""
    mock_jira_fetcher.config.is_cloud = False
    with pytest.raises(NotImplementedError):
        await jira_client.call_tool(
            "jira_batch_get_changelogs",
            {"issue_ids_or_keys": ["PROJ-1"], "fields": None},
        )
    mock_jira_fetcher.config.is_cloud = True


@pytest.mark.anyio
async def test_create_issue(jira_client, mock_jira_fetcher):
    """Test the create_issue tool with fixture data."""
    response = await jira_client.call_tool(
        "jira_create_issue",
        {
            "project_key": "TEST",
            "summary": "New Issue",
            "issue_type": "Task",
            "description": "This is a new task",
            "components": "Frontend,API",
            "additional_fields": {"priority": {"name": "Medium"}},
        },
    )
    assert hasattr(response, "content")
    content_list = response.content
    assert isinstance(content_list, list)
    assert len(content_list) > 0
    text_content = content_list[0]
    assert text_content.type == "text"
    content = json.loads(text_content.text)
    assert content["message"] == "Issue created successfully"
    assert "issue" in content
    assert content["issue"]["key"] == "TEST-456"
    assert content["issue"]["summary"] == "New Issue"
    assert content["issue"]["description"] == "This is a new task"
    assert "components" in content["issue"]
    component_names = [comp["name"] for comp in content["issue"]["components"]]
    assert "Frontend" in component_names
    assert "API" in component_names
    assert content["issue"]["priority"] == {"name": "Medium"}
    mock_jira_fetcher.create_issue.assert_called_once_with(
        project_key="TEST",
        summary="New Issue",
        issue_type="Task",
        description="This is a new task",
        assignee=None,
        components=["Frontend", "API"],
        priority={"name": "Medium"},
    )


@pytest.mark.anyio
async def test_batch_create_issues(jira_client, mock_jira_fetcher):
    """Test batch creation of Jira issues."""
    test_issues = [
        {
            "project_key": "TEST",
            "summary": "Test Issue 1",
            "issue_type": "Task",
            "description": "Test description 1",
            "assignee": "test.user@example.com",
            "components": ["Frontend", "API"],
        },
        {
            "project_key": "TEST",
            "summary": "Test Issue 2",
            "issue_type": "Bug",
            "description": "Test description 2",
        },
    ]
    test_issues_json = json.dumps(test_issues)
    response = await jira_client.call_tool(
        "jira_batch_create_issues",
        {"issues": test_issues_json, "validate_only": False},
    )
    assert hasattr(response, "content")
    content_list = response.content
    assert len(content_list) == 1
    text_content = content_list[0]
    assert text_content.type == "text"
    content = json.loads(text_content.text)
    assert "message" in content
    assert "issues" in content
    assert len(content["issues"]) == 2
    assert content["issues"][0]["key"] == "TEST-1"
    assert content["issues"][1]["key"] == "TEST-2"
    call_args, call_kwargs = mock_jira_fetcher.batch_create_issues.call_args
    assert call_args[0] == test_issues
    assert "validate_only" in call_kwargs
    assert call_kwargs["validate_only"] is False


@pytest.mark.anyio
async def test_batch_create_issues_invalid_json(jira_client):
    """Test error handling for invalid JSON in batch issue creation."""
    with pytest.raises(ToolError) as excinfo:
        await jira_client.call_tool(
            "jira_batch_create_issues",
            {"issues": "{invalid json", "validate_only": False},
        )
    assert "Error calling tool 'batch_create_issues'" in str(excinfo.value)


@pytest.mark.anyio
async def test_get_user_profile_tool_success(jira_client, mock_jira_fetcher):
    """Test the get_user_profile tool successfully retrieves user info."""
    response = await jira_client.call_tool(
        "jira_get_user_profile", {"user_identifier": "test.profile@example.com"}
    )
    mock_jira_fetcher.get_user_profile_by_identifier.assert_called_once_with(
        "test.profile@example.com"
    )
    assert len(response.content) == 1
    result_data = json.loads(response.content[0].text)
    assert result_data["success"] is True
    assert "user" in result_data
    user_info = result_data["user"]
    assert user_info["display_name"] == "Test User (test.profile@example.com)"
    assert user_info["email"] == "test.profile@example.com"
    assert (
        user_info["avatar_url"]
        == "https://test.atlassian.net/avatar/test.profile@example.com"
    )


@pytest.mark.anyio
async def test_get_user_profile_tool_not_found(jira_client, mock_jira_fetcher):
    """Test the get_user_profile tool handles 'user not found' errors."""
    response = await jira_client.call_tool(
        "jira_get_user_profile", {"user_identifier": "nonexistent@example.com"}
    )
    assert len(response.content) == 1
    result_data = json.loads(response.content[0].text)
    assert result_data["success"] is False
    assert "error" in result_data
    assert "not found" in result_data["error"]
    assert result_data["user_identifier"] == "nonexistent@example.com"


@pytest.mark.anyio
async def test_get_user_profile_tool_auth_error(jira_client, mock_jira_fetcher):
    """Test authentication errors are surfaced in get_user_profile."""
    original_side_effect = mock_jira_fetcher.get_user_profile_by_identifier.side_effect
    mock_jira_fetcher.get_user_profile_by_identifier.side_effect = (
        MCPAtlassianAuthenticationError("denied")
    )
    response = await jira_client.call_tool(
        "jira_get_user_profile", {"user_identifier": "denied@example.com"}
    )
    payload = json.loads(response.content[0].text)
    assert payload["success"] is False
    assert "denied" in payload["error"]
    mock_jira_fetcher.get_user_profile_by_identifier.side_effect = original_side_effect


@pytest.mark.anyio
async def test_get_user_profile_tool_network_error(jira_client, mock_jira_fetcher):
    """Test network errors are captured."""
    original_side_effect = mock_jira_fetcher.get_user_profile_by_identifier.side_effect
    mock_jira_fetcher.get_user_profile_by_identifier.side_effect = OSError("boom")
    response = await jira_client.call_tool(
        "jira_get_user_profile", {"user_identifier": "network@example.com"}
    )
    payload = json.loads(response.content[0].text)
    assert payload["success"] is False
    assert payload["error"] == "boom"
    mock_jira_fetcher.get_user_profile_by_identifier.side_effect = original_side_effect


@pytest.mark.anyio
async def test_get_user_profile_tool_unexpected_error(jira_client, mock_jira_fetcher):
    """Test unexpected exceptions in get_user_profile."""
    original_side_effect = mock_jira_fetcher.get_user_profile_by_identifier.side_effect
    mock_jira_fetcher.get_user_profile_by_identifier.side_effect = RuntimeError("boom")
    response = await jira_client.call_tool(
        "jira_get_user_profile", {"user_identifier": "oops@example.com"}
    )
    payload = json.loads(response.content[0].text)
    assert payload["success"] is False
    assert "oops@example.com" in payload["user_identifier"]
    mock_jira_fetcher.get_user_profile_by_identifier.side_effect = original_side_effect


@pytest.mark.anyio
async def test_no_fetcher_get_issue(no_fetcher_client_fixture, mock_request):
    """Test that get_issue fails when Jira client is not configured (global config missing)."""

    async def mock_get_fetcher_error(*args, **kwargs):
        raise ValueError(
            "Mocked: Jira client (fetcher) not available. Ensure server is configured correctly."
        )

    with (
        patch(
            "mcp_atlassian.servers.jira.get_jira_fetcher",
            AsyncMock(side_effect=mock_get_fetcher_error),
        ),
        patch(
            "mcp_atlassian.servers.dependencies.get_http_request",
            return_value=mock_request,
        ),
    ):
        with pytest.raises(ToolError) as excinfo:
            await no_fetcher_client_fixture.call_tool(
                "jira_get_issue",
                {
                    "issue_key": "TEST-123",
                },
            )
    assert "Error calling tool 'get_issue'" in str(excinfo.value)


@pytest.mark.anyio
async def test_get_issue_with_user_specific_fetcher_in_state(
    test_jira_mcp, mock_jira_fetcher, mock_base_jira_config
):
    """Test get_issue uses fetcher from request.state if UserTokenMiddleware provided it."""
    _mock_request_with_fetcher_in_state = MagicMock(spec=Request)
    _mock_request_with_fetcher_in_state.state = MagicMock()
    _mock_request_with_fetcher_in_state.state.jira_fetcher = mock_jira_fetcher
    _mock_request_with_fetcher_in_state.state.user_atlassian_auth_type = "oauth"
    _mock_request_with_fetcher_in_state.state.user_atlassian_token = (
        "user_specific_token"
    )

    # Define the specific fields we expect for this test case
    test_fields_str = "summary,status,issuetype"
    expected_fields_list = ["summary", "status", "issuetype"]

    # Import the real get_jira_fetcher to test its interaction with request.state
    from mcp_atlassian.servers.dependencies import (
        get_jira_fetcher as get_jira_fetcher_real,
    )

    with (
        patch(
            "mcp_atlassian.servers.dependencies.get_http_request",
            return_value=_mock_request_with_fetcher_in_state,
        ) as mock_get_http,
        patch(
            "mcp_atlassian.servers.jira.get_jira_fetcher",
            side_effect=AsyncMock(wraps=get_jira_fetcher_real),
        ),
    ):
        # Use direct function call to avoid FastMCP transport hanging
        direct_caller = DirectJiraToolCaller(mock_jira_fetcher)
        response = await direct_caller.call_tool(
            "jira_get_issue",
            {"issue_key": "USER-STATE-1", "fields": test_fields_str},
        )

    mock_get_http.assert_called()
    mock_jira_fetcher.get_issue.assert_called_with(
        issue_key="USER-STATE-1",
        fields=expected_fields_list,
        expand=None,
        comment_limit=10,
        properties=None,
        update_history=True,
    )
    result_data = json.loads(response.content[0].text)
    assert result_data["key"] == "USER-STATE-1"


@pytest.mark.anyio
async def test_update_issue_with_attachments(jira_client, mock_jira_fetcher):
    """Test jira_update_issue handles attachments and additional fields."""
    response = await jira_client.call_tool(
        "jira_update_issue",
        {
            "issue_key": "PROJ-1",
            "fields": {"summary": "Updated summary"},
            "additional_fields": {"customfield_1": "value"},
            "attachments": '["/tmp/file.txt"]',
        },
    )
    mock_jira_fetcher.update_issue.assert_called_once_with(
        issue_key="PROJ-1",
        summary="Updated summary",
        customfield_1="value",
        attachments=["/tmp/file.txt"],
    )
    payload = json.loads(response.content[0].text)
    assert payload["issue"]["attachment_results"][0]["file"] == "doc.txt"


@pytest.mark.anyio
async def test_update_issue_invalid_attachments(jira_client):
    """Test jira_update_issue validates attachment format."""
    with pytest.raises(ToolError):
        await jira_client.call_tool(
            "jira_update_issue",
            {
                "issue_key": "PROJ-1",
                "fields": {"summary": "Updated"},
                "attachments": 123,
            },
        )


@pytest.mark.anyio
async def test_delete_issue_tool(jira_client, mock_jira_fetcher):
    """Test jira_delete_issue performs deletion."""
    response = await jira_client.call_tool("jira_delete_issue", {"issue_key": "PROJ-9"})
    mock_jira_fetcher.delete_issue.assert_called_once_with("PROJ-9")
    payload = json.loads(response.content[0].text)
    assert "deleted" in payload["message"]


@pytest.mark.anyio
async def test_add_comment_tool(jira_client, mock_jira_fetcher):
    """Test jira_add_comment returns comment payload."""
    response = await jira_client.call_tool(
        "jira_add_comment", {"issue_key": "PROJ-1", "comment": "Nice work!"}
    )
    mock_jira_fetcher.add_comment.assert_called_once_with("PROJ-1", "Nice work!")
    payload = json.loads(response.content[0].text)
    assert payload["body"] == "Added comment"


@pytest.mark.anyio
async def test_add_worklog_tool(jira_client, mock_jira_fetcher):
    """Test jira_add_worklog returns success message."""
    response = await jira_client.call_tool(
        "jira_add_worklog",
        {
            "issue_key": "PROJ-1",
            "time_spent": "1h",
            "comment": "Worked on task",
        },
    )
    mock_jira_fetcher.add_worklog.assert_called_once()
    payload = json.loads(response.content[0].text)
    assert payload["message"].startswith("Worklog")


@pytest.mark.anyio
async def test_link_to_epic_tool(jira_client, mock_jira_fetcher):
    """Test jira_link_to_epic returns updated issue."""
    response = await jira_client.call_tool(
        "jira_link_to_epic", {"issue_key": "PROJ-1", "epic_key": "EPIC-9"}
    )
    mock_jira_fetcher.link_issue_to_epic.assert_called_once_with("PROJ-1", "EPIC-9")
    payload = json.loads(response.content[0].text)
    assert "linked to epic" in payload["message"]


@pytest.mark.anyio
async def test_create_issue_link_tool(jira_client, mock_jira_fetcher):
    """Test jira_create_issue_link forwards payload."""
    response = await jira_client.call_tool(
        "jira_create_issue_link",
        {
            "link_type": "Relates",
            "inward_issue_key": "PROJ-1",
            "outward_issue_key": "PROJ-2",
        },
    )
    mock_jira_fetcher.create_issue_link.assert_called_once()
    link_payload = mock_jira_fetcher.create_issue_link.call_args.args[0]
    assert link_payload["type"]["name"] == "Relates"
    assert link_payload["inwardIssue"]["key"] == "PROJ-1"
    payload = json.loads(response.content[0].text)
    assert payload["status"] == "LINKED"


@pytest.mark.anyio
async def test_create_remote_issue_link_requires_fields(jira_client):
    """Missing required fields should raise ToolError."""
    with pytest.raises(ToolError):
        await jira_client.call_tool(
            "jira_create_remote_issue_link",
            {"issue_key": "PROJ-1", "url": "", "title": ""},
        )


@pytest.mark.anyio
async def test_create_remote_issue_link_success(jira_client, mock_jira_fetcher):
    """Test jira_create_remote_issue_link builds link data."""
    response = await jira_client.call_tool(
        "jira_create_remote_issue_link",
        {
            "issue_key": "PROJ-1",
            "url": "https://example.com",
            "title": "Docs",
            "summary": "See docs",
            "relationship": "relates to",
            "icon_url": "https://example.com/icon.png",
        },
    )
    mock_jira_fetcher.create_remote_issue_link.assert_called_once()
    payload = json.loads(response.content[0].text)
    assert payload["id"] == "remote-link"


@pytest.mark.anyio
async def test_remove_issue_link_tool(jira_client, mock_jira_fetcher):
    """Test jira_remove_issue_link returns status."""
    response = await jira_client.call_tool("jira_remove_issue_link", {"link_id": "55"})
    mock_jira_fetcher.remove_issue_link.assert_called_once_with("55")
    payload = json.loads(response.content[0].text)
    assert payload["removed"] is True


@pytest.mark.anyio
async def test_transition_issue_validation(jira_client):
    """Missing issue_key/transition_id should raise ToolError."""
    with pytest.raises(ToolError):
        await jira_client.call_tool(
            "jira_transition_issue",
            {"issue_key": "", "transition_id": "", "fields": {"resolution": "Done"}},
        )


@pytest.mark.anyio
async def test_transition_issue_success(jira_client, mock_jira_fetcher):
    """Test jira_transition_issue returns message."""
    response = await jira_client.call_tool(
        "jira_transition_issue",
        {
            "issue_key": "PROJ-1",
            "transition_id": "31",
            "fields": {"resolution": {"name": "Done"}},
        },
    )
    mock_jira_fetcher.transition_issue.assert_called_once()
    payload = json.loads(response.content[0].text)
    assert "transitioned successfully" in payload["message"]


@pytest.mark.anyio
async def test_create_sprint_tool(jira_client, mock_jira_fetcher):
    """Test jira_create_sprint returns sprint info."""
    response = await jira_client.call_tool(
        "jira_create_sprint",
        {
            "board_id": "1",
            "sprint_name": "Sprint 1",
            "start_date": "2024-01-01T00:00:00.000+0000",
            "end_date": "2024-01-15T00:00:00.000+0000",
            "goal": "Ship feature",
        },
    )
    mock_jira_fetcher.create_sprint.assert_called_once()
    payload = json.loads(response.content[0].text)
    assert payload["name"] == "Created Sprint"


@pytest.mark.anyio
async def test_update_sprint_tool(jira_client, mock_jira_fetcher):
    """Test jira_update_sprint returns updated sprint."""
    response = await jira_client.call_tool(
        "jira_update_sprint",
        {
            "sprint_id": "7",
            "sprint_name": "Renamed",
            "state": "active",
            "goal": "Keep delivering",
        },
    )
    mock_jira_fetcher.update_sprint.assert_called_once_with(
        sprint_id="7",
        sprint_name="Renamed",
        state="active",
        start_date=None,
        end_date=None,
        goal="Keep delivering",
    )
    payload = json.loads(response.content[0].text)
    assert payload["name"] == "Updated Sprint"


@pytest.mark.anyio
async def test_get_project_versions_tool(jira_client, mock_jira_fetcher):
    """Test the jira_get_project_versions tool returns simplified version list."""
    # Prepare mock raw versions
    raw_versions = [
        {
            "id": "100",
            "name": "v1.0",
            "description": "First",
            "released": True,
            "archived": False,
        },
        {
            "id": "101",
            "name": "v2.0",
            "startDate": "2025-01-01",
            "releaseDate": "2025-02-01",
            "released": False,
            "archived": False,
        },
    ]
    mock_jira_fetcher.get_project_versions.return_value = raw_versions

    response = await jira_client.call_tool(
        "jira_get_project_versions",
        {"project_key": "TEST"},
    )
    assert hasattr(response, "content")
    content_list = response.content
    assert isinstance(content_list, list)
    assert len(response.content) == 1  # FastMCP wraps as list of messages
    msg = content_list[0]
    assert msg.type == "text"
    import json

    data = json.loads(msg.text)
    assert isinstance(data, list)
    # Check fields in simplified dict
    assert data[0]["id"] == "100"
    assert data[0]["name"] == "v1.0"
    assert data[0]["description"] == "First"


@pytest.mark.anyio
async def test_get_all_projects_tool(jira_client, mock_jira_fetcher):
    """Test the jira_get_all_projects tool returns all accessible projects."""
    # Prepare mock project data
    mock_projects = [
        {
            "id": "10000",
            "key": "PROJ1",
            "name": "Project One",
            "description": "First project",
            "lead": {"name": "user1", "displayName": "User One"},
            "projectTypeKey": "software",
            "archived": False,
        },
        {
            "id": "10001",
            "key": "PROJ2",
            "name": "Project Two",
            "description": "Second project",
            "lead": {"name": "user2", "displayName": "User Two"},
            "projectTypeKey": "business",
            "archived": False,
        },
    ]
    # Reset the mock and set specific return value for this test
    mock_jira_fetcher.get_all_projects.reset_mock()
    mock_jira_fetcher.get_all_projects.side_effect = (
        lambda include_archived=False: mock_projects
    )

    # Test with default parameters (include_archived=False)
    response = await jira_client.call_tool(
        "jira_get_all_projects",
        {},
    )
    assert hasattr(response, "content")
    content_list = response.content
    assert isinstance(content_list, list)
    assert len(response.content) == 1  # FastMCP wraps as list of messages
    msg = content_list[0]
    assert msg.type == "text"

    data = json.loads(msg.text)
    assert isinstance(data, list)
    assert len(data) == 2
    assert data[0]["id"] == "10000"
    assert data[0]["key"] == "PROJ1"
    assert data[0]["name"] == "Project One"
    assert data[1]["id"] == "10001"
    assert data[1]["key"] == "PROJ2"
    assert data[1]["name"] == "Project Two"

    # Verify the underlying method was called with default parameter
    mock_jira_fetcher.get_all_projects.assert_called_once_with(include_archived=False)


@pytest.mark.anyio
async def test_get_all_projects_tool_with_archived(jira_client, mock_jira_fetcher):
    """Test the jira_get_all_projects tool with include_archived=True."""
    mock_projects = [
        {
            "id": "10000",
            "key": "PROJ1",
            "name": "Active Project",
            "description": "Active project",
            "archived": False,
        },
        {
            "id": "10002",
            "key": "ARCHIVED",
            "name": "Archived Project",
            "description": "Archived project",
            "archived": True,
        },
    ]
    # Reset the mock and set specific return value for this test
    mock_jira_fetcher.get_all_projects.reset_mock()
    mock_jira_fetcher.get_all_projects.side_effect = (
        lambda include_archived=False: mock_projects
    )

    # Test with include_archived=True
    response = await jira_client.call_tool(
        "jira_get_all_projects",
        {"include_archived": True},
    )
    assert hasattr(response, "content")
    content_list = response.content
    assert isinstance(content_list, list)
    assert len(response.content) == 1
    msg = content_list[0]
    assert msg.type == "text"

    data = json.loads(msg.text)
    assert isinstance(data, list)
    assert len(data) == 2
    # Project keys should always be uppercase in the response
    assert data[0]["key"] == "PROJ1"
    assert data[1]["key"] == "ARCHIVED"

    # Verify the underlying method was called with include_archived=True
    mock_jira_fetcher.get_all_projects.assert_called_once_with(include_archived=True)


@pytest.mark.anyio
async def test_get_all_projects_tool_with_projects_filter(
    jira_client, mock_jira_fetcher
):
    """Test the jira_get_all_projects tool respects project filter configuration."""
    # Prepare mock project data - simulate getting all projects from API
    all_mock_projects = [
        {
            "id": "10000",
            "key": "PROJ1",
            "name": "Project One",
            "description": "First project",
        },
        {
            "id": "10001",
            "key": "PROJ2",
            "name": "Project Two",
            "description": "Second project",
        },
        {
            "id": "10002",
            "key": "OTHER",
            "name": "Other Project",
            "description": "Should be filtered out",
        },
    ]

    # Set up the mock to return all projects
    mock_jira_fetcher.get_all_projects.reset_mock()
    mock_jira_fetcher.get_all_projects.side_effect = (
        lambda include_archived=False: all_mock_projects
    )

    # Set up the projects filter in the config
    mock_jira_fetcher.config.projects_filter = "PROJ1,PROJ2"

    # Call the tool
    response = await jira_client.call_tool(
        "jira_get_all_projects",
        {},
    )

    assert hasattr(response, "content")
    content_list = response.content
    assert isinstance(content_list, list)
    assert len(response.content) == 1
    msg = content_list[0]
    assert msg.type == "text"

    data = json.loads(msg.text)
    assert isinstance(data, list)

    # Should only return projects in the filter (PROJ1, PROJ2), not OTHER
    assert len(data) == 2
    returned_keys = [project["key"] for project in data]
    # Project keys should always be uppercase in the response
    assert "PROJ1" in returned_keys
    assert "PROJ2" in returned_keys
    assert "OTHER" not in returned_keys

    # Verify the underlying method was called (still gets all projects, but then filters)
    mock_jira_fetcher.get_all_projects.assert_called_once_with(include_archived=False)


@pytest.mark.anyio
async def test_get_all_projects_tool_no_projects_filter(jira_client, mock_jira_fetcher):
    """Test the jira_get_all_projects tool returns all projects when no filter is configured."""
    # Prepare mock project data
    all_mock_projects = [
        {
            "id": "10000",
            "key": "PROJ1",
            "name": "Project One",
            "description": "First project",
        },
        {
            "id": "10001",
            "key": "OTHER",
            "name": "Other Project",
            "description": "Should not be filtered out",
        },
    ]

    # Set up the mock to return all projects
    mock_jira_fetcher.get_all_projects.reset_mock()
    mock_jira_fetcher.get_all_projects.side_effect = (
        lambda include_archived=False: all_mock_projects
    )

    # Ensure no projects filter is set
    mock_jira_fetcher.config.projects_filter = None

    # Call the tool
    response = await jira_client.call_tool(
        "jira_get_all_projects",
        {},
    )

    assert hasattr(response, "content")
    content_list = response.content
    assert isinstance(content_list, list)
    assert len(response.content) == 1
    msg = content_list[0]
    assert msg.type == "text"

    data = json.loads(msg.text)
    assert isinstance(data, list)

    # Should return all projects when no filter is configured
    assert len(data) == 2
    returned_keys = [project["key"] for project in data]
    # Project keys should always be uppercase in the response
    assert "PROJ1" in returned_keys
    assert "OTHER" in returned_keys

    # Verify the underlying method was called
    mock_jira_fetcher.get_all_projects.assert_called_once_with(include_archived=False)


@pytest.mark.anyio
async def test_get_all_projects_tool_case_insensitive_filter(
    jira_client, mock_jira_fetcher
):
    """Test the jira_get_all_projects tool handles case-insensitive filtering and whitespace."""
    # Prepare mock project data with mixed case
    all_mock_projects = [
        {
            "id": "10000",
            "key": "proj1",  # lowercase
            "name": "Project One",
            "description": "First project",
        },
        {
            "id": "10001",
            "key": "PROJ2",  # uppercase
            "name": "Project Two",
            "description": "Second project",
        },
        {
            "id": "10002",
            "key": "other",  # should be filtered out
            "name": "Other Project",
            "description": "Should be filtered out",
        },
    ]

    # Set up the mock to return all projects
    mock_jira_fetcher.get_all_projects.reset_mock()
    mock_jira_fetcher.get_all_projects.side_effect = (
        lambda include_archived=False: all_mock_projects
    )

    # Set up projects filter with mixed case and whitespace
    mock_jira_fetcher.config.projects_filter = " PROJ1 , proj2 "

    # Call the tool
    response = await jira_client.call_tool(
        "jira_get_all_projects",
        {},
    )

    assert hasattr(response, "content")
    content_list = response.content
    assert isinstance(content_list, list)
    assert len(response.content) == 1
    msg = content_list[0]
    assert msg.type == "text"

    data = json.loads(msg.text)
    assert isinstance(data, list)

    # Should return projects matching the filter (case-insensitive)
    assert len(data) == 2
    returned_keys = [project["key"] for project in data]
    # Project keys should always be uppercase in the response, regardless of input case
    assert "PROJ1" in returned_keys  # lowercase input converted to uppercase
    assert "PROJ2" in returned_keys  # uppercase stays uppercase
    assert "OTHER" not in returned_keys  # not in filter

    # Verify the underlying method was called
    mock_jira_fetcher.get_all_projects.assert_called_once_with(include_archived=False)


@pytest.mark.anyio
async def test_get_all_projects_tool_empty_response(jira_client, mock_jira_fetcher):
    """Test tool handles empty list of projects from API."""
    mock_jira_fetcher.get_all_projects.side_effect = lambda include_archived=False: []

    response = await jira_client.call_tool("jira_get_all_projects", {})

    assert hasattr(response, "content")
    content_list = response.content
    assert isinstance(content_list, list)
    assert len(response.content) == 1
    msg = content_list[0]
    assert msg.type == "text"

    data = json.loads(msg.text)
    assert data == []


@pytest.mark.anyio
async def test_get_all_projects_tool_api_error_handling(jira_client, mock_jira_fetcher):
    """Test tool handles API errors gracefully."""
    from requests.exceptions import HTTPError

    mock_jira_fetcher.get_all_projects.side_effect = HTTPError("API Error")

    response = await jira_client.call_tool("jira_get_all_projects", {})

    assert hasattr(response, "content")
    content_list = response.content
    assert isinstance(content_list, list)
    assert len(response.content) == 1
    msg = content_list[0]
    assert msg.type == "text"

    data = json.loads(msg.text)
    assert data["success"] is False
    assert "API Error" in data["error"]


@pytest.mark.anyio
async def test_get_all_projects_tool_authentication_error_handling(
    jira_client, mock_jira_fetcher
):
    """Test tool handles authentication errors gracefully."""
    mock_jira_fetcher.get_all_projects.side_effect = MCPAtlassianAuthenticationError(
        "Authentication failed"
    )

    response = await jira_client.call_tool("jira_get_all_projects", {})

    assert hasattr(response, "content")
    content_list = response.content
    assert isinstance(content_list, list)
    assert len(response.content) == 1
    msg = content_list[0]
    assert msg.type == "text"

    data = json.loads(msg.text)
    assert data["success"] is False
    assert "Authentication/Permission Error" in data["error"]


@pytest.mark.anyio
async def test_get_all_projects_tool_configuration_error_handling(
    jira_client, mock_jira_fetcher
):
    """Test tool handles configuration errors gracefully."""
    mock_jira_fetcher.get_all_projects.side_effect = ValueError(
        "Jira client not configured"
    )

    response = await jira_client.call_tool("jira_get_all_projects", {})

    assert hasattr(response, "content")
    content_list = response.content
    assert isinstance(content_list, list)
    assert len(response.content) == 1
    msg = content_list[0]
    assert msg.type == "text"

    data = json.loads(msg.text)
    assert data["success"] is False
    assert "Configuration Error" in data["error"]


@pytest.mark.anyio
async def test_batch_create_versions_all_success(jira_client, mock_jira_fetcher):
    """Test batch creation of Jira versions where all succeed."""
    versions = [
        {
            "name": "v1.0",
            "startDate": "2025-01-01",
            "releaseDate": "2025-02-01",
            "description": "First release",
        },
        {"name": "v2.0", "description": "Second release"},
    ]
    # Patch create_project_version to always succeed
    mock_jira_fetcher.create_project_version.side_effect = lambda **kwargs: {
        "id": f"{kwargs['name']}-id",
        **kwargs,
    }
    response = await jira_client.call_tool(
        "jira_batch_create_versions",
        {"project_key": "TEST", "versions": json.dumps(versions)},
    )
    assert len(response.content) == 1
    content = json.loads(response.content[0].text)
    assert all(item["success"] for item in content)
    assert content[0]["version"]["name"] == "v1.0"
    assert content[1]["version"]["name"] == "v2.0"


@pytest.mark.anyio
async def test_batch_create_versions_partial_failure(jira_client, mock_jira_fetcher):
    """Test batch creation of Jira versions with some failures."""

    def side_effect(
        project_key, name, start_date=None, release_date=None, description=None
    ):
        if name == "bad":
            raise Exception("Simulated failure")
        return {"id": f"{name}-id", "name": name}

    mock_jira_fetcher.create_project_version.side_effect = side_effect
    versions = [
        {"name": "good1"},
        {"name": "bad"},
        {"name": "good2"},
    ]
    response = await jira_client.call_tool(
        "jira_batch_create_versions",
        {"project_key": "TEST", "versions": json.dumps(versions)},
    )
    content = json.loads(response.content[0].text)
    assert content[0]["success"] is True
    assert content[1]["success"] is False
    assert "Simulated failure" in content[1]["error"]
    assert content[2]["success"] is True


@pytest.mark.anyio
async def test_batch_create_versions_all_failure(jira_client, mock_jira_fetcher):
    """Test batch creation of Jira versions where all fail."""
    mock_jira_fetcher.create_project_version.side_effect = Exception("API down")
    versions = [
        {"name": "fail1"},
        {"name": "fail2"},
    ]
    response = await jira_client.call_tool(
        "jira_batch_create_versions",
        {"project_key": "TEST", "versions": json.dumps(versions)},
    )
    content = json.loads(response.content[0].text)
    assert all(not item["success"] for item in content)
    assert all("API down" in item["error"] for item in content)


@pytest.mark.anyio
async def test_batch_create_versions_empty(jira_client, mock_jira_fetcher):
    """Test batch creation of Jira versions with empty input."""
    response = await jira_client.call_tool(
        "jira_batch_create_versions",
        {"project_key": "TEST", "versions": json.dumps([])},
    )
    content = json.loads(response.content[0].text)
    assert content == []


@pytest.mark.anyio
async def test_create_version_error_handling(jira_client, mock_jira_fetcher):
    """Test jira_create_version returns error payload."""
    mock_jira_fetcher.create_project_version.side_effect = Exception("boom")
    response = await jira_client.call_tool(
        "jira_create_version",
        {
            "project_key": "PROJ",
            "name": "Version X",
            "start_date": "2024-01-01",
            "release_date": "2024-02-01",
        },
    )
    data = json.loads(response.content[0].text)
    assert data["success"] is False
    mock_jira_fetcher.create_project_version.side_effect = None
