"""Tests for the Jira Search mixin."""

from unittest.mock import MagicMock

import pytest
import requests

from mcp_atlassian.jira import JiraFetcher
from mcp_atlassian.jira.search import SearchMixin
from mcp_atlassian.models.jira import JiraIssue, JiraSearchResult


class TestSearchMixin:
    """Tests for the SearchMixin class."""

    @pytest.fixture
    def search_mixin(self, jira_fetcher: JiraFetcher) -> SearchMixin:
        """Create a SearchMixin instance with mocked dependencies."""
        mixin = jira_fetcher

        # Mock methods that are typically provided by other mixins
        mixin._clean_text = MagicMock(side_effect=lambda text: text if text else "")

        # Set config with is_cloud=False by default (Server/DC)
        mixin.config = MagicMock()
        mixin.config.is_cloud = False
        mixin.config.projects_filter = None
        mixin.config.url = "https://example.atlassian.net"

        return mixin

    @pytest.fixture
    def mock_issues_response(self) -> dict:
        """Create a mock Jira issues response for testing."""
        return {
            "issues": [
                {
                    "id": "10001",
                    "key": "TEST-123",
                    "fields": {
                        "summary": "Test issue",
                        "issuetype": {"name": "Bug"},
                        "status": {"name": "Open"},
                        "description": "Test description",
                        "created": "2024-01-01T10:00:00.000+0000",
                        "updated": "2024-01-01T11:00:00.000+0000",
                    },
                }
            ],
            "total": 1,
            "startAt": 0,
            "maxResults": 50,
        }

    @staticmethod
    def _setup_dual_mocks(search_mixin, issues_response):
        """Mock both the Cloud (enhanced JQL) and Server/DC (POST) code paths."""
        search_mixin.jira.post = MagicMock(
            return_value={**issues_response, "count": issues_response.get("total", 0)}
        )
        search_mixin.jira.enhanced_jql_get_list_of_tickets = MagicMock(
            return_value=issues_response["issues"]
        )

    @staticmethod
    def _constructed_jql(search_mixin, is_cloud):
        """Return the JQL actually sent, regardless of deployment path."""
        if is_cloud:
            return search_mixin.jira.enhanced_jql_get_list_of_tickets.call_args[0][0]
        return search_mixin.jira.post.call_args[1]["json"]["jql"]

    @staticmethod
    def _reset_dual_mocks(search_mixin):
        search_mixin.jira.post.reset_mock()
        search_mixin.jira.enhanced_jql_get_list_of_tickets.reset_mock()

    @pytest.mark.parametrize("is_cloud", [True, False])
    def test_search_issues_routes_by_deployment(
        self,
        search_mixin: SearchMixin,
        mock_issues_response,
        is_cloud,
    ):
        """Cloud uses the enhanced JQL API; Server/DC uses POST /rest/api/2/search."""
        search_mixin.config.is_cloud = is_cloud
        search_mixin.config.projects_filter = None
        search_mixin.config.url = "https://test.example.com"

        self._setup_dual_mocks(search_mixin, mock_issues_response)

        jql_query = "project = TEST"
        result = search_mixin.search_issues(jql_query, limit=10, start=0)

        assert isinstance(result, JiraSearchResult)
        assert len(result.issues) > 0

        if is_cloud:
            search_mixin.jira.enhanced_jql_get_list_of_tickets.assert_called_once()
            assert (
                search_mixin.jira.enhanced_jql_get_list_of_tickets.call_args[0][0]
                == jql_query
            )
            search_mixin.jira.post.assert_called_once()
            assert search_mixin.jira.post.call_args[1]["json"] == {"jql": jql_query}
        else:
            search_mixin.jira.post.assert_called_once()
            body = search_mixin.jira.post.call_args[1]["json"]
            assert body["jql"] == jql_query
            assert body["startAt"] == 0
            assert "maxResults" in body

    def test_search_issues_basic(self, search_mixin: SearchMixin):
        """Test basic search functionality."""
        # Setup mock response
        mock_issues = {
            "issues": [
                {
                    "id": "10001",
                    "key": "TEST-123",
                    "fields": {
                        "summary": "Test issue",
                        "issuetype": {"name": "Bug"},
                        "status": {"name": "Open"},
                        "description": "Issue description",
                        "created": "2024-01-01T10:00:00.000+0000",
                        "updated": "2024-01-01T11:00:00.000+0000",
                        "priority": {"name": "High"},
                    },
                }
            ],
            "total": 1,
            "startAt": 0,
            "maxResults": 50,
        }
        search_mixin.jira.post = MagicMock(return_value=mock_issues)

        # Call the method
        result = search_mixin.search_issues("project = TEST")

        # Verify POST call with correct body
        search_mixin.jira.post.assert_called_once()
        body = search_mixin.jira.post.call_args[1]["json"]
        assert body["jql"] == "project = TEST"
        assert body["startAt"] == 0
        assert body["maxResults"] == 50

        # Verify results
        assert isinstance(result, JiraSearchResult)
        assert len(result.issues) == 1
        assert all(isinstance(issue, JiraIssue) for issue in result.issues)
        assert result.total == 1
        assert result.start_at == 0
        assert result.max_results == 50

        # Check the first issue
        issue = result.issues[0]
        assert issue.key == "TEST-123"
        assert issue.summary == "Test issue"
        assert issue.description == "Issue description"
        assert issue.status is not None
        assert issue.status.name == "Open"
        assert issue.issue_type is not None
        assert issue.issue_type.name == "Bug"
        assert issue.priority is not None
        assert issue.priority.name == "High"

        assert "Issue description" in issue.description
        assert issue.key == "TEST-123"

    def test_search_issues_with_empty_description(self, search_mixin: SearchMixin):
        """Test search with issues that have no description."""
        # Setup mock response
        mock_issues = {
            "issues": [
                {
                    "id": "10001",
                    "key": "TEST-123",
                    "fields": {
                        "summary": "Test issue",
                        "issuetype": {"name": "Bug"},
                        "status": {"name": "Open"},
                        "description": None,
                        "created": "2024-01-01T10:00:00.000+0000",
                        "updated": "2024-01-01T11:00:00.000+0000",
                    },
                }
            ],
            "total": 1,
            "startAt": 0,
            "maxResults": 50,
        }
        search_mixin.jira.post = MagicMock(return_value=mock_issues)

        # Call the method
        result = search_mixin.search_issues("project = TEST")

        # Verify results
        assert len(result.issues) == 1
        assert isinstance(result.issues[0], JiraIssue)
        assert result.issues[0].key == "TEST-123"
        assert result.issues[0].description is None
        assert result.issues[0].summary == "Test issue"

        assert "Test issue" in result.issues[0].summary

    def test_search_issues_with_missing_fields(self, search_mixin: SearchMixin):
        """Test search with issues missing some fields."""
        # Setup mock response
        mock_issues = {
            "issues": [
                {
                    "key": "TEST-123",
                    "fields": {
                        "summary": "Test issue",
                        # Missing issuetype, status, etc.
                    },
                }
            ],
            "total": 1,
            "startAt": 0,
            "maxResults": 50,
        }
        search_mixin.jira.post = MagicMock(return_value=mock_issues)

        # Call the method
        result = search_mixin.search_issues("project = TEST")

        # Verify results
        assert len(result.issues) == 1
        assert isinstance(result.issues[0], JiraIssue)
        assert result.issues[0].key == "TEST-123"
        assert result.issues[0].summary == "Test issue"
        assert result.issues[0].status is None
        assert result.issues[0].issue_type is None

    def test_search_issues_with_empty_results(self, search_mixin: SearchMixin):
        """Test search with no results."""
        # Setup mock response
        search_mixin.jira.post = MagicMock(
            return_value={"issues": [], "total": 0, "startAt": 0, "maxResults": 50}
        )

        # Call the method
        result = search_mixin.search_issues("project = NONEXISTENT")

        # Verify results
        assert isinstance(result, JiraSearchResult)
        assert len(result.issues) == 0

    def test_search_issues_with_error(self, search_mixin: SearchMixin):
        """Test search with API error."""
        # Setup mock to raise exception
        search_mixin.jira.post = MagicMock(side_effect=Exception("API Error"))

        # Call the method and verify it raises the expected exception
        with pytest.raises(Exception, match="Error searching issues"):
            search_mixin.search_issues("project = TEST")

    def test_search_issues_with_projects_filter(self, search_mixin: SearchMixin):
        """Test search with projects filter."""
        # Setup mock response
        mock_issues = {
            "issues": [
                {
                    "id": "10001",
                    "key": "TEST-123",
                    "fields": {
                        "summary": "Test issue",
                        "issuetype": {"name": "Bug"},
                        "status": {"name": "Open"},
                    },
                }
            ],
            "total": 1,
            "startAt": 0,
            "maxResults": 50,
        }
        search_mixin.jira.post = MagicMock(return_value=mock_issues)
        search_mixin.config.url = "https://example.atlassian.net"

        # Test with single project filter
        result = search_mixin.search_issues("text ~ 'test'", projects_filter="TEST")
        body = search_mixin.jira.post.call_args[1]["json"]
        assert body["jql"] == "(text ~ 'test') AND project = \"TEST\""
        assert len(result.issues) == 1
        assert result.total == 1

        search_mixin.jira.post.reset_mock()

        # Test with multiple project filter
        result = search_mixin.search_issues("text ~ 'test'", projects_filter="TEST,DEV")
        body = search_mixin.jira.post.call_args[1]["json"]
        assert body["jql"] == '(text ~ \'test\') AND project IN ("TEST", "DEV")'
        assert len(result.issues) == 1
        assert result.total == 1

    def test_search_issues_with_config_projects_filter(self, search_mixin: SearchMixin):
        """Test search with projects filter from config."""
        # Setup mock response
        mock_issues = {
            "issues": [
                {
                    "id": "10001",
                    "key": "TEST-123",
                    "fields": {
                        "summary": "Test issue",
                        "issuetype": {"name": "Bug"},
                        "status": {"name": "Open"},
                    },
                }
            ],
            "total": 1,
            "startAt": 0,
            "maxResults": 50,
        }
        search_mixin.jira.post = MagicMock(return_value=mock_issues)
        search_mixin.config.url = "https://example.atlassian.net"
        search_mixin.config.projects_filter = "TEST,DEV"

        # Test with config filter
        result = search_mixin.search_issues("text ~ 'test'")
        body = search_mixin.jira.post.call_args[1]["json"]
        assert body["jql"] == '(text ~ \'test\') AND project IN ("TEST", "DEV")'
        assert len(result.issues) == 1
        assert result.total == 1

        search_mixin.jira.post.reset_mock()

        # Test with override
        result = search_mixin.search_issues("text ~ 'test'", projects_filter="OVERRIDE")
        body = search_mixin.jira.post.call_args[1]["json"]
        assert body["jql"] == "(text ~ 'test') AND project = \"OVERRIDE\""
        assert len(result.issues) == 1
        assert result.total == 1

        search_mixin.jira.post.reset_mock()

        # Test with override - multiple projects
        result = search_mixin.search_issues(
            "text ~ 'test'", projects_filter="OVER1,OVER2"
        )
        body = search_mixin.jira.post.call_args[1]["json"]
        assert body["jql"] == '(text ~ \'test\') AND project IN ("OVER1", "OVER2")'
        assert len(result.issues) == 1
        assert result.total == 1

    def test_search_issues_with_fields_parameter(self, search_mixin: SearchMixin):
        """Test search with specific fields parameter, including custom fields."""
        # Setup mock response with a custom field
        mock_issues = {
            "issues": [
                {
                    "id": "10001",
                    "key": "TEST-123",
                    "fields": {
                        "summary": "Test issue with custom field",
                        "assignee": {
                            "displayName": "Test User",
                            "emailAddress": "test@example.com",
                            "active": True,
                        },
                        "customfield_10049": "Custom value",
                        "issuetype": {"name": "Bug"},
                        "status": {"name": "Open"},
                        "description": "Issue description",
                        "created": "2024-01-01T10:00:00.000+0000",
                        "updated": "2024-01-01T11:00:00.000+0000",
                        "priority": {"name": "High"},
                    },
                }
            ],
            "total": 1,
            "startAt": 0,
            "maxResults": 50,
        }
        search_mixin.jira.post = MagicMock(return_value=mock_issues)
        search_mixin.config.url = "https://example.atlassian.net"

        # Call the method with specific fields
        result = search_mixin.search_issues(
            "project = TEST", fields="summary,assignee,customfield_10049"
        )

        # Verify POST body includes correct fields list
        body = search_mixin.jira.post.call_args[1]["json"]
        assert body["jql"] == "project = TEST"
        assert "summary" in body["fields"]
        assert "assignee" in body["fields"]
        assert "customfield_10049" in body["fields"]

        # Verify results
        assert isinstance(result, JiraSearchResult)
        assert len(result.issues) == 1
        issue = result.issues[0]

        # Convert to simplified dict to check field filtering
        simplified = issue.to_simplified_dict()

        # These fields should be included (plus id and key which are always included)
        assert "id" in simplified
        assert "key" in simplified
        assert "summary" in simplified
        assert "assignee" in simplified
        assert "customfield_10049" in simplified

        assert simplified["customfield_10049"] == {"value": "Custom value"}
        assert "assignee" in simplified
        assert simplified["assignee"]["display_name"] == "Test User"

    def test_get_board_issues(self, search_mixin: SearchMixin):
        """Test get_board_issues method."""
        mock_issues = {
            "issues": [
                {
                    "id": "10001",
                    "key": "TEST-123",
                    "fields": {
                        "summary": "Test issue",
                        "issuetype": {"name": "Bug"},
                        "status": {"name": "Open"},
                        "description": "Issue description",
                        "created": "2024-01-01T10:00:00.000+0000",
                        "updated": "2024-01-01T11:00:00.000+0000",
                        "priority": {"name": "High"},
                    },
                }
            ],
            "total": 1,
            "startAt": 0,
            "maxResults": 50,
        }
        search_mixin.jira.get_issues_for_board.return_value = mock_issues

        # Call the method
        result = search_mixin.get_board_issues("1000", jql="", limit=20)

        # Verify results
        assert isinstance(result, JiraSearchResult)
        assert len(result.issues) == 1
        assert all(isinstance(issue, JiraIssue) for issue in result.issues)
        assert result.total == 1
        assert result.start_at == 0
        assert result.max_results == 50

        # Check the first issue
        issue = result.issues[0]
        assert issue.key == "TEST-123"
        assert issue.summary == "Test issue"
        assert issue.description == "Issue description"
        assert issue.status is not None
        assert issue.status.name == "Open"
        assert issue.issue_type is not None
        assert issue.issue_type.name == "Bug"
        assert issue.priority is not None
        assert issue.priority.name == "High"

        # Remove backward compatibility checks
        assert "Issue description" in issue.description
        assert issue.key == "TEST-123"

    def test_get_board_issues_exception(self, search_mixin: SearchMixin):
        search_mixin.jira.get_issues_for_board.side_effect = Exception("API Error")

        with pytest.raises(Exception) as e:
            search_mixin.get_board_issues("1000", jql="", limit=20)
        assert "API Error" in str(e.value)

    def test_get_board_issues_http_error(self, search_mixin: SearchMixin):
        search_mixin.jira.get_issues_for_board.side_effect = requests.HTTPError(
            response=MagicMock(content="API Error content")
        )

        with pytest.raises(Exception) as e:
            search_mixin.get_board_issues("1000", jql="", limit=20)
        assert "API Error content" in str(e.value)

    def test_get_sprint_issues(self, search_mixin: SearchMixin):
        """Test get_sprint_issues method."""
        mock_issues = {
            "issues": [
                {
                    "id": "10001",
                    "key": "TEST-123",
                    "fields": {
                        "summary": "Test issue",
                        "issuetype": {"name": "Bug"},
                        "status": {"name": "Open"},
                        "description": "Issue description",
                        "created": "2024-01-01T10:00:00.000+0000",
                        "updated": "2024-01-01T11:00:00.000+0000",
                        "priority": {"name": "High"},
                    },
                }
            ],
            "total": 1,
            "startAt": 0,
            "maxResults": 50,
        }
        search_mixin.jira.get_sprint_issues.return_value = mock_issues

        # Call the method
        result = search_mixin.get_sprint_issues("10001")

        # Verify results
        assert isinstance(result, JiraSearchResult)
        assert len(result.issues) == 1
        assert all(isinstance(issue, JiraIssue) for issue in result.issues)
        assert result.total == 1
        assert result.start_at == 0
        assert result.max_results == 50

        # Check the first issue
        issue = result.issues[0]
        assert issue.key == "TEST-123"
        assert issue.summary == "Test issue"
        assert issue.description == "Issue description"
        assert issue.status is not None
        assert issue.status.name == "Open"
        assert issue.issue_type is not None
        assert issue.issue_type.name == "Bug"
        assert issue.priority is not None
        assert issue.priority.name == "High"

    def test_get_sprint_issues_exception(self, search_mixin: SearchMixin):
        search_mixin.jira.get_sprint_issues.side_effect = Exception("API Error")

        with pytest.raises(Exception) as e:
            search_mixin.get_sprint_issues("10001")
        assert "API Error" in str(e.value)

    def test_get_sprint_issues_http_error(self, search_mixin: SearchMixin):
        search_mixin.jira.get_sprint_issues.side_effect = requests.HTTPError(
            response=MagicMock(content="API Error content")
        )

        with pytest.raises(Exception) as e:
            search_mixin.get_sprint_issues("10001")
        assert "API Error content" in str(e.value)

    @pytest.mark.parametrize("is_cloud", [True, False])
    def test_search_issues_with_projects_filter_jql_construction(
        self, search_mixin: SearchMixin, mock_issues_response, is_cloud
    ):
        """Test that JQL string is correctly constructed when projects_filter is provided."""
        search_mixin.config.is_cloud = is_cloud
        search_mixin.config.projects_filter = None
        search_mixin.config.url = "https://test.example.com"

        self._setup_dual_mocks(search_mixin, mock_issues_response)

        # Single project filter
        search_mixin.search_issues("text ~ 'test'", projects_filter="TEST")
        jql = self._constructed_jql(search_mixin, is_cloud)
        assert jql == "(text ~ 'test') AND project = \"TEST\""
        self._reset_dual_mocks(search_mixin)

        # Multiple projects filter
        search_mixin.search_issues("text ~ 'test'", projects_filter="TEST, DEV")
        jql = self._constructed_jql(search_mixin, is_cloud)
        assert jql == '(text ~ \'test\') AND project IN ("TEST", "DEV")'
        self._reset_dual_mocks(search_mixin)

        # Existing JQL already contains project filter — not wrapped
        search_mixin.search_issues("project = OTHER", projects_filter="TEST")
        jql = self._constructed_jql(search_mixin, is_cloud)
        assert jql == "project = OTHER"

    @pytest.mark.parametrize("is_cloud", [True, False])
    def test_search_issues_with_config_projects_filter_jql_construction(
        self, search_mixin: SearchMixin, mock_issues_response, is_cloud
    ):
        """Test that JQL string is correctly constructed when config.projects_filter is used."""
        search_mixin.config.is_cloud = is_cloud
        search_mixin.config.projects_filter = "CONF1,CONF2"
        search_mixin.config.url = "https://test.example.com"

        self._setup_dual_mocks(search_mixin, mock_issues_response)

        # Use config filter
        search_mixin.search_issues("text ~ 'test'")
        jql = self._constructed_jql(search_mixin, is_cloud)
        assert jql == '(text ~ \'test\') AND project IN ("CONF1", "CONF2")'
        self._reset_dual_mocks(search_mixin)

        # Override config filter with parameter
        search_mixin.search_issues("text ~ 'test'", projects_filter="OVERRIDE")
        jql = self._constructed_jql(search_mixin, is_cloud)
        assert jql == "(text ~ 'test') AND project = \"OVERRIDE\""

    @pytest.mark.parametrize("is_cloud", [True, False])
    def test_search_issues_with_empty_jql_and_projects_filter(
        self, search_mixin: SearchMixin, mock_issues_response, is_cloud
    ):
        """Test that empty JQL correctly prepends project filter without AND."""
        # Setup
        search_mixin.config.is_cloud = is_cloud
        search_mixin.config.projects_filter = None
        search_mixin.config.url = "https://test.example.com"

        self._setup_dual_mocks(search_mixin, mock_issues_response)

        # Test 1: Empty string JQL with single project
        search_mixin.search_issues("", projects_filter="PROJ1")
        jql = self._constructed_jql(search_mixin, is_cloud)
        assert jql == 'project = "PROJ1"'
        self._reset_dual_mocks(search_mixin)

        # Test 2: Empty string JQL with multiple projects
        search_mixin.search_issues("", projects_filter="PROJ1,PROJ2")
        jql = self._constructed_jql(search_mixin, is_cloud)
        assert jql == 'project IN ("PROJ1", "PROJ2")'
        self._reset_dual_mocks(search_mixin)

        # Test 3: None JQL with projects filter
        result = search_mixin.search_issues(None, projects_filter="PROJ1")
        jql = self._constructed_jql(search_mixin, is_cloud)
        assert jql == 'project = "PROJ1"'
        assert isinstance(result, JiraSearchResult)

    @pytest.mark.parametrize("is_cloud", [True, False])
    def test_search_issues_with_order_by_and_projects_filter(
        self, search_mixin: SearchMixin, mock_issues_response, is_cloud
    ):
        """Test that JQL starting with ORDER BY correctly prepends project filter."""
        # Setup
        search_mixin.config.is_cloud = is_cloud
        search_mixin.config.projects_filter = None
        search_mixin.config.url = "https://test.example.com"

        self._setup_dual_mocks(search_mixin, mock_issues_response)

        # Test 1: ORDER BY with single project
        search_mixin.search_issues("ORDER BY created DESC", projects_filter="PROJ1")
        jql = self._constructed_jql(search_mixin, is_cloud)
        assert jql == 'project = "PROJ1" ORDER BY created DESC'
        self._reset_dual_mocks(search_mixin)

        # Test 2: ORDER BY with multiple projects
        search_mixin.search_issues(
            "ORDER BY created DESC", projects_filter="PROJ1,PROJ2"
        )
        jql = self._constructed_jql(search_mixin, is_cloud)
        assert jql == 'project IN ("PROJ1", "PROJ2") ORDER BY created DESC'
        self._reset_dual_mocks(search_mixin)

        # Test 3: Case insensitive ORDER BY
        search_mixin.search_issues("order by updated ASC", projects_filter="PROJ1")
        jql = self._constructed_jql(search_mixin, is_cloud)
        assert jql == 'project = "PROJ1" order by updated ASC'
        self._reset_dual_mocks(search_mixin)

        # Test 4: ORDER BY with extra spaces
        search_mixin.search_issues(
            "  ORDER BY priority DESC  ", projects_filter="PROJ1"
        )
        jql = self._constructed_jql(search_mixin, is_cloud)
        assert jql == 'project = "PROJ1"   ORDER BY priority DESC  '

    def test_search_issues_large_jql_uses_post_body(self, search_mixin: SearchMixin):
        """Large JQL with many OR clauses must be passed via POST body unchanged."""
        # Build a query representative of the reported 150-180 clause failure
        clauses = " OR ".join(f'key = "PROJ-{i}"' for i in range(1, 161))
        large_jql = f"({clauses})"

        search_mixin.jira.post = MagicMock(
            return_value={
                "issues": [],
                "total": 0,
                "startAt": 0,
                "maxResults": 50,
            }
        )

        result = search_mixin.search_issues(large_jql, limit=50)

        assert isinstance(result, JiraSearchResult)
        search_mixin.jira.post.assert_called_once()
        body = search_mixin.jira.post.call_args[1]["json"]
        # Full JQL must be in the request body — not truncated or URL-encoded
        assert body["jql"] == large_jql
        # Confirms we exceed typical URL length limits
        assert len(body["jql"]) > 2000

    def test_search_issues_post_body_fields_star_all(self, search_mixin: SearchMixin):
        """fields='*all' is correctly serialised to ['*all'] in the POST body."""
        search_mixin.jira.post = MagicMock(
            return_value={"issues": [], "total": 0, "startAt": 0, "maxResults": 50}
        )

        search_mixin.search_issues("project = TEST", fields="*all")

        body = search_mixin.jira.post.call_args[1]["json"]
        assert body["fields"] == ["*all"]

    def test_search_issues_post_body_expand(self, search_mixin: SearchMixin):
        """Expand parameter is included as a list in the POST body."""
        search_mixin.jira.post = MagicMock(
            return_value={"issues": [], "total": 0, "startAt": 0, "maxResults": 50}
        )

        search_mixin.search_issues("project = TEST", expand="renderedFields,changelog")

        body = search_mixin.jira.post.call_args[1]["json"]
        assert "renderedFields" in body["expand"]
        assert "changelog" in body["expand"]

    def test_search_issues_dc_caps_max_results_at_50(self, search_mixin: SearchMixin):
        """Data Center path caps maxResults at 50."""
        search_mixin.config.is_cloud = False
        search_mixin.jira.post = MagicMock(
            return_value={"issues": [], "total": 0, "startAt": 0, "maxResults": 50}
        )

        search_mixin.search_issues("project = TEST", limit=200)

        body = search_mixin.jira.post.call_args[1]["json"]
        assert body["maxResults"] <= 50

    def test_search_issues_cloud_uses_enhanced_jql(self, search_mixin: SearchMixin):
        """Cloud path uses the enhanced JQL API, passing the requested limit."""
        search_mixin.config.is_cloud = True
        search_mixin.jira.get = MagicMock()
        search_mixin.jira.enhanced_jql_get_list_of_tickets = MagicMock(return_value=[])
        search_mixin.jira.post = MagicMock(return_value={"count": 7})

        result = search_mixin.search_issues("project = TEST", limit=200)

        search_mixin.jira.enhanced_jql_get_list_of_tickets.assert_called_once()
        _, kwargs = search_mixin.jira.enhanced_jql_get_list_of_tickets.call_args
        assert kwargs["limit"] == 200
        search_mixin.jira.get.assert_not_called()
        assert search_mixin.jira.post.call_args[1]["json"] == {"jql": "project = TEST"}
        assert result.total == 7

    def test_search_issues_cloud_keeps_results_without_count(
        self, search_mixin: SearchMixin
    ):
        """A failed approximate count leaves total at -1 and keeps the issues."""
        search_mixin.config.is_cloud = True
        search_mixin.jira.enhanced_jql_get_list_of_tickets = MagicMock(return_value=[])
        search_mixin.jira.post = MagicMock(side_effect=ValueError("removed"))

        result = search_mixin.search_issues("project = TEST")

        search_mixin.jira.enhanced_jql_get_list_of_tickets.assert_called_once()
        assert result.total == -1
