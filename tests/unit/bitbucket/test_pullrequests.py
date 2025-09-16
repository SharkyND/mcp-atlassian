"""Tests for the Bitbucket pull requests module."""

from unittest.mock import MagicMock, Mock, patch

import pytest
from requests.exceptions import HTTPError

from mcp_atlassian.bitbucket.config import BitbucketConfig
from mcp_atlassian.bitbucket.pullrequests import PullRequestsMixin
from mcp_atlassian.exceptions import MCPAtlassianAuthenticationError
from mcp_atlassian.models.bitbucket.common import BitbucketPullRequest


class TestPullRequestsMixin:
    """Test cases for PullRequestsMixin class."""

    @pytest.fixture
    def config(self):
        """Create a configuration for testing."""
        return BitbucketConfig(
            url="https://api.bitbucket.org/2.0",
            auth_type="basic",
            username="test@example.com",
            app_password="app_password",
        )

    @pytest.fixture
    def pullrequests_mixin(self, config):
        """Create a PullRequestsMixin instance for testing."""
        with patch("mcp_atlassian.bitbucket.client.Bitbucket"):
            with patch("mcp_atlassian.bitbucket.client.configure_ssl_verification"):
                mixin = PullRequestsMixin(config)
                mixin.bitbucket = MagicMock()
                return mixin

    @pytest.fixture
    def sample_pull_request_data(self):
        """Create sample pull request data for testing."""
        return [
            {
                "id": 1,
                "title": "Add new feature",
                "description": "This PR adds a new feature",
                "state": "OPEN",
                "author": {"username": "john_doe", "display_name": "John Doe"},
                "source": {"branch": {"name": "feature/new-feature"}},
                "destination": {"branch": {"name": "main"}},
                "created_on": "2023-01-01T00:00:00Z",
                "updated_on": "2023-01-02T00:00:00Z",
            },
            {
                "id": 2,
                "title": "Fix bug",
                "description": "This PR fixes a critical bug",
                "state": "MERGED",
                "author": {"username": "jane_doe", "display_name": "Jane Doe"},
                "source": {"branch": {"name": "bugfix/critical-fix"}},
                "destination": {"branch": {"name": "main"}},
                "created_on": "2023-01-03T00:00:00Z",
                "updated_on": "2023-01-04T00:00:00Z",
            },
        ]

    def test_get_all_pull_requests_success(
        self, pullrequests_mixin, sample_pull_request_data
    ):
        """Test successful retrieval of all pull requests."""
        pullrequests_mixin.bitbucket.get_pull_requests.return_value = (
            sample_pull_request_data
        )

        with patch(
            "mcp_atlassian.models.bitbucket.common.BitbucketPullRequest.from_api_response"
        ) as mock_from_api:
            mock_prs = []
            for pr_data in sample_pull_request_data:
                mock_pr = MagicMock(spec=BitbucketPullRequest)
                mock_pr.id = pr_data["id"]
                mock_pr.title = pr_data["title"]
                mock_prs.append(mock_pr)
            mock_from_api.side_effect = mock_prs

            result = pullrequests_mixin.get_all_pull_requests("workspace", "repo")

            assert len(result) == 2
            pullrequests_mixin.bitbucket.get_pull_requests.assert_called_once_with(
                "workspace", "repo", "OPEN"
            )

    def test_get_all_pull_requests_with_state(
        self, pullrequests_mixin, sample_pull_request_data
    ):
        """Test retrieval of pull requests with specific state."""
        pullrequests_mixin.bitbucket.get_pull_requests.return_value = (
            sample_pull_request_data
        )

        with patch(
            "mcp_atlassian.models.bitbucket.common.BitbucketPullRequest.from_api_response"
        ) as mock_from_api:
            mock_prs = []
            for pr_data in sample_pull_request_data:
                mock_pr = MagicMock(spec=BitbucketPullRequest)
                mock_pr.id = pr_data["id"]
                mock_prs.append(mock_pr)
            mock_from_api.side_effect = mock_prs

            result = pullrequests_mixin.get_all_pull_requests(
                "workspace", "repo", "MERGED"
            )

            assert len(result) == 2
            pullrequests_mixin.bitbucket.get_pull_requests.assert_called_once_with(
                "workspace", "repo", "MERGED"
            )

    def test_get_all_pull_requests_authentication_error_401(self, pullrequests_mixin):
        """Test authentication error (401) handling."""
        mock_response = Mock()
        mock_response.status_code = 401
        http_error = HTTPError(response=mock_response)
        pullrequests_mixin.bitbucket.get_pull_requests.side_effect = http_error

        with pytest.raises(MCPAtlassianAuthenticationError):
            pullrequests_mixin.get_all_pull_requests("workspace", "repo")

    def test_get_all_pull_requests_authentication_error_403(self, pullrequests_mixin):
        """Test authentication error (403) handling."""
        mock_response = Mock()
        mock_response.status_code = 403
        http_error = HTTPError(response=mock_response)
        pullrequests_mixin.bitbucket.get_pull_requests.side_effect = http_error

        with pytest.raises(MCPAtlassianAuthenticationError):
            pullrequests_mixin.get_all_pull_requests("workspace", "repo")

    def test_get_all_pull_requests_http_error_other(self, pullrequests_mixin):
        """Test other HTTP error handling."""
        mock_response = Mock()
        mock_response.status_code = 500
        http_error = HTTPError(response=mock_response)
        pullrequests_mixin.bitbucket.get_pull_requests.side_effect = http_error

        with pytest.raises(HTTPError):
            pullrequests_mixin.get_all_pull_requests("workspace", "repo")

    def test_get_all_pull_requests_general_exception(self, pullrequests_mixin):
        """Test general exception handling."""
        pullrequests_mixin.bitbucket.get_pull_requests.side_effect = Exception(
            "API error"
        )

        with pytest.raises(Exception) as exc_info:
            pullrequests_mixin.get_all_pull_requests("workspace", "repo")

        assert "Error getting pull requests" in str(exc_info.value)

    def test_get_pull_request_success(self, pullrequests_mixin):
        """Test successful retrieval of pull request by ID."""
        pr_data = {
            "id": 1,
            "title": "Test PR",
            "description": "Test description",
            "state": "OPEN",
        }
        pullrequests_mixin.bitbucket.get_pull_request.return_value = pr_data

        with patch(
            "mcp_atlassian.models.bitbucket.common.BitbucketPullRequest.from_api_response"
        ) as mock_from_api:
            mock_pr = MagicMock(spec=BitbucketPullRequest)
            mock_pr.id = 1
            mock_from_api.return_value = mock_pr

            result = pullrequests_mixin.get_pull_request("workspace", "repo", 1)

            assert result is not None
            assert result.id == 1

    def test_get_pull_request_authentication_error(self, pullrequests_mixin):
        """Test authentication error in get_pull_request."""
        mock_response = Mock()
        mock_response.status_code = 401
        http_error = HTTPError(response=mock_response)
        pullrequests_mixin.bitbucket.get_pull_request.side_effect = http_error

        with pytest.raises(MCPAtlassianAuthenticationError):
            pullrequests_mixin.get_pull_request("workspace", "repo", 1)

    def test_get_pull_request_general_exception(self, pullrequests_mixin):
        """Test general exception in get_pull_request."""
        pullrequests_mixin.bitbucket.get_pull_request.side_effect = Exception(
            "API error"
        )

        with pytest.raises(Exception) as exc_info:
            pullrequests_mixin.get_pull_request("workspace", "repo", 1)

        assert "Error getting pull request" in str(exc_info.value)

    def test_create_pull_request_success(self, pullrequests_mixin):
        """Test successful creation of pull request."""
        pr_data = {
            "id": 1,
            "title": "New PR",
            "description": "New PR description",
            "state": "OPEN",
        }
        pullrequests_mixin.bitbucket.create_pull_request.return_value = pr_data

        with patch(
            "mcp_atlassian.models.bitbucket.common.BitbucketPullRequest.from_api_response"
        ) as mock_from_api:
            mock_pr = MagicMock(spec=BitbucketPullRequest)
            mock_pr.id = 1
            mock_from_api.return_value = mock_pr

            pr_request_data = {
                "title": "New PR",
                "description": "New PR description",
                "source": {"branch": {"name": "feature"}},
                "destination": {"branch": {"name": "main"}},
            }
            result = pullrequests_mixin.create_pull_request(
                "workspace", "repo", pr_request_data
            )

            assert result is not None
            pullrequests_mixin.bitbucket.create_pull_request.assert_called_once_with(
                "workspace", "repo", pr_request_data
            )

    def test_create_pull_request_authentication_error(self, pullrequests_mixin):
        """Test authentication error in create_pull_request."""
        mock_response = Mock()
        mock_response.status_code = 403
        http_error = HTTPError(response=mock_response)
        pullrequests_mixin.bitbucket.create_pull_request.side_effect = http_error

        pr_request_data = {
            "title": "New PR",
            "description": "New PR description",
            "source": {"branch": {"name": "feature"}},
            "destination": {"branch": {"name": "main"}},
        }

        with pytest.raises(MCPAtlassianAuthenticationError):
            pullrequests_mixin.create_pull_request("workspace", "repo", pr_request_data)

    def test_create_pull_request_general_exception(self, pullrequests_mixin):
        """Test general exception in create_pull_request."""
        pullrequests_mixin.bitbucket.create_pull_request.side_effect = Exception(
            "API error"
        )

        pr_request_data = {
            "title": "New PR",
            "description": "New PR description",
            "source": {"branch": {"name": "feature"}},
            "destination": {"branch": {"name": "main"}},
        }

        with pytest.raises(Exception) as exc_info:
            pullrequests_mixin.create_pull_request("workspace", "repo", pr_request_data)

        assert "Error creating pull request" in str(exc_info.value)

    def test_get_pull_request_commits_success(self, pullrequests_mixin):
        """Test successful retrieval of pull request commits."""
        commits_data = [
            {"hash": "abc123", "message": "Commit 1"},
            {"hash": "def456", "message": "Commit 2"},
        ]
        pullrequests_mixin.bitbucket.get_pull_requests_commits.return_value = (
            commits_data
        )

        result = pullrequests_mixin.get_pull_request_commits("workspace", "repo", 1)

        assert len(result) == 2
        assert result[0]["hash"] == "abc123"

    def test_get_pull_request_commits_authentication_error(self, pullrequests_mixin):
        """Test authentication error in get_pull_request_commits."""
        mock_response = Mock()
        mock_response.status_code = 401
        http_error = HTTPError(response=mock_response)
        pullrequests_mixin.bitbucket.get_pull_requests_commits.side_effect = http_error

        with pytest.raises(MCPAtlassianAuthenticationError):
            pullrequests_mixin.get_pull_request_commits("workspace", "repo", 1)

    def test_get_pull_request_commits_general_exception(self, pullrequests_mixin):
        """Test general exception in get_pull_request_commits."""
        pullrequests_mixin.bitbucket.get_pull_requests_commits.side_effect = Exception(
            "API error"
        )

        with pytest.raises(Exception) as exc_info:
            pullrequests_mixin.get_pull_request_commits("workspace", "repo", 1)

        assert "Error getting PR commits" in str(exc_info.value)

    def test_empty_pull_requests_response(self, pullrequests_mixin):
        """Test get_all_pull_requests with empty response."""
        pullrequests_mixin.bitbucket.get_pull_requests.return_value = []

        result = pullrequests_mixin.get_all_pull_requests("workspace", "repo")

        assert result == []
        assert isinstance(result, list)

    def test_invalid_state_warning(self, pullrequests_mixin):
        """Test that invalid state triggers warning and defaults to OPEN."""
        pullrequests_mixin.bitbucket.get_pull_requests.return_value = []

        with patch("mcp_atlassian.bitbucket.pullrequests.logger") as mock_logger:
            result = pullrequests_mixin.get_all_pull_requests(
                "workspace", "repo", "INVALID_STATE"
            )

            mock_logger.warning.assert_called_once_with(
                "Invalid PR state 'INVALID_STATE', using 'OPEN' instead"
            )
            pullrequests_mixin.bitbucket.get_pull_requests.assert_called_once_with(
                "workspace", "repo", "OPEN"
            )

    def test_mixin_inheritance(self):
        """Test that PullRequestsMixin properly inherits from BitbucketClient."""
        from mcp_atlassian.bitbucket.client import BitbucketClient

        assert issubclass(PullRequestsMixin, BitbucketClient)

        # Test that mixin can be instantiated (with mocked dependencies)
        with patch("mcp_atlassian.bitbucket.client.Bitbucket"):
            with patch("mcp_atlassian.bitbucket.client.configure_ssl_verification"):
                config = BitbucketConfig(
                    url="https://api.bitbucket.org/2.0",
                    auth_type="basic",
                    username="test@example.com",
                    app_password="password",
                )
                mixin = PullRequestsMixin(config)
                assert hasattr(mixin, "get_all_pull_requests")
                assert hasattr(mixin, "get_pull_request")
                assert hasattr(mixin, "create_pull_request")
                assert hasattr(mixin, "get_pull_request_commits")
                assert hasattr(mixin, "config")  # From parent class
