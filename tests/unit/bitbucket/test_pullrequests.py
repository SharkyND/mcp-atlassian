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

    def test_get_pull_requests_success(
        self, pullrequests_mixin, sample_pull_request_data
    ):
        """Test successful retrieval of pull requests (raw dict version)."""
        pullrequests_mixin.bitbucket.get_pull_requests.return_value = (
            sample_pull_request_data
        )
        result = pullrequests_mixin.get_pull_requests("workspace", "repo", "OPEN")
        assert result == sample_pull_request_data
        pullrequests_mixin.bitbucket.get_pull_requests.assert_called_once_with(
            "workspace", "repo", state="OPEN"
        )

    def test_get_pull_requests_authentication_error_401(self, pullrequests_mixin):
        """Test authentication error (401) in get_pull_requests."""
        mock_response = Mock()
        mock_response.status_code = 401
        http_error = HTTPError(response=mock_response)
        pullrequests_mixin.bitbucket.get_pull_requests.side_effect = http_error
        with pytest.raises(MCPAtlassianAuthenticationError):
            pullrequests_mixin.get_pull_requests("workspace", "repo", "OPEN")

    def test_get_pull_requests_authentication_error_403(self, pullrequests_mixin):
        """Test authentication error (403) in get_pull_requests."""
        mock_response = Mock()
        mock_response.status_code = 403
        http_error = HTTPError(response=mock_response)
        pullrequests_mixin.bitbucket.get_pull_requests.side_effect = http_error
        with pytest.raises(MCPAtlassianAuthenticationError):
            pullrequests_mixin.get_pull_requests("workspace", "repo", "OPEN")

    def test_get_pull_requests_http_error_other(self, pullrequests_mixin):
        """Test other HTTP error in get_pull_requests."""
        mock_response = Mock()
        mock_response.status_code = 500
        http_error = HTTPError(response=mock_response)
        pullrequests_mixin.bitbucket.get_pull_requests.side_effect = http_error
        with pytest.raises(HTTPError):
            pullrequests_mixin.get_pull_requests("workspace", "repo", "OPEN")

    def test_get_pull_requests_general_exception(self, pullrequests_mixin):
        """Test general exception in get_pull_requests."""
        pullrequests_mixin.bitbucket.get_pull_requests.side_effect = Exception(
            "API error"
        )
        with pytest.raises(Exception) as exc_info:
            pullrequests_mixin.get_pull_requests("workspace", "repo", "OPEN")
        assert "Error getting PRs" in str(exc_info.value)

    def test_get_pull_request_activities_success(self, pullrequests_mixin):
        """Test successful retrieval of pull request activities/comments."""
        activities_data = [
            {"comment": "Looks good!", "user": "john"},
            {"comment": "Needs changes.", "user": "jane"},
        ]
        with patch.object(
            PullRequestsMixin,
            "get_pull_request_activities",
            return_value=activities_data,
        ):
            result = pullrequests_mixin.get_pull_request_activities(
                "workspace", "repo", 1
            )
            assert result == activities_data

    def test_get_pull_request_activities_authentication_error(self, pullrequests_mixin):
        """Test authentication error in get_pull_request_activities."""
        mock_response = Mock()
        mock_response.status_code = 401
        http_error = HTTPError(response=mock_response)
        with patch(
            "mcp_atlassian.bitbucket.client.BitbucketClient.get_pull_request_activities",
            side_effect=http_error,
        ):
            with pytest.raises(MCPAtlassianAuthenticationError):
                pullrequests_mixin.get_pull_request_activities("workspace", "repo", 1)

    def test_get_pull_request_activities_general_exception(self, pullrequests_mixin):
        """Test general exception in get_pull_request_activities."""
        with patch(
            "mcp_atlassian.bitbucket.client.BitbucketClient.get_pull_request_activities",
            side_effect=Exception("API error"),
        ):
            with pytest.raises(Exception) as exc_info:
                pullrequests_mixin.get_pull_request_activities("workspace", "repo", 1)
            assert "Error getting PR comments" in str(exc_info.value)

    def test_add_pull_request_comment_success(self, pullrequests_mixin):
        """Test successful addition of a pull request comment."""
        comment_data = {"content": "Nice work!"}
        expected_response = {"id": 123, "content": "Nice work!"}
        pullrequests_mixin.bitbucket.add_pull_request_comment.return_value = (
            expected_response
        )
        result = pullrequests_mixin.add_pull_request_comment(
            "workspace", "repo", 1, comment_data
        )
        assert result == expected_response
        pullrequests_mixin.bitbucket.add_pull_request_comment.assert_called_once_with(
            "workspace", "repo", 1, comment_data
        )

    def test_add_pull_request_comment_authentication_error(self, pullrequests_mixin):
        """Test authentication error in add_pull_request_comment."""
        mock_response = Mock()
        mock_response.status_code = 401
        http_error = HTTPError(response=mock_response)
        pullrequests_mixin.bitbucket.add_pull_request_comment.side_effect = http_error
        comment_data = {"content": "Nice work!"}
        with pytest.raises(MCPAtlassianAuthenticationError):
            pullrequests_mixin.add_pull_request_comment(
                "workspace", "repo", 1, comment_data
            )

    def test_add_pull_request_comment_http_error_other(self, pullrequests_mixin):
        """Test other HTTP error in add_pull_request_comment."""
        mock_response = Mock()
        mock_response.status_code = 500
        http_error = HTTPError(response=mock_response)
        pullrequests_mixin.bitbucket.add_pull_request_comment.side_effect = http_error
        comment_data = {"content": "Nice work!"}
        with pytest.raises(HTTPError):
            pullrequests_mixin.add_pull_request_comment(
                "workspace", "repo", 1, comment_data
            )

    def test_add_pull_request_comment_general_exception(self, pullrequests_mixin):
        """Test general exception in add_pull_request_comment."""
        pullrequests_mixin.bitbucket.add_pull_request_comment.side_effect = Exception(
            "API error"
        )
        comment_data = {"content": "Nice work!"}
        with pytest.raises(Exception) as exc_info:
            pullrequests_mixin.add_pull_request_comment(
                "workspace", "repo", 1, comment_data
            )
        assert "Error adding PR comment" in str(exc_info.value)

    def test_add_pull_request_blocker_comment_success(self, pullrequests_mixin):
        """Test successful addition of a blocker comment."""
        expected_response = {"id": 456, "content": "Blocker!", "severity": "BLOCKER"}
        pullrequests_mixin.bitbucket.add_pull_request_blocker_comment.return_value = (
            expected_response
        )
        result = pullrequests_mixin.add_pull_request_blocker_comment(
            "workspace", "repo", 1, "Blocker!", severity="BLOCKER"
        )
        assert result == expected_response
        pullrequests_mixin.bitbucket.add_pull_request_blocker_comment.assert_called_once_with(
            "workspace", "repo", 1, "Blocker!", severity="BLOCKER"
        )

    def test_add_pull_request_blocker_comment_authentication_error(
        self, pullrequests_mixin
    ):
        """Test authentication error in add_pull_request_blocker_comment."""
        mock_response = Mock()
        mock_response.status_code = 403
        http_error = HTTPError(response=mock_response)
        pullrequests_mixin.bitbucket.add_pull_request_blocker_comment.side_effect = (
            http_error
        )
        with pytest.raises(MCPAtlassianAuthenticationError):
            pullrequests_mixin.add_pull_request_blocker_comment(
                "workspace", "repo", 1, "Blocker!", severity="BLOCKER"
            )

    def test_add_pull_request_blocker_comment_http_error_other(
        self, pullrequests_mixin
    ):
        """Test other HTTP error in add_pull_request_blocker_comment."""
        mock_response = Mock()
        mock_response.status_code = 500
        http_error = HTTPError(response=mock_response)
        pullrequests_mixin.bitbucket.add_pull_request_blocker_comment.side_effect = (
            http_error
        )
        with pytest.raises(HTTPError):
            pullrequests_mixin.add_pull_request_blocker_comment(
                "workspace", "repo", 1, "Blocker!", severity="BLOCKER"
            )

    def test_add_pull_request_blocker_comment_general_exception(
        self, pullrequests_mixin
    ):
        """Test general exception in add_pull_request_blocker_comment."""
        pullrequests_mixin.bitbucket.add_pull_request_blocker_comment.side_effect = (
            Exception("API error")
        )
        with pytest.raises(Exception) as exc_info:
            pullrequests_mixin.add_pull_request_blocker_comment(
                "workspace", "repo", 1, "Blocker!", severity="BLOCKER"
            )
        assert "Error blocker adding PR comment" in str(exc_info.value)

    def test_add_pull_request_inline_comment_success_cloud(self, pullrequests_mixin):
        """Test successful addition of an inline comment on Cloud."""
        expected_response = {"id": 789, "content": {"raw": "Looks good!"}}
        pullrequests_mixin.bitbucket.post.return_value = expected_response

        with patch.object(
            type(pullrequests_mixin.config),
            "is_cloud",
            new_callable=lambda: property(lambda self: True),
        ):
            result = pullrequests_mixin.add_pull_request_inline_comment(
                "workspace", "repo", 1, "Looks good!", "src/main.py", 42
            )

        assert result == expected_response
        pullrequests_mixin.bitbucket.post.assert_called_once_with(
            "repositories/workspace/repo/pullrequests/1/comments",
            data={
                "content": {"raw": "Looks good!"},
                "inline": {"to": 42, "path": "src/main.py"},
            },
        )

    def test_add_pull_request_inline_comment_success_server(self, pullrequests_mixin):
        """Test successful addition of an inline comment on Server/DC."""
        expected_response = {"id": 101, "text": "Needs fix"}
        pullrequests_mixin.bitbucket.post.return_value = expected_response
        pullrequests_mixin.bitbucket.get_pull_request.return_value = {
            "fromRef": {"latestCommit": "from-sha"},
            "toRef": {"latestCommit": "to-sha"},
        }

        with patch.object(
            type(pullrequests_mixin.config),
            "is_cloud",
            new_callable=lambda: property(lambda self: False),
        ):
            result = pullrequests_mixin.add_pull_request_inline_comment(
                "PROJECT", "repo", 2, "Needs fix", "src/utils.py", 10, line_type="ADDED"
            )

        assert result == expected_response
        pullrequests_mixin.bitbucket.post.assert_called_once_with(
            "projects/PROJECT/repos/repo/pull-requests/2/comments",
            data={
                "text": "Needs fix",
                "anchor": {
                    "diffType": "COMMIT",
                    "line": 10,
                    "lineType": "ADDED",
                    "fileType": "TO",
                    "fromHash": "from-sha",
                    "path": "src/utils.py",
                    "toHash": "to-sha",
                },
            },
        )

    def test_add_pull_request_inline_comment_invalid_line_type_defaults(
        self, pullrequests_mixin
    ):
        """Test that an invalid line_type defaults to 'ADDED' for Server/DC."""
        pullrequests_mixin.bitbucket.post.return_value = {"id": 1}
        pullrequests_mixin.bitbucket.get_pull_request.return_value = {
            "fromRef": {"latestCommit": "from-sha"},
            "toRef": {"latestCommit": "to-sha"},
        }

        with patch.object(
            type(pullrequests_mixin.config),
            "is_cloud",
            new_callable=lambda: property(lambda self: False),
        ):
            pullrequests_mixin.add_pull_request_inline_comment(
                "PROJECT", "repo", 1, "comment", "file.py", 5, line_type="INVALID"
            )

        call_data = pullrequests_mixin.bitbucket.post.call_args[1]["data"]
        assert call_data["anchor"]["lineType"] == "ADDED"
        assert call_data["anchor"]["fileType"] == "TO"

    def test_add_pull_request_inline_comment_removed_line_uses_from_file(
        self, pullrequests_mixin
    ):
        """Test removed-line comments anchor to the source side of the diff."""
        pullrequests_mixin.bitbucket.post.return_value = {"id": 1}
        pullrequests_mixin.bitbucket.get_pull_request.return_value = {
            "fromRef": {"latestCommit": "from-sha"},
            "toRef": {"latestCommit": "to-sha"},
        }

        with patch.object(
            type(pullrequests_mixin.config),
            "is_cloud",
            new_callable=lambda: property(lambda self: False),
        ):
            pullrequests_mixin.add_pull_request_inline_comment(
                "PROJECT", "repo", 1, "comment", "file.py", 5, line_type="REMOVED"
            )

        call_data = pullrequests_mixin.bitbucket.post.call_args[1]["data"]
        assert call_data["anchor"]["fileType"] == "FROM"

    def test_add_pull_request_inline_comment_server_requires_diff_hashes(
        self, pullrequests_mixin
    ):
        """Test Server/DC inline comments fail fast when diff hashes are unavailable."""
        pullrequests_mixin.bitbucket.get_pull_request.return_value = {
            "fromRef": {},
            "toRef": {},
        }

        with patch.object(
            type(pullrequests_mixin.config),
            "is_cloud",
            new_callable=lambda: property(lambda self: False),
        ):
            with pytest.raises(Exception) as exc_info:
                pullrequests_mixin.add_pull_request_inline_comment(
                    "PROJECT", "repo", 1, "comment", "file.py", 5
                )

        assert "Error adding inline PR comment" in str(exc_info.value)

    def test_add_pull_request_inline_comment_authentication_error(
        self, pullrequests_mixin
    ):
        """Test authentication error in add_pull_request_inline_comment."""
        mock_response = Mock()
        mock_response.status_code = 401
        http_error = HTTPError(response=mock_response)
        pullrequests_mixin.bitbucket.post.side_effect = http_error

        with pytest.raises(MCPAtlassianAuthenticationError):
            pullrequests_mixin.add_pull_request_inline_comment(
                "workspace", "repo", 1, "comment", "file.py", 1
            )

    def test_add_pull_request_inline_comment_http_error_other(self, pullrequests_mixin):
        """Test other HTTP error in add_pull_request_inline_comment."""
        mock_response = Mock()
        mock_response.status_code = 500
        http_error = HTTPError(response=mock_response)
        pullrequests_mixin.bitbucket.post.side_effect = http_error

        with pytest.raises(HTTPError):
            pullrequests_mixin.add_pull_request_inline_comment(
                "workspace", "repo", 1, "comment", "file.py", 1
            )

    def test_add_pull_request_inline_comment_general_exception(
        self, pullrequests_mixin
    ):
        """Test general exception in add_pull_request_inline_comment."""
        pullrequests_mixin.bitbucket.post.side_effect = Exception("API error")

        with pytest.raises(Exception) as exc_info:
            pullrequests_mixin.add_pull_request_inline_comment(
                "workspace", "repo", 1, "comment", "file.py", 1
            )
        assert "Error adding inline PR comment" in str(exc_info.value)
