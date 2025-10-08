"""Tests for the Bitbucket branches module."""

from unittest.mock import MagicMock, Mock, patch

import pytest
from requests.exceptions import HTTPError

from mcp_atlassian.bitbucket.branches import BranchesMixin
from mcp_atlassian.bitbucket.config import BitbucketConfig
from mcp_atlassian.exceptions import MCPAtlassianAuthenticationError
from mcp_atlassian.models.bitbucket.common import BitbucketBranch, BitbucketCommit


class TestBranchesMixin:
    """Test cases for BranchesMixin class."""

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
    def branches_mixin(self, config):
        """Create a BranchesMixin instance for testing."""
        with patch("mcp_atlassian.bitbucket.client.Bitbucket"):
            with patch("mcp_atlassian.bitbucket.client.configure_ssl_verification"):
                mixin = BranchesMixin(config)
                mixin.bitbucket = MagicMock()
                return mixin

    @pytest.fixture
    def sample_branch_data(self):
        """Create sample branch data for testing."""
        return [
            {
                "name": "main",
                "target": {
                    "hash": "abc123",
                    "author": {"raw": "John Doe <john@example.com>"},
                    "message": "Initial commit",
                    "date": "2023-01-01T00:00:00Z",
                },
                "type": "branch",
            },
            {
                "name": "develop",
                "target": {
                    "hash": "def456",
                    "author": {"raw": "Jane Doe <jane@example.com>"},
                    "message": "Development branch",
                    "date": "2023-01-02T00:00:00Z",
                },
                "type": "branch",
            },
            {
                "name": "feature/new-feature",
                "target": {
                    "hash": "ghi789",
                    "author": {"raw": "Bob Smith <bob@example.com>"},
                    "message": "Add new feature",
                    "date": "2023-01-03T00:00:00Z",
                },
                "type": "branch",
            },
        ]

    @pytest.fixture
    def sample_commit_data(self):
        """Create sample commit data for testing."""
        return [
            {
                "hash": "abc123",
                "author": {"raw": "John Doe <john@example.com>"},
                "message": "Initial commit",
                "date": "2023-01-01T00:00:00Z",
                "type": "commit",
            },
            {
                "hash": "def456",
                "author": {"raw": "Jane Doe <jane@example.com>"},
                "message": "Add README",
                "date": "2023-01-02T00:00:00Z",
                "type": "commit",
            },
        ]

    def test_get_all_branches_success(self, branches_mixin, sample_branch_data):
        """Test successful retrieval of all branches."""
        branches_mixin.bitbucket.get_branches.return_value = sample_branch_data

        with patch(
            "mcp_atlassian.models.bitbucket.common.BitbucketBranch.from_api_response"
        ) as mock_from_api:
            mock_branches = []
            for branch_data in sample_branch_data:
                mock_branch = MagicMock(spec=BitbucketBranch)
                mock_branch.name = branch_data["name"]
                mock_branches.append(mock_branch)
            mock_from_api.side_effect = mock_branches

            result = branches_mixin.get_all_branches("workspace", "repo")

            assert len(result) == 3
            branches_mixin.bitbucket.get_branches.assert_called_once_with(
                "workspace", "repo"
            )

    def test_get_all_branches_authentication_error_401(self, branches_mixin):
        """Test authentication error (401) handling."""
        mock_response = Mock()
        mock_response.status_code = 401
        http_error = HTTPError(response=mock_response)
        branches_mixin.bitbucket.get_branches.side_effect = http_error

        with pytest.raises(MCPAtlassianAuthenticationError):
            branches_mixin.get_all_branches("workspace", "repo")

    def test_get_all_branches_authentication_error_403(self, branches_mixin):
        """Test authentication error (403) handling."""
        mock_response = Mock()
        mock_response.status_code = 403
        http_error = HTTPError(response=mock_response)
        branches_mixin.bitbucket.get_branches.side_effect = http_error

        with pytest.raises(MCPAtlassianAuthenticationError):
            branches_mixin.get_all_branches("workspace", "repo")

    def test_get_all_branches_http_error_other(self, branches_mixin):
        """Test other HTTP error handling."""
        mock_response = Mock()
        mock_response.status_code = 500
        http_error = HTTPError(response=mock_response)
        branches_mixin.bitbucket.get_branches.side_effect = http_error

        with pytest.raises(HTTPError):
            branches_mixin.get_all_branches("workspace", "repo")

    def test_get_all_branches_general_exception(self, branches_mixin):
        """Test general exception handling."""
        branches_mixin.bitbucket.get_branches.side_effect = Exception("API error")

        with pytest.raises(Exception) as exc_info:
            branches_mixin.get_all_branches("workspace", "repo")

        assert "Error getting branches" in str(exc_info.value)

    def test_get_default_branch_success_with_main_branch(self, branches_mixin):
        """Test getting default branch when main branch exists."""
        mock_response = {"name": "main"}
        branches_mixin.bitbucket.get_default_branch.return_value = mock_response

        with patch(
            "mcp_atlassian.models.bitbucket.common.BitbucketBranch.from_api_response"
        ) as mock_from_api:
            mock_branch = MagicMock(spec=BitbucketBranch)
            mock_branch.name = "main"
            mock_from_api.return_value = mock_branch

            result = branches_mixin.get_default_branch("workspace", "repo")

            assert result is not None
            assert result.name == "main"

    def test_get_default_branch_fallback_to_common_names(
        self, branches_mixin, sample_branch_data
    ):
        """Test fallback to common default branch names when API fails."""
        # First call fails, second call succeeds with branches
        http_error = HTTPError()
        branches_mixin.bitbucket.get_default_branch.side_effect = http_error
        branches_mixin.bitbucket.get_branches.return_value = sample_branch_data

        with patch(
            "mcp_atlassian.models.bitbucket.common.BitbucketBranch.from_api_response"
        ) as mock_from_api:
            mock_branches = []
            for branch_data in sample_branch_data:
                mock_branch = MagicMock(spec=BitbucketBranch)
                mock_branch.name = branch_data["name"]
                mock_branches.append(mock_branch)
            mock_from_api.side_effect = mock_branches

            result = branches_mixin.get_default_branch("workspace", "repo")

            assert result is not None
            assert (
                result.name == "develop"
            )  # Should find "develop" from DEFAULT_BRANCH_NAMES

    def test_get_default_branch_fallback_auth_error_propagation(self, branches_mixin):
        """Test that auth errors are propagated during fallback."""
        mock_response = Mock()
        mock_response.status_code = 401
        http_error = HTTPError(response=mock_response)
        branches_mixin.bitbucket.get_default_branch.side_effect = http_error

        with pytest.raises(MCPAtlassianAuthenticationError):
            branches_mixin.get_default_branch("workspace", "repo")

    def test_get_commits_success(self, branches_mixin, sample_commit_data):
        """Test successful retrieval of branch commits."""
        branches_mixin.bitbucket.get_commits.return_value = sample_commit_data

        with patch(
            "mcp_atlassian.models.bitbucket.common.BitbucketCommit.from_api_response"
        ) as mock_from_api:
            mock_commits = []
            for commit_data in sample_commit_data:
                mock_commit = MagicMock(spec=BitbucketCommit)
                mock_commit.hash = commit_data["hash"]
                mock_commits.append(mock_commit)
            mock_from_api.side_effect = mock_commits

            result = branches_mixin.get_commits("workspace", "repo", limit=25)

            assert len(result) == 2
            branches_mixin.bitbucket.get_commits.assert_called_once_with(
                "workspace", "repo", limit=25, until=None, since=None
            )

    def test_get_commits_authentication_error(self, branches_mixin):
        """Test authentication error in get_commits."""
        mock_response = Mock()
        mock_response.status_code = 401
        http_error = HTTPError(response=mock_response)
        branches_mixin.bitbucket.get_commits.side_effect = http_error

        with pytest.raises(MCPAtlassianAuthenticationError):
            branches_mixin.get_commits("workspace", "repo", "main")

    def test_get_commits_general_exception(self, branches_mixin):
        """Test general exception in get_commits."""
        branches_mixin.bitbucket.get_commits.side_effect = Exception("API error")

        with pytest.raises(Exception) as exc_info:
            branches_mixin.get_commits("workspace", "repo", "main")

        assert "Error getting commits" in str(exc_info.value)

    def test_get_commit_changes_success(self, branches_mixin):
        """Test successful retrieval of commit changes."""
        changes_data = {
            "values": [
                {
                    "type": "modified",
                    "old": {"path": "file1.py"},
                    "new": {"path": "file1.py"},
                }
            ]
        }
        branches_mixin.bitbucket.get_commit_changes.return_value = changes_data

        with patch(
            "mcp_atlassian.models.bitbucket.common.CommitChanges.from_api_response"
        ) as mock_from_api:
            mock_changes = MagicMock()
            mock_changes.files = [{"path": "file1.py", "type": "modified"}]
            mock_from_api.return_value = mock_changes

            result = branches_mixin.get_commit_changes("workspace", "repo", "abc123")

            assert result is not None
            assert result.files == [{"path": "file1.py", "type": "modified"}]

    def test_get_commit_changes_authentication_error(self, branches_mixin):
        """Test authentication error in get_commit_changes."""
        mock_response = Mock()
        mock_response.status_code = 403
        http_error = HTTPError(response=mock_response)
        branches_mixin.bitbucket.get_commit_changes.side_effect = http_error

        with pytest.raises(MCPAtlassianAuthenticationError):
            branches_mixin.get_commit_changes("workspace", "repo", "abc123")

    def test_get_commit_changes_general_exception(self, branches_mixin):
        """Test general exception in get_commit_changes."""
        branches_mixin.bitbucket.get_commit_changes.side_effect = Exception("API error")

        with pytest.raises(Exception) as exc_info:
            branches_mixin.get_commit_changes("workspace", "repo", "abc123")

        assert "Error getting commit changes" in str(exc_info.value)

    def test_get_all_branches_empty_response(self, branches_mixin):
        """Test get_all_branches with empty response."""
        branches_mixin.bitbucket.get_branches.return_value = []

        result = branches_mixin.get_all_branches("workspace", "repo")

        assert result == []
        assert isinstance(result, list)

    def test_get_commits_empty_response(self, branches_mixin):
        """Test get_commits with empty response."""
        branches_mixin.bitbucket.get_commits.return_value = []

        result = branches_mixin.get_commits("workspace", "repo")

        assert result == []
        assert isinstance(result, list)

    def test_mixin_inheritance(self):
        """Test that BranchesMixin properly inherits from BitbucketClient."""
        from mcp_atlassian.bitbucket.client import BitbucketClient

        assert issubclass(BranchesMixin, BitbucketClient)

        # Test that mixin can be instantiated (with mocked dependencies)
        with patch("mcp_atlassian.bitbucket.client.Bitbucket"):
            with patch("mcp_atlassian.bitbucket.client.configure_ssl_verification"):
                config = BitbucketConfig(
                    url="https://api.bitbucket.org/2.0",
                    auth_type="basic",
                    username="test@example.com",
                    app_password="password",
                )
                mixin = BranchesMixin(config)
                assert hasattr(mixin, "get_all_branches")
                assert hasattr(mixin, "get_branches")
                assert hasattr(mixin, "get_default_branch")
                assert hasattr(mixin, "get_commits")
                assert hasattr(mixin, "config")  # From parent class

    def test_get_branches_success(self, branches_mixin, sample_branch_data):
        """Test successful retrieval of branches using get_branches."""
        branches_mixin.bitbucket.get_branches.return_value = sample_branch_data
        with patch(
            "mcp_atlassian.models.bitbucket.common.BitbucketBranch.from_api_response"
        ) as mock_from_api:
            mock_branches = []
            for branch_data in sample_branch_data:
                mock_branch = MagicMock(spec=BitbucketBranch)
                mock_branch.name = branch_data["name"]
                mock_branches.append(mock_branch)
            mock_from_api.side_effect = mock_branches
            result = branches_mixin.get_branches("workspace", "repo")
            assert len(result) == 3
            branches_mixin.bitbucket.get_branches.assert_called_once()

    def test_get_branches_authentication_error_401(self, branches_mixin):
        """Test authentication error (401) in get_branches."""
        mock_response = Mock()
        mock_response.status_code = 401
        http_error = HTTPError(response=mock_response)
        branches_mixin.bitbucket.get_branches.side_effect = http_error
        with pytest.raises(MCPAtlassianAuthenticationError):
            branches_mixin.get_branches("workspace", "repo")

    def test_get_branches_authentication_error_403(self, branches_mixin):
        """Test authentication error (403) in get_branches."""
        mock_response = Mock()
        mock_response.status_code = 403
        http_error = HTTPError(response=mock_response)
        branches_mixin.bitbucket.get_branches.side_effect = http_error
        with pytest.raises(MCPAtlassianAuthenticationError):
            branches_mixin.get_branches("workspace", "repo")

    def test_get_branches_http_error_other(self, branches_mixin):
        """Test other HTTP error in get_branches."""
        mock_response = Mock()
        mock_response.status_code = 500
        http_error = HTTPError(response=mock_response)
        branches_mixin.bitbucket.get_branches.side_effect = http_error
        with pytest.raises(HTTPError):
            branches_mixin.get_branches("workspace", "repo")

    def test_get_branches_general_exception(self, branches_mixin):
        """Test general exception in get_branches."""
        branches_mixin.bitbucket.get_branches.side_effect = Exception("API error")
        with pytest.raises(Exception) as exc_info:
            branches_mixin.get_branches("workspace", "repo")
        assert "Error getting branches" in str(exc_info.value)

    def test_get_branches_empty_response(self, branches_mixin):
        """Test get_branches with empty response."""
        branches_mixin.bitbucket.get_branches.return_value = []
        result = branches_mixin.get_branches("workspace", "repo")
        assert result == []
        assert isinstance(result, list)

    def test_create_branch_success_minimal(self, branches_mixin):
        """Test successful branch creation with minimal branch_data."""
        branch_data = {"name": "feature/test"}
        branches_mixin.bitbucket.create_branch.return_value = {
            "name": "feature/test",
            "start_point": "main",
        }
        result = branches_mixin.create_branch("workspace", "repo", branch_data)
        assert result["name"] == "feature/test"
        assert result["start_point"] == "main"
        branches_mixin.bitbucket.create_branch.assert_called_once_with(
            "workspace", "repo", "feature/test", "main"
        )

    def test_create_branch_success_full(self, branches_mixin):
        """Test successful branch creation with full branch_data including target branch name."""
        branch_data = {
            "name": "feature/test",
            "target": {"branch": {"name": "develop"}},
        }
        branches_mixin.bitbucket.create_branch.return_value = {
            "name": "feature/test",
            "start_point": "develop",
        }
        result = branches_mixin.create_branch("workspace", "repo", branch_data)
        assert result["name"] == "feature/test"
        assert result["start_point"] == "develop"
        branches_mixin.bitbucket.create_branch.assert_called_once_with(
            "workspace", "repo", "feature/test", "develop"
        )

    def test_create_branch_authentication_error_401(self, branches_mixin):
        """Test authentication error (401) in create_branch."""
        mock_response = Mock()
        mock_response.status_code = 401
        http_error = HTTPError(response=mock_response)
        branches_mixin.bitbucket.create_branch.side_effect = http_error
        branch_data = {"name": "feature/test"}
        with pytest.raises(MCPAtlassianAuthenticationError):
            branches_mixin.create_branch("workspace", "repo", branch_data)

    def test_create_branch_authentication_error_403(self, branches_mixin):
        """Test authentication error (403) in create_branch."""
        mock_response = Mock()
        mock_response.status_code = 403
        http_error = HTTPError(response=mock_response)
        branches_mixin.bitbucket.create_branch.side_effect = http_error
        branch_data = {"name": "feature/test"}
        with pytest.raises(MCPAtlassianAuthenticationError):
            branches_mixin.create_branch("workspace", "repo", branch_data)

    def test_create_branch_http_error_other(self, branches_mixin):
        """Test other HTTP error in create_branch."""
        mock_response = Mock()
        mock_response.status_code = 500
        http_error = HTTPError(response=mock_response)
        branches_mixin.bitbucket.create_branch.side_effect = http_error
        branch_data = {"name": "feature/test"}
        with pytest.raises(HTTPError):
            branches_mixin.create_branch("workspace", "repo", branch_data)

    def test_create_branch_general_exception(self, branches_mixin):
        """Test general exception in create_branch."""
        branches_mixin.bitbucket.create_branch.side_effect = Exception("API error")
        branch_data = {"name": "feature/test"}
        with pytest.raises(Exception) as exc_info:
            branches_mixin.create_branch("workspace", "repo", branch_data)
        assert "Error creating branch" in str(exc_info.value)

    def test_create_branch_missing_name(self, branches_mixin):
        """Test create_branch with missing name in branch_data."""
        branch_data = {"target": {"branch": {"name": "main"}}}
        branches_mixin.bitbucket.create_branch.return_value = {
            "name": "",
            "start_point": "main",
        }
        result = branches_mixin.create_branch("workspace", "repo", branch_data)
        assert result["name"] == ""
        assert result["start_point"] == "main"

    def test_create_branch_malformed_target(self, branches_mixin):
        """Test create_branch with malformed target in branch_data."""
        branch_data = {"name": "feature/test", "target": {"branch": "not_a_dict"}}
        branches_mixin.bitbucket.create_branch.return_value = {
            "name": "feature/test",
            "start_point": "main",
        }
        result = branches_mixin.create_branch("workspace", "repo", branch_data)
        assert result["name"] == "feature/test"
        assert result["start_point"] == "main"
