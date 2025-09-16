"""Tests for the Bitbucket repositories module."""

from unittest.mock import MagicMock, patch

import pytest
from requests.exceptions import HTTPError

from mcp_atlassian.bitbucket.config import BitbucketConfig
from mcp_atlassian.bitbucket.repositories import RepositoriesMixin
from mcp_atlassian.exceptions import MCPAtlassianAuthenticationError
from mcp_atlassian.models.bitbucket.common import BitbucketRepository


class TestRepositoriesMixin:
    """Test cases for RepositoriesMixin class."""

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
    def repositories_mixin(self, config):
        """Create a RepositoriesMixin instance for testing."""
        with patch("mcp_atlassian.bitbucket.client.Bitbucket"):
            with patch("mcp_atlassian.bitbucket.client.configure_ssl_verification"):
                mixin = RepositoriesMixin(config)
                mixin.bitbucket = MagicMock()
                return mixin

    @pytest.fixture
    def sample_repository_data(self):
        """Create sample repository data for testing."""
        return [
            {
                "uuid": "{12345678-1234-1234-1234-123456789abc}",
                "name": "repo1",
                "full_name": "workspace1/repo1",
                "description": "Repository 1",
                "is_private": False,
                "scm": "git",
                "language": "python",
                "size": 1024,
            },
            {
                "uuid": "{87654321-4321-4321-4321-cba987654321}",
                "name": "repo2",
                "full_name": "workspace1/repo2",
                "description": "Repository 2",
                "is_private": True,
                "scm": "git",
                "language": "javascript",
                "size": 2048,
            },
        ]

    @pytest.fixture
    def sample_repository_info(self):
        """Create sample repository info for testing."""
        return {
            "uuid": "{12345678-1234-1234-1234-123456789abc}",
            "name": "test-repo",
            "full_name": "test-workspace/test-repo",
            "description": "Test repository",
            "is_private": False,
            "scm": "git",
            "language": "python",
            "size": 1024,
            "created_on": "2023-01-01T00:00:00Z",
            "updated_on": "2023-01-02T00:00:00Z",
        }

    def test_get_all_repositories_success(
        self, repositories_mixin, sample_repository_data
    ):
        """Test successful retrieval of all repositories."""
        repositories_mixin.bitbucket.get_repositories.return_value = (
            sample_repository_data
        )

        result = repositories_mixin.get_all_repositories("test-workspace")

        assert result == sample_repository_data
        repositories_mixin.bitbucket.get_repositories.assert_called_once_with(
            "test-workspace"
        )

    def test_get_all_repositories_without_workspace(
        self, repositories_mixin, sample_repository_data
    ):
        """Test retrieval of repositories without specifying workspace."""
        repositories_mixin.bitbucket.get_repositories.return_value = (
            sample_repository_data
        )

        result = repositories_mixin.get_all_repositories()

        assert result == sample_repository_data
        repositories_mixin.bitbucket.get_repositories.assert_called_once_with(None)

    def test_get_all_repositories_http_401_error(self, repositories_mixin):
        """Test handling of 401 HTTP error in get_all_repositories."""
        mock_response = MagicMock()
        mock_response.status_code = 401
        http_error = HTTPError()
        http_error.response = mock_response
        repositories_mixin.bitbucket.get_repositories.side_effect = http_error

        with pytest.raises(
            MCPAtlassianAuthenticationError,
            match="Authentication failed for Bitbucket API \\(401\\)",
        ):
            repositories_mixin.get_all_repositories("test-workspace")

    def test_get_all_repositories_http_403_error(self, repositories_mixin):
        """Test handling of 403 HTTP error in get_all_repositories."""
        mock_response = MagicMock()
        mock_response.status_code = 403
        http_error = HTTPError()
        http_error.response = mock_response
        repositories_mixin.bitbucket.get_repositories.side_effect = http_error

        with pytest.raises(
            MCPAtlassianAuthenticationError,
            match="Authentication failed for Bitbucket API \\(403\\)",
        ):
            repositories_mixin.get_all_repositories("test-workspace")

    def test_get_all_repositories_http_500_error(self, repositories_mixin):
        """Test handling of non-auth HTTP errors in get_all_repositories."""
        mock_response = MagicMock()
        mock_response.status_code = 500
        http_error = HTTPError()
        http_error.response = mock_response
        repositories_mixin.bitbucket.get_repositories.side_effect = http_error

        with pytest.raises(HTTPError):
            repositories_mixin.get_all_repositories("test-workspace")

    def test_get_all_repositories_general_exception(self, repositories_mixin):
        """Test handling of general exceptions in get_all_repositories."""
        repositories_mixin.bitbucket.get_repositories.side_effect = Exception(
            "Network error"
        )

        with pytest.raises(
            Exception, match="Error getting repositories: Network error"
        ):
            repositories_mixin.get_all_repositories("test-workspace")

    def test_get_repository_info_success(
        self, repositories_mixin, sample_repository_info
    ):
        """Test successful retrieval of repository info."""
        repositories_mixin.bitbucket.get_repo.return_value = sample_repository_info

        with patch(
            "mcp_atlassian.models.bitbucket.common.BitbucketRepository.from_api_response"
        ) as mock_from_api:
            mock_repo = MagicMock(spec=BitbucketRepository)
            mock_from_api.return_value = mock_repo

            result = repositories_mixin.get_repository_info(
                "test-workspace", "test-repo"
            )

            assert result == mock_repo
            repositories_mixin.bitbucket.get_repo.assert_called_once_with(
                "test-workspace", "test-repo"
            )
            mock_from_api.assert_called_once_with(sample_repository_info)

    def test_get_repository_info_http_401_error(self, repositories_mixin):
        """Test handling of 401 HTTP error in get_repository_info."""
        mock_response = MagicMock()
        mock_response.status_code = 401
        http_error = HTTPError()
        http_error.response = mock_response
        repositories_mixin.bitbucket.get_repo.side_effect = http_error

        with pytest.raises(
            MCPAtlassianAuthenticationError,
            match="Authentication failed for Bitbucket API \\(401\\)",
        ):
            repositories_mixin.get_repository_info("test-workspace", "test-repo")

    def test_get_repository_info_general_exception(self, repositories_mixin):
        """Test handling of general exceptions in get_repository_info."""
        repositories_mixin.bitbucket.get_repo.side_effect = Exception("API error")

        with pytest.raises(Exception, match="Error getting repository info: API error"):
            repositories_mixin.get_repository_info("test-workspace", "test-repo")

    def test_get_file_content_success(self, repositories_mixin):
        """Test successful file content retrieval."""
        expected_content = b"print('Hello, World!')"
        repositories_mixin.bitbucket.get_content_of_file.return_value = expected_content

        result = repositories_mixin.get_file_content(
            "test-workspace", "test-repo", "main.py"
        )

        assert result == expected_content
        repositories_mixin.bitbucket.get_content_of_file.assert_called_once_with(
            "test-workspace", "test-repo", "main.py", "main"
        )

    def test_get_file_content_with_custom_branch(self, repositories_mixin):
        """Test file content retrieval with custom branch."""
        expected_content = b"console.log('Hello, World!');"
        repositories_mixin.bitbucket.get_content_of_file.return_value = expected_content

        result = repositories_mixin.get_file_content(
            "test-workspace", "test-repo", "index.js", "development"
        )

        assert result == expected_content
        repositories_mixin.bitbucket.get_content_of_file.assert_called_once_with(
            "test-workspace", "test-repo", "index.js", "development"
        )

    def test_get_file_content_http_401_error(self, repositories_mixin):
        """Test handling of 401 HTTP error in get_file_content."""
        mock_response = MagicMock()
        mock_response.status_code = 401
        http_error = HTTPError()
        http_error.response = mock_response
        repositories_mixin.bitbucket.get_content_of_file.side_effect = http_error

        with pytest.raises(
            MCPAtlassianAuthenticationError,
            match="Authentication failed for Bitbucket API \\(401\\)",
        ):
            repositories_mixin.get_file_content(
                "test-workspace", "test-repo", "main.py"
            )

    def test_get_file_content_general_exception(self, repositories_mixin):
        """Test handling of general exceptions in get_file_content."""
        repositories_mixin.bitbucket.get_content_of_file.side_effect = Exception(
            "File not found"
        )

        with pytest.raises(
            Exception, match="Error getting file content: File not found"
        ):
            repositories_mixin.get_file_content(
                "test-workspace", "test-repo", "nonexistent.py"
            )

    def test_get_directory_content_success(self, repositories_mixin):
        """Test successful directory content retrieval."""
        expected_content = [
            {"type": "file", "name": "main.py", "path": "main.py"},
            {"type": "file", "name": "requirements.txt", "path": "requirements.txt"},
            {"type": "directory", "name": "src", "path": "src"},
        ]
        repositories_mixin.bitbucket.get_file_list.return_value = expected_content

        result = repositories_mixin.get_directory_content("test-workspace", "test-repo")

        assert result == expected_content
        repositories_mixin.bitbucket.get_file_list.assert_called_once_with(
            "test-workspace", "test-repo", "", "main"
        )

    def test_get_directory_content_with_path_and_branch(self, repositories_mixin):
        """Test directory content retrieval with custom path and branch."""
        expected_content = [
            {"type": "file", "name": "__init__.py", "path": "src/__init__.py"},
            {"type": "file", "name": "utils.py", "path": "src/utils.py"},
        ]
        repositories_mixin.bitbucket.get_file_list.return_value = expected_content

        result = repositories_mixin.get_directory_content(
            "test-workspace", "test-repo", "src", "development"
        )

        assert result == expected_content
        repositories_mixin.bitbucket.get_file_list.assert_called_once_with(
            "test-workspace", "test-repo", "src", "development"
        )

    def test_get_directory_content_http_401_error(self, repositories_mixin):
        """Test handling of 401 HTTP error in get_directory_content."""
        mock_response = MagicMock()
        mock_response.status_code = 401
        http_error = HTTPError()
        http_error.response = mock_response
        repositories_mixin.bitbucket.get_file_list.side_effect = http_error

        with pytest.raises(
            MCPAtlassianAuthenticationError,
            match="Authentication failed for Bitbucket API \\(401\\)",
        ):
            repositories_mixin.get_directory_content("test-workspace", "test-repo")

    def test_get_directory_content_general_exception(self, repositories_mixin):
        """Test handling of general exceptions in get_directory_content."""
        repositories_mixin.bitbucket.get_file_list.side_effect = Exception(
            "Directory not found"
        )

        with pytest.raises(
            Exception, match="Error getting directory content: Directory not found"
        ):
            repositories_mixin.get_directory_content(
                "test-workspace", "test-repo", "nonexistent"
            )

    def test_get_repositories_success(self, repositories_mixin, sample_repository_data):
        """Test successful retrieval of repositories using get_repositories method."""
        repositories_mixin.bitbucket.repo_list.return_value = iter(
            sample_repository_data
        )

        with patch(
            "mcp_atlassian.models.bitbucket.common.BitbucketRepository.from_api_response"
        ) as mock_from_api:
            mock_repos = []
            for _ in sample_repository_data:
                mock_repo = MagicMock(spec=BitbucketRepository)
                mock_repos.append(mock_repo)
            mock_from_api.side_effect = mock_repos

            result = repositories_mixin.get_repositories("test-workspace")

            assert len(result) == 2
            assert all(isinstance(repo, MagicMock) for repo in result)
            repositories_mixin.bitbucket.repo_list.assert_called_once_with(
                "test-workspace"
            )
            assert mock_from_api.call_count == 2

    def test_get_repositories_http_401_error(self, repositories_mixin):
        """Test handling of 401 HTTP error in get_repositories."""
        mock_response = MagicMock()
        mock_response.status_code = 401
        http_error = HTTPError()
        http_error.response = mock_response
        repositories_mixin.bitbucket.repo_list.side_effect = http_error

        with pytest.raises(
            MCPAtlassianAuthenticationError,
            match="Authentication failed for Bitbucket API \\(401\\)",
        ):
            repositories_mixin.get_repositories("test-workspace")

    def test_get_repositories_empty_result(self, repositories_mixin):
        """Test handling of empty repository list."""
        repositories_mixin.bitbucket.repo_list.return_value = iter([])

        result = repositories_mixin.get_repositories("test-workspace")

        assert result == []
        assert isinstance(result, list)

    def test_error_logging_consistency(self, repositories_mixin):
        """Test that error logging is consistent across methods."""
        mock_response = MagicMock()
        mock_response.status_code = 500
        http_error = HTTPError()
        http_error.response = mock_response

        # Test that all methods log HTTP errors consistently
        repositories_mixin.bitbucket.get_repositories.side_effect = http_error
        repositories_mixin.bitbucket.get_repo.side_effect = http_error
        repositories_mixin.bitbucket.get_content_of_file.side_effect = http_error
        repositories_mixin.bitbucket.get_file_list.side_effect = http_error

        with patch("mcp_atlassian.bitbucket.repositories.logger") as mock_logger:
            # Test each method logs errors
            for method, args in [
                (repositories_mixin.get_all_repositories, ("workspace",)),
                (repositories_mixin.get_repository_info, ("workspace", "repo")),
                (repositories_mixin.get_file_content, ("workspace", "repo", "file.py")),
                (repositories_mixin.get_directory_content, ("workspace", "repo")),
            ]:
                try:
                    method(*args)
                except HTTPError:
                    pass  # Expected

                # Check that error was logged
                mock_logger.error.assert_called()
                mock_logger.reset_mock()

    def test_mixin_inheritance(self):
        """Test that RepositoriesMixin properly inherits from BitbucketClient."""
        from mcp_atlassian.bitbucket.client import BitbucketClient

        assert issubclass(RepositoriesMixin, BitbucketClient)

        # Test that mixin can be instantiated (with mocked dependencies)
        with patch("mcp_atlassian.bitbucket.client.Bitbucket"):
            with patch("mcp_atlassian.bitbucket.client.configure_ssl_verification"):
                config = BitbucketConfig(
                    url="https://api.bitbucket.org/2.0",
                    auth_type="basic",
                    username="test@example.com",
                    app_password="password",
                )
                mixin = RepositoriesMixin(config)
                assert hasattr(mixin, "get_all_repositories")
                assert hasattr(mixin, "get_repository_info")
                assert hasattr(mixin, "get_file_content")
                assert hasattr(mixin, "get_directory_content")
                assert hasattr(mixin, "get_repositories")
                assert hasattr(mixin, "config")  # From parent class
