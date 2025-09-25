"""Tests for the Bitbucket workspaces module."""

from unittest.mock import MagicMock, patch

import pytest
from requests.exceptions import HTTPError

from mcp_atlassian.bitbucket.config import BitbucketConfig
from mcp_atlassian.bitbucket.workspaces import WorkspacesMixin
from mcp_atlassian.exceptions import MCPAtlassianAuthenticationError
from mcp_atlassian.models.bitbucket.common import BitbucketWorkspace


class TestWorkspacesMixin:
    """Test cases for WorkspacesMixin class."""

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
    def config_with_filter(self):
        """Create a configuration with workspace filter."""
        return BitbucketConfig(
            url="https://api.bitbucket.org/2.0",
            auth_type="basic",
            username="test@example.com",
            app_password="app_password",
            workspaces_filter="workspace1,workspace2",
        )

    @pytest.fixture
    def workspaces_mixin(self, config):
        """Create a WorkspacesMixin instance for testing."""
        with patch("mcp_atlassian.bitbucket.client.Bitbucket"):
            with patch("mcp_atlassian.bitbucket.client.configure_ssl_verification"):
                mixin = WorkspacesMixin(config)
                mixin.bitbucket = MagicMock()
                return mixin

    @pytest.fixture
    def workspaces_mixin_with_filter(self, config_with_filter):
        """Create a WorkspacesMixin instance with filter for testing."""
        with patch("mcp_atlassian.bitbucket.client.Bitbucket"):
            with patch("mcp_atlassian.bitbucket.client.configure_ssl_verification"):
                mixin = WorkspacesMixin(config_with_filter)
                mixin.bitbucket = MagicMock()
                return mixin

    @pytest.fixture
    def sample_workspace_data(self):
        """Create sample workspace data for testing."""
        return [
            {
                "uuid": "{12345678-1234-1234-1234-123456789abc}",
                "name": "workspace1",
                "slug": "workspace1-slug",
                "display_name": "Workspace 1",
                "type": "workspace",
            },
            {
                "uuid": "{87654321-4321-4321-4321-cba987654321}",
                "name": "workspace2",
                "slug": "workspace2-slug",
                "display_name": "Workspace 2",
                "type": "workspace",
            },
            {
                "uuid": "{11111111-1111-1111-1111-111111111111}",
                "name": "workspace3",
                "slug": "workspace3-slug",
                "display_name": "Workspace 3",
                "type": "workspace",
            },
        ]

    def test_get_all_workspaces_success(self, workspaces_mixin, sample_workspace_data):
        """Test successful retrieval of all workspaces."""
        workspaces_mixin.bitbucket.project_list.return_value = sample_workspace_data

        with patch(
            "mcp_atlassian.models.bitbucket.common.BitbucketWorkspace.from_api_response"
        ) as mock_from_api:
            # Mock the from_api_response to return BitbucketWorkspace objects
            mock_workspaces = []
            for ws_data in sample_workspace_data:
                mock_ws = MagicMock(spec=BitbucketWorkspace)
                mock_ws.uuid = ws_data["uuid"]
                mock_ws.name = ws_data["name"]
                mock_ws.slug = ws_data["slug"]
                mock_workspaces.append(mock_ws)
            mock_from_api.side_effect = mock_workspaces

            result = workspaces_mixin.get_all_workspaces()

            assert len(result) == 3
            assert all(isinstance(ws, MagicMock) for ws in result)
            workspaces_mixin.bitbucket.project_list.assert_called_once()
            assert mock_from_api.call_count == 3

    def test_get_all_workspaces_with_filter(
        self, workspaces_mixin_with_filter, sample_workspace_data
    ):
        """Test retrieval of workspaces with filtering applied."""
        workspaces_mixin_with_filter.bitbucket.project_list.return_value = (
            sample_workspace_data
        )

        with patch(
            "mcp_atlassian.models.bitbucket.common.BitbucketWorkspace.from_api_response"
        ) as mock_from_api:
            # Mock the from_api_response to return BitbucketWorkspace objects
            mock_workspaces = []
            for ws_data in sample_workspace_data:
                mock_ws = MagicMock(spec=BitbucketWorkspace)
                mock_ws.uuid = ws_data["uuid"]
                mock_ws.name = ws_data["name"]
                mock_ws.slug = ws_data["slug"]
                mock_workspaces.append(mock_ws)
            mock_from_api.side_effect = mock_workspaces

            with patch("mcp_atlassian.bitbucket.workspaces.logger") as mock_logger:
                result = workspaces_mixin_with_filter.get_all_workspaces()

                # Should return workspaces that match the filter (workspace1, workspace2)
                # The config has filter "workspace1,workspace2" so 2 should match
                assert len(result) == 2

                # Check that filtering debug message was logged
                mock_logger.debug.assert_called()

    def test_get_all_workspaces_filter_by_uuid(self, config, sample_workspace_data):
        """Test filtering workspaces by UUID."""
        config.workspaces_filter = "{12345678-1234-1234-1234-123456789abc}"

        with patch("mcp_atlassian.bitbucket.client.Bitbucket"):
            with patch("mcp_atlassian.bitbucket.client.configure_ssl_verification"):
                mixin = WorkspacesMixin(config)
                mixin.bitbucket = MagicMock()
                mixin.bitbucket.project_list.return_value = sample_workspace_data

                with patch(
                    "mcp_atlassian.models.bitbucket.common.BitbucketWorkspace.from_api_response"
                ) as mock_from_api:
                    # Create mock workspaces with different UUIDs/names
                    mock_workspaces = []
                    for _i, ws_data in enumerate(sample_workspace_data):
                        mock_ws = MagicMock(spec=BitbucketWorkspace)
                        mock_ws.uuid = ws_data["uuid"]
                        mock_ws.name = ws_data["name"]
                        mock_ws.slug = ws_data["slug"]
                        mock_workspaces.append(mock_ws)
                    mock_from_api.side_effect = mock_workspaces

                    result = mixin.get_all_workspaces()

                    # Should only return the workspace with matching UUID
                    # Only first workspace has the UUID we're filtering for
                    assert len(result) == 1
                    assert result[0].uuid == "{12345678-1234-1234-1234-123456789abc}"

    def test_get_all_workspaces_http_401_error(self, workspaces_mixin):
        """Test handling of 401 HTTP error."""
        mock_response = MagicMock()
        mock_response.status_code = 401
        http_error = HTTPError()
        http_error.response = mock_response
        workspaces_mixin.bitbucket.project_list.side_effect = http_error

        with pytest.raises(
            MCPAtlassianAuthenticationError,
            match="Authentication failed for Bitbucket API \\(401\\)",
        ):
            workspaces_mixin.get_all_workspaces()

    def test_get_all_workspaces_http_403_error(self, workspaces_mixin):
        """Test handling of 403 HTTP error."""
        mock_response = MagicMock()
        mock_response.status_code = 403
        http_error = HTTPError()
        http_error.response = mock_response
        workspaces_mixin.bitbucket.project_list.side_effect = http_error

        with pytest.raises(
            MCPAtlassianAuthenticationError,
            match="Authentication failed for Bitbucket API \\(403\\)",
        ):
            workspaces_mixin.get_all_workspaces()

    def test_get_all_workspaces_http_500_error(self, workspaces_mixin):
        """Test handling of non-auth HTTP errors."""
        mock_response = MagicMock()
        mock_response.status_code = 500
        http_error = HTTPError()
        http_error.response = mock_response
        workspaces_mixin.bitbucket.project_list.side_effect = http_error

        with pytest.raises(HTTPError):
            workspaces_mixin.get_all_workspaces()

    def test_get_all_workspaces_general_exception(self, workspaces_mixin):
        """Test handling of general exceptions."""
        workspaces_mixin.bitbucket.project_list.side_effect = Exception("Network error")

        with pytest.raises(Exception, match="Error getting workspaces: Network error"):
            workspaces_mixin.get_all_workspaces()

    def test_get_workspace_by_id_found_by_uuid(
        self, workspaces_mixin, sample_workspace_data
    ):
        """Test finding workspace by UUID."""
        with patch.object(workspaces_mixin, "get_all_workspaces") as mock_get_all:
            mock_workspaces = []
            for ws_data in sample_workspace_data:
                mock_ws = MagicMock(spec=BitbucketWorkspace)
                mock_ws.uuid = ws_data["uuid"]
                mock_ws.name = ws_data["name"]
                mock_ws.slug = ws_data["slug"]
                mock_workspaces.append(mock_ws)
            mock_get_all.return_value = mock_workspaces

            result = workspaces_mixin.get_workspace_by_id(
                "{12345678-1234-1234-1234-123456789abc}"
            )

            assert result is not None
            assert result.uuid == "{12345678-1234-1234-1234-123456789abc}"

    def test_get_workspace_by_id_found_by_name(
        self, workspaces_mixin, sample_workspace_data
    ):
        """Test finding workspace by name."""
        with patch.object(workspaces_mixin, "get_all_workspaces") as mock_get_all:
            mock_workspaces = []
            for ws_data in sample_workspace_data:
                mock_ws = MagicMock(spec=BitbucketWorkspace)
                mock_ws.uuid = ws_data["uuid"]
                mock_ws.name = ws_data["name"]
                mock_ws.slug = ws_data["slug"]
                mock_workspaces.append(mock_ws)
            mock_get_all.return_value = mock_workspaces

            result = workspaces_mixin.get_workspace_by_id("workspace2")

            assert result is not None
            assert result.name == "workspace2"

    def test_get_workspace_by_id_found_by_slug(
        self, workspaces_mixin, sample_workspace_data
    ):
        """Test finding workspace by slug."""
        with patch.object(workspaces_mixin, "get_all_workspaces") as mock_get_all:
            mock_workspaces = []
            for ws_data in sample_workspace_data:
                mock_ws = MagicMock(spec=BitbucketWorkspace)
                mock_ws.uuid = ws_data["uuid"]
                mock_ws.name = ws_data["name"]
                mock_ws.slug = ws_data["slug"]
                mock_workspaces.append(mock_ws)
            mock_get_all.return_value = mock_workspaces

            result = workspaces_mixin.get_workspace_by_id("workspace3-slug")

            assert result is not None
            assert result.slug == "workspace3-slug"

    def test_get_workspace_by_id_not_found(
        self, workspaces_mixin, sample_workspace_data
    ):
        """Test workspace not found scenario."""
        with patch.object(workspaces_mixin, "get_all_workspaces") as mock_get_all:
            mock_workspaces = []
            for ws_data in sample_workspace_data:
                mock_ws = MagicMock(spec=BitbucketWorkspace)
                mock_ws.uuid = ws_data["uuid"]
                mock_ws.name = ws_data["name"]
                mock_ws.slug = ws_data["slug"]
                mock_workspaces.append(mock_ws)
            mock_get_all.return_value = mock_workspaces

            result = workspaces_mixin.get_workspace_by_id("nonexistent")

            assert result is None

    def test_get_workspace_by_id_exception_handling(self, workspaces_mixin):
        """Test exception handling in get_workspace_by_id."""
        with patch.object(workspaces_mixin, "get_all_workspaces") as mock_get_all:
            mock_get_all.side_effect = Exception("API error")

            with pytest.raises(Exception, match="Error getting workspace: API error"):
                workspaces_mixin.get_workspace_by_id("test-workspace")

    def test_get_all_workspaces_empty_result(self, workspaces_mixin):
        """Test handling of empty workspace list."""
        workspaces_mixin.bitbucket.project_list.return_value = []

        result = workspaces_mixin.get_all_workspaces()

        assert result == []
        assert isinstance(result, list)

    def test_get_all_workspaces_filter_no_matches(
        self, workspaces_mixin_with_filter, sample_workspace_data
    ):
        """Test filtering when no workspaces match the filter."""
        # Set a filter that doesn't match any workspaces
        workspaces_mixin_with_filter.config.workspaces_filter = (
            "nonexistent1,nonexistent2"
        )
        workspaces_mixin_with_filter.bitbucket.project_list.return_value = (
            sample_workspace_data
        )

        with patch(
            "mcp_atlassian.models.bitbucket.common.BitbucketWorkspace.from_api_response"
        ) as mock_from_api:
            mock_workspaces = []
            for ws_data in sample_workspace_data:
                mock_ws = MagicMock(spec=BitbucketWorkspace)
                mock_ws.uuid = ws_data["uuid"]
                mock_ws.name = ws_data["name"]
                mock_ws.slug = ws_data["slug"]
                mock_workspaces.append(mock_ws)
            mock_from_api.side_effect = mock_workspaces

            with patch("mcp_atlassian.bitbucket.workspaces.logger") as mock_logger:
                result = workspaces_mixin_with_filter.get_all_workspaces()

                assert len(result) == 0
                # Should still log the filtering
                mock_logger.debug.assert_called()

    def test_mixin_inheritance(self):
        """Test that WorkspacesMixin properly inherits from BitbucketClient."""
        from mcp_atlassian.bitbucket.client import BitbucketClient

        assert issubclass(WorkspacesMixin, BitbucketClient)

        # Test that mixin can be instantiated (with mocked dependencies)
        with patch("mcp_atlassian.bitbucket.client.Bitbucket"):
            with patch("mcp_atlassian.bitbucket.client.configure_ssl_verification"):
                config = BitbucketConfig(
                    url="https://api.bitbucket.org/2.0",
                    auth_type="basic",
                    username="test@example.com",
                    app_password="password",
                )
                mixin = WorkspacesMixin(config)
                assert hasattr(mixin, "get_all_workspaces")
                assert hasattr(mixin, "get_workspace_by_id")
                assert hasattr(mixin, "config")  # From parent class
