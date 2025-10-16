"""Tests for the Bitbucket client module."""

import json
import shutil
import tempfile
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from git.exc import GitCommandError, InvalidGitRepositoryError

import mcp_atlassian.bitbucket.client as client_module
from mcp_atlassian.bitbucket.client import BitbucketClient
from mcp_atlassian.bitbucket.config import BitbucketConfig
from mcp_atlassian.exceptions import MCPAtlassianAuthenticationError
from mcp_atlassian.utils.oauth import OAuthConfig


@pytest.fixture(autouse=True)
def reset_code_search_state(monkeypatch, tmp_path):
    """Reset BitbucketClient code search state between tests."""
    BitbucketClient._code_search_lock = threading.Lock()
    BitbucketClient._code_search_initialized = False
    BitbucketClient._code_search_base_dir = None
    BitbucketClient._code_search_metadata_path = None
    BitbucketClient._code_search_metadata = {}
    BitbucketClient._code_search_cleanup_thread = None
    BitbucketClient._code_search_ttl_seconds = 300
    BitbucketClient._code_search_cleanup_interval_seconds = 60

    base_dir = tmp_path / "bitbucket_clone_cache"
    monkeypatch.setenv("BITBUCKET_CLONE_BASE_DIR", str(base_dir))

    def fake_start(cls):
        cls._code_search_cleanup_thread = SimpleNamespace(is_alive=lambda: True)

    monkeypatch.setattr(
        BitbucketClient,
        "_start_cleanup_worker",
        classmethod(fake_start),
    )

    yield

    BitbucketClient._code_search_initialized = False
    BitbucketClient._code_search_base_dir = None
    BitbucketClient._code_search_metadata_path = None
    BitbucketClient._code_search_metadata = {}
    BitbucketClient._code_search_cleanup_thread = None


@pytest.fixture
def client_factory():
    """Factory for creating BitbucketClient instances with patched dependencies."""

    def _factory(
        config: BitbucketConfig | None = None,
        bitbucket_attrs: dict | None = None,
    ) -> tuple[BitbucketClient, MagicMock]:
        cfg = config or BitbucketConfig(
            url="https://bitbucket.org",
            auth_type="basic",
            username="user@example.com",
            app_password="secret",
        )

        with (
            patch("mcp_atlassian.bitbucket.client.Bitbucket") as mock_bb,
            patch("mcp_atlassian.bitbucket.client.configure_ssl_verification"),
        ):
            bb_instance = MagicMock()
            bb_instance._session = MagicMock()
            bb_instance._session.proxies = {}
            bb_instance._session.headers = {}
            bb_instance._session.trust_env = True
            if bitbucket_attrs:
                for key, value in bitbucket_attrs.items():
                    setattr(bb_instance, key, value)
            mock_bb.return_value = bb_instance
            client = BitbucketClient(cfg)
            return client, bb_instance

    return _factory


class TestBitbucketClient:
    """Test cases for BitbucketClient class."""

    @pytest.fixture
    def basic_auth_config(self):
        """Create a basic auth configuration for testing."""
        return BitbucketConfig(
            url="https://api.bitbucket.org/2.0",
            auth_type="basic",
            username="test@example.com",
            app_password="app_password",
        )

    @pytest.fixture
    def pat_config(self):
        """Create a PAT configuration for testing."""
        return BitbucketConfig(
            url="https://bitbucket.company.com",
            auth_type="pat",
            username="testuser",
            personal_token="pat_token",
        )

    @pytest.fixture
    def oauth_config(self):
        """Create an OAuth configuration for testing."""
        oauth_conf = OAuthConfig(
            client_id="client_id",
            client_secret="client_secret",
            redirect_uri="http://localhost:8080/callback",
            scope="read",
            cloud_id="cloud_id",
        )
        return BitbucketConfig(
            url="https://api.bitbucket.org/2.0",
            auth_type="oauth",
            oauth_config=oauth_conf,
        )

    @patch("mcp_atlassian.bitbucket.client.Bitbucket")
    @patch("mcp_atlassian.bitbucket.client.configure_ssl_verification")
    def test_init_basic_auth_cloud(
        self, mock_ssl_config, mock_bitbucket, basic_auth_config
    ):
        """Test initialization with basic auth for cloud."""
        mock_bb_instance = MagicMock()
        mock_bb_instance._session = MagicMock()
        mock_bb_instance._session.proxies = {}
        mock_bb_instance._session.headers = {}
        mock_bitbucket.return_value = mock_bb_instance

        client = BitbucketClient(basic_auth_config)

        assert client.config == basic_auth_config
        mock_bitbucket.assert_called_once_with(
            url="https://api.bitbucket.org/2.0",
            username="test@example.com",
            password="app_password",
            cloud=True,
            verify_ssl=True,
        )
        mock_ssl_config.assert_called_once()

    @patch("mcp_atlassian.bitbucket.client.Bitbucket")
    @patch("mcp_atlassian.bitbucket.client.configure_ssl_verification")
    def test_init_pat_server(self, mock_ssl_config, mock_bitbucket, pat_config):
        """Test initialization with PAT for server."""
        mock_bb_instance = MagicMock()
        mock_bb_instance._session = MagicMock()
        mock_bb_instance._session.proxies = {}
        mock_bb_instance._session.headers = {}
        mock_bitbucket.return_value = mock_bb_instance

        client = BitbucketClient(pat_config)

        assert client.config == pat_config
        mock_bitbucket.assert_called_once_with(
            url="https://bitbucket.company.com",
            cloud=False,
            verify_ssl=True,
            token="pat_token",  # PAT goes in token field
        )
        mock_ssl_config.assert_called_once()

    @patch("mcp_atlassian.bitbucket.client.Bitbucket")
    @patch("mcp_atlassian.bitbucket.client.configure_ssl_verification")
    @patch("mcp_atlassian.bitbucket.client.configure_oauth_session")
    @patch("mcp_atlassian.bitbucket.client.Session")
    def test_init_oauth(
        self,
        mock_session,
        mock_oauth_config,
        mock_ssl_config,
        mock_bitbucket,
        oauth_config,
    ):
        """Test initialization with OAuth."""
        mock_session_instance = MagicMock()
        mock_session.return_value = mock_session_instance
        mock_oauth_config.return_value = True

        mock_bb_instance = MagicMock()
        mock_bb_instance._session = mock_session_instance
        mock_bitbucket.return_value = mock_bb_instance

        client = BitbucketClient(oauth_config)

        assert client.config == oauth_config
        mock_session.assert_called_once()
        mock_oauth_config.assert_called_once_with(
            mock_session_instance, oauth_config.oauth_config
        )

        expected_url = "https://api.atlassian.com/ex/bitbucket/cloud_id"
        mock_bitbucket.assert_called_once_with(
            url=expected_url, session=mock_session_instance, cloud=True, verify_ssl=True
        )

    @patch("mcp_atlassian.bitbucket.client.configure_oauth_session")
    @patch("mcp_atlassian.bitbucket.client.Session")
    def test_init_oauth_missing_cloud_id(
        self, mock_session, mock_oauth_config, oauth_config
    ):
        """Test OAuth initialization fails with missing cloud_id."""
        oauth_config.oauth_config.cloud_id = None

        with pytest.raises(
            ValueError, match="OAuth authentication requires a valid cloud_id"
        ):
            BitbucketClient(oauth_config)

    @patch("mcp_atlassian.bitbucket.client.configure_oauth_session")
    @patch("mcp_atlassian.bitbucket.client.Session")
    def test_init_oauth_session_config_fails(
        self, mock_session, mock_oauth_config, oauth_config
    ):
        """Test OAuth initialization fails when session configuration fails."""
        mock_session_instance = MagicMock()
        mock_session.return_value = mock_session_instance
        mock_oauth_config.return_value = False

        with pytest.raises(
            MCPAtlassianAuthenticationError, match="Failed to configure OAuth session"
        ):
            BitbucketClient(oauth_config)

    @patch("mcp_atlassian.bitbucket.client.BitbucketConfig")
    @patch("mcp_atlassian.bitbucket.client.Bitbucket")
    @patch("mcp_atlassian.bitbucket.client.configure_ssl_verification")
    def test_init_without_config_uses_env(
        self, mock_ssl_config, mock_bitbucket, mock_config_class
    ):
        """Test initialization without config uses environment variables."""
        mock_config_instance = MagicMock()
        mock_config_instance.auth_type = "basic"
        mock_config_instance.url = "https://api.bitbucket.org/2.0"
        mock_config_instance.username = "test@example.com"
        mock_config_instance.app_password = "password"
        mock_config_instance.is_cloud = True
        mock_config_instance.ssl_verify = True
        mock_config_class.from_env.return_value = mock_config_instance

        mock_bb_instance = MagicMock()
        mock_bb_instance._session = MagicMock()
        mock_bitbucket.return_value = mock_bb_instance

        client = BitbucketClient()

        mock_config_class.from_env.assert_called_once()
        assert client.config == mock_config_instance

    @patch("mcp_atlassian.bitbucket.client.Bitbucket")
    @patch("mcp_atlassian.bitbucket.client.configure_ssl_verification")
    def test_ssl_verification_disabled(self, mock_ssl_config, mock_bitbucket):
        """Test client with SSL verification disabled."""
        config = BitbucketConfig(
            url="https://api.bitbucket.org/2.0",
            auth_type="basic",
            username="test@example.com",
            app_password="password",
            ssl_verify=False,
        )

        mock_bb_instance = MagicMock()
        mock_bb_instance._session = MagicMock()
        mock_bb_instance._session.proxies = {}
        mock_bb_instance._session.headers = {}
        mock_bitbucket.return_value = mock_bb_instance

        client = BitbucketClient(config)

        mock_bitbucket.assert_called_once_with(
            url="https://api.bitbucket.org/2.0",
            username="test@example.com",
            password="password",
            cloud=True,
            verify_ssl=False,
        )

    @patch("mcp_atlassian.bitbucket.client.Bitbucket")
    @patch("mcp_atlassian.bitbucket.client.configure_ssl_verification")
    def test_proxy_configuration(self, mock_ssl_config, mock_bitbucket):
        """Test client with proxy configuration."""
        config = BitbucketConfig(
            url="https://api.bitbucket.org/2.0",
            auth_type="basic",
            username="test@example.com",
            app_password="password",
            http_proxy="http://proxy:8080",
            https_proxy="https://proxy:8080",
            no_proxy="localhost,127.0.0.1",
        )

        mock_bb_instance = MagicMock()
        mock_session = MagicMock()
        mock_session.proxies = {}
        mock_session.headers = {}
        mock_bb_instance._session = mock_session
        mock_bitbucket.return_value = mock_bb_instance

        client = BitbucketClient(config)

        # Check that proxies were configured
        expected_proxies = {"http": "http://proxy:8080", "https": "https://proxy:8080"}
        # Check the final state of proxies instead of mocking the update call
        assert mock_session.proxies == expected_proxies

    @patch("mcp_atlassian.bitbucket.client.Bitbucket")
    @patch("mcp_atlassian.bitbucket.client.configure_ssl_verification")
    def test_socks_proxy_configuration(self, mock_ssl_config, mock_bitbucket):
        """Test client with SOCKS proxy configuration."""
        config = BitbucketConfig(
            url="https://api.bitbucket.org/2.0",
            auth_type="basic",
            username="test@example.com",
            app_password="password",
            socks_proxy="socks5://proxy:1080",
        )

        mock_bb_instance = MagicMock()
        mock_session = MagicMock()
        mock_session.proxies = {}
        mock_session.headers = {}
        mock_bb_instance._session = mock_session
        mock_bitbucket.return_value = mock_bb_instance

        client = BitbucketClient(config)

        # Check that SOCKS proxy was configured
        expected_proxies = {
            "http": "socks5://proxy:1080",
            "https": "socks5://proxy:1080",
        }
        # Check the final state of proxies instead of mocking the update call
        assert mock_session.proxies == expected_proxies

    @patch("mcp_atlassian.bitbucket.client.Bitbucket")
    @patch("mcp_atlassian.bitbucket.client.configure_ssl_verification")
    def test_custom_headers_configuration(self, mock_ssl_config, mock_bitbucket):
        """Test client with custom headers configuration."""
        config = BitbucketConfig(
            url="https://api.bitbucket.org/2.0",
            auth_type="basic",
            username="test@example.com",
            app_password="password",
            custom_headers={"X-Custom": "value"},
        )

        mock_bb_instance = MagicMock()
        mock_session = MagicMock()
        mock_session.proxies = {}
        mock_session.headers = {}
        mock_bb_instance._session = mock_session
        mock_bitbucket.return_value = mock_bb_instance

        client = BitbucketClient(config)

        # Check that custom headers were configured
        # Check the final state of headers instead of mocking the update call
        assert "X-Custom" in mock_session.headers
        assert mock_session.headers["X-Custom"] == "value"

    def test_client_has_bitbucket_attribute(self, basic_auth_config):
        """Test that client has bitbucket attribute after initialization."""
        with patch("mcp_atlassian.bitbucket.client.Bitbucket") as mock_bitbucket:
            mock_bb_instance = MagicMock()
            mock_bb_instance._session = MagicMock()
            mock_bitbucket.return_value = mock_bb_instance

            with patch("mcp_atlassian.bitbucket.client.configure_ssl_verification"):
                client = BitbucketClient(basic_auth_config)

            assert hasattr(client, "bitbucket")
            assert client.bitbucket == mock_bb_instance

    def test_client_logging_basic_auth(self, basic_auth_config):
        """Test that appropriate logging occurs for basic auth."""
        with patch("mcp_atlassian.bitbucket.client.Bitbucket") as mock_bitbucket:
            mock_bb_instance = MagicMock()
            mock_bb_instance._session = MagicMock()
            mock_bitbucket.return_value = mock_bb_instance

            with patch("mcp_atlassian.bitbucket.client.configure_ssl_verification"):
                with patch("mcp_atlassian.bitbucket.client.logger") as mock_logger:
                    client = BitbucketClient(basic_auth_config)

                    # Should log debug messages
                    assert mock_logger.debug.called

    def test_client_logging_pat_auth(self, pat_config):
        """Test that appropriate logging occurs for PAT auth."""
        with patch("mcp_atlassian.bitbucket.client.Bitbucket") as mock_bitbucket:
            mock_bb_instance = MagicMock()
            mock_bb_instance._session = MagicMock()
            mock_bitbucket.return_value = mock_bb_instance

            with patch("mcp_atlassian.bitbucket.client.configure_ssl_verification"):
                with patch("mcp_atlassian.bitbucket.client.logger") as mock_logger:
                    client = BitbucketClient(pat_config)

                    # Should log debug messages with masked PAT
                    assert mock_logger.debug.called
                    # Verify PAT is masked in logs
                    log_calls = [
                        call.args[0] for call in mock_logger.debug.call_args_list
                    ]
                    pat_logged_directly = any(
                        "pat_token" in str(call) for call in log_calls
                    )
                    assert not pat_logged_directly, "PAT should be masked in logs"

    def test_get_pull_request_activities_cloud_success(self, basic_auth_config):
        """Test successful retrieval of pull request activities for cloud."""
        with patch("mcp_atlassian.bitbucket.client.Bitbucket") as mock_bitbucket:
            with patch("mcp_atlassian.bitbucket.client.configure_ssl_verification"):
                mock_bb_instance = MagicMock()
                mock_bb_instance._session = MagicMock()
                mock_bb_instance._session.proxies = {}
                mock_bb_instance._session.headers = {}
                mock_bb_instance.get.return_value = {
                    "values": [{"id": 1, "content": "test comment"}]
                }
                mock_bitbucket.return_value = mock_bb_instance

                client = BitbucketClient(basic_auth_config)
                result = client.get_pull_request_activities("workspace", "repo", 1)

                assert result == [{"id": 1, "content": "test comment"}]
                mock_bb_instance.get.assert_called_once_with(
                    "repositories/workspace/repo/pullrequests/1/activities"
                )

    def test_get_pull_request_activities_server_success(self, pat_config):
        """Test successful retrieval of pull request activities for server."""
        with patch("mcp_atlassian.bitbucket.client.Bitbucket") as mock_bitbucket:
            with patch("mcp_atlassian.bitbucket.client.configure_ssl_verification"):
                mock_bb_instance = MagicMock()
                mock_bb_instance._session = MagicMock()
                mock_bb_instance._session.proxies = {}
                mock_bb_instance._session.headers = {}
                mock_bb_instance.get.return_value = [
                    {"id": 1, "content": "test comment"}
                ]
                mock_bitbucket.return_value = mock_bb_instance

                client = BitbucketClient(pat_config)
                result = client.get_pull_request_activities("workspace", "repo", 1)

                assert result == [{"id": 1, "content": "test comment"}]
                mock_bb_instance.get.assert_called_once_with(
                    "projects/workspace/repos/repo/pull-requests/1/activities"
                )

    def test_get_pull_request_activities_empty_response(self, basic_auth_config):
        """Test pull request activities with empty response."""
        with patch("mcp_atlassian.bitbucket.client.Bitbucket") as mock_bitbucket:
            with patch("mcp_atlassian.bitbucket.client.configure_ssl_verification"):
                mock_bb_instance = MagicMock()
                mock_bb_instance._session = MagicMock()
                mock_bb_instance._session.proxies = {}
                mock_bb_instance._session.headers = {}
                mock_bb_instance.get.return_value = None
                mock_bitbucket.return_value = mock_bb_instance

                client = BitbucketClient(basic_auth_config)
                result = client.get_pull_request_activities("workspace", "repo", 1)

                assert result == []

    def test_get_pull_request_activities_exception_handling(self, basic_auth_config):
        """Test exception handling in get_pull_request_activities."""
        with patch("mcp_atlassian.bitbucket.client.Bitbucket") as mock_bitbucket:
            with patch("mcp_atlassian.bitbucket.client.configure_ssl_verification"):
                mock_bb_instance = MagicMock()
                mock_bb_instance._session = MagicMock()
                mock_bb_instance._session.proxies = {}
                mock_bb_instance._session.headers = {}
                mock_bb_instance.get.side_effect = Exception("API error")
                mock_bitbucket.return_value = mock_bb_instance

                client = BitbucketClient(basic_auth_config)

                with pytest.raises(Exception) as exc_info:
                    client.get_pull_request_activities("workspace", "repo", 1)

                assert "API error" in str(exc_info.value)


def test_code_search_returns_warning_when_update_failed(client_factory, tmp_path):
    client, _ = client_factory()
    repo_path = tmp_path / "repo"
    repo_path.mkdir()
    (repo_path / "README.md").write_text("needle\nother\n", encoding="utf-8")

    client._determine_default_branch = MagicMock(return_value=None)
    client._prepare_repository_clone = MagicMock(return_value=(repo_path, True))

    response = client.code_search(
        project_key="PROJ",
        repository_slug="repo",
        search_query="needle",
        surrounding_lines=0,
        max_results=5,
    )

    assert response["branch"] == "main"
    assert response["results"]
    assert response["results"][0]["matches"][0]["match_text"] == "needle"
    assert response["warning"]["type"] == "stale_content"


def test_code_search_validation_errors(client_factory):
    client, _ = client_factory()

    with pytest.raises(ValueError):
        client.code_search("", "repo", "query")
    with pytest.raises(ValueError):
        client.code_search("proj", "", "query")
    with pytest.raises(ValueError):
        client.code_search("proj", "repo", "   ")
    with pytest.raises(ValueError):
        client.code_search("proj", "repo", "query", surrounding_lines=-1)


def test_determine_default_branch_prefers_dict_fields(client_factory):
    client, bitbucket = client_factory()
    bitbucket.get_default_branch.return_value = {"displayId": "feature/main"}

    result = client._determine_default_branch("proj", "repo")

    assert result == "main"


def test_determine_default_branch_handles_attribute_and_string(client_factory):
    client, bitbucket = client_factory()
    bitbucket.get_default_branch.side_effect = [
        SimpleNamespace(name="develop"),
        "release",
    ]

    assert client._determine_default_branch("proj", "repo") == "develop"
    assert client._determine_default_branch("proj", "repo") == "release"


def test_determine_default_branch_uses_repo_fallback(client_factory):
    client, bitbucket = client_factory()
    bitbucket.get_default_branch.side_effect = RuntimeError("not found")
    bitbucket.get_repo.return_value = {
        "project": {"defaultBranch": {"name": "hotfix"}},
    }

    assert client._determine_default_branch("proj", "repo") == "hotfix"


def test_determine_default_branch_returns_none_when_repo_lookup_fails(client_factory):
    client, bitbucket = client_factory()
    bitbucket.get_default_branch.return_value = {}
    bitbucket.get_repo.side_effect = RuntimeError("boom")

    assert client._determine_default_branch("proj", "repo") is None


def test_prepare_repository_clone_triggers_clone_when_missing(client_factory):
    client, bitbucket = client_factory()
    clone_url = "https://example.org/repo.git"
    bitbucket.get_repo.return_value = {
        "links": {"clone": [{"href": clone_url, "name": "https"}]},
    }

    call_args: dict[str, tuple] = {}

    def fake_clone(url: str, target: Path, branch: str) -> None:
        target.mkdir(parents=True, exist_ok=True)
        call_args["args"] = (url, target, branch)

    client._clone_repository = MagicMock(side_effect=fake_clone)

    repo_path, update_failed = client._prepare_repository_clone("PROJ", "repo", "main")

    assert update_failed is False
    authenticated_url = call_args["args"][0]
    assert authenticated_url.endswith("/repo.git")
    assert "example.org" in authenticated_url
    assert repo_path.exists()
    assert "PROJ:repo:main" in BitbucketClient._code_search_metadata


def test_prepare_repository_clone_updates_existing_entry(client_factory):
    client, bitbucket = client_factory()
    clone_url = "https://example.org/repo.git"
    bitbucket.get_repo.return_value = {
        "links": {"clone": [{"href": clone_url, "name": "https"}]},
    }

    cache_key = "PROJ:repo:main"
    repo_path = (
        BitbucketClient._code_search_base_dir
        / BitbucketClient._slugify_for_path("PROJ", "repo", "main")
    )
    repo_path.mkdir(parents=True, exist_ok=True)
    BitbucketClient._code_search_metadata[cache_key] = {
        "project_key": "PROJ",
        "repository_slug": "repo",
        "branch": "main",
        "path": str(repo_path),
        "created_at": "2024-01-01T00:00:00+00:00",
        "last_accessed": "2024-01-01T00:00:00+00:00",
    }
    previous_access = BitbucketClient._code_search_metadata[cache_key]["last_accessed"]

    client._update_repository = MagicMock()

    returned_path, update_failed = client._prepare_repository_clone(
        "PROJ", "repo", "main"
    )

    assert update_failed is False
    assert returned_path == repo_path
    assert (
        BitbucketClient._code_search_metadata[cache_key]["last_accessed"]
        != previous_access
    )
    client._update_repository.assert_called_once()


def test_prepare_repository_clone_marks_update_failure(client_factory):
    client, bitbucket = client_factory()
    clone_url = "https://example.org/repo.git"
    bitbucket.get_repo.return_value = {
        "links": {"clone": [{"href": clone_url, "name": "https"}]},
    }

    cache_key = "PROJ:repo:main"
    repo_path = (
        BitbucketClient._code_search_base_dir
        / BitbucketClient._slugify_for_path("PROJ", "repo", "main")
    )
    repo_path.mkdir(parents=True, exist_ok=True)
    BitbucketClient._code_search_metadata[cache_key] = {
        "project_key": "PROJ",
        "repository_slug": "repo",
        "branch": "main",
        "path": str(repo_path),
        "created_at": "2024-01-01T00:00:00+00:00",
        "last_accessed": "2024-01-01T00:00:00+00:00",
    }
    previous_access = BitbucketClient._code_search_metadata[cache_key]["last_accessed"]

    client._update_repository = MagicMock(side_effect=RuntimeError("network issue"))

    _, update_failed = client._prepare_repository_clone("PROJ", "repo", "main")

    assert update_failed is True
    assert (
        BitbucketClient._code_search_metadata[cache_key]["last_accessed"]
        == previous_access
    )


def test_clone_repository_uses_pat_flow_for_server_pat(client_factory, tmp_path):
    config = BitbucketConfig(
        url="https://bitbucket.company.com",
        auth_type="pat",
        username="svc",
        personal_token="token",
    )
    client, _ = client_factory(config=config)

    with patch.object(client, "_clone_with_pat_auth") as mock_clone:
        client._clone_repository(
            "https://example.org/repo.git", tmp_path / "repo", "main"
        )
        mock_clone.assert_called_once()


def test_clone_repository_uses_repo_clone_from(client_factory, monkeypatch, tmp_path):
    client, _ = client_factory()

    captured: dict[str, str] = {}

    def fake_clone_from(url, target, branch, depth, single_branch):
        target.mkdir(parents=True, exist_ok=True)
        captured["branch"] = branch

    monkeypatch.setattr(
        "mcp_atlassian.bitbucket.client.Repo.clone_from",
        fake_clone_from,
    )

    client._clone_repository(
        "https://example.org/repo.git", tmp_path / "repo", "develop"
    )

    assert captured["branch"] == "develop"


def test_clone_repository_wraps_git_errors(client_factory, monkeypatch, tmp_path):
    client, _ = client_factory()
    monkeypatch.setattr(
        "mcp_atlassian.bitbucket.client.Repo.clone_from",
        MagicMock(side_effect=GitCommandError("clone", 1, "boom")),
    )

    with pytest.raises(RuntimeError):
        client._clone_repository(
            "https://example.org/repo.git", tmp_path / "repo", "main"
        )


def test_clone_with_pat_auth_runs_subprocess(client_factory, monkeypatch, tmp_path):
    config = BitbucketConfig(
        url="https://bitbucket.company.com",
        auth_type="pat",
        username="svc",
        personal_token="token",
    )
    client, _ = client_factory(config=config)

    target = tmp_path / "repo"
    captured: dict[str, list[str]] = {}

    def fake_run(command, env, text, capture_output):
        captured["command"] = command
        captured["env"] = env
        return SimpleNamespace(returncode=0, stdout="ok", stderr="")

    monkeypatch.setattr("mcp_atlassian.bitbucket.client.subprocess.run", fake_run)

    client._clone_with_pat_auth("https://example.org/repo.git", target, "main")

    assert any("Authorization: Bearer token" in part for part in captured["command"])
    assert target.exists()


def test_clone_with_pat_auth_failure_cleans_directory(
    client_factory, monkeypatch, tmp_path
):
    config = BitbucketConfig(
        url="https://bitbucket.company.com",
        auth_type="pat",
        username="svc",
        personal_token="token",
    )
    client, _ = client_factory(config=config)

    target = tmp_path / "repo"

    def fake_run(command, env, text, capture_output):
        return SimpleNamespace(returncode=1, stdout="", stderr="fail")

    monkeypatch.setattr("mcp_atlassian.bitbucket.client.subprocess.run", fake_run)

    with pytest.raises(RuntimeError):
        client._clone_with_pat_auth("https://example.org/repo.git", target, "main")

    assert not target.exists()


def test_clone_with_pat_auth_requires_token(client_factory):
    config = BitbucketConfig(
        url="https://bitbucket.company.com",
        auth_type="pat",
        username="svc",
        personal_token=None,
    )
    client, _ = client_factory(config=config)

    with pytest.raises(RuntimeError):
        client._clone_with_pat_auth(
            "https://example.org/repo.git", Path("repo"), "main"
        )


def test_update_repository_reclones_invalid_repo(client_factory, monkeypatch, tmp_path):
    client, _ = client_factory()
    repo_path = tmp_path / "repo"
    repo_path.mkdir()

    class InvalidRepo:
        def __init__(self, path):
            raise InvalidGitRepositoryError(str(path))

    monkeypatch.setattr(client_module, "Repo", InvalidRepo)

    removed: dict[str, Path] = {}
    monkeypatch.setattr(
        BitbucketClient,
        "_safe_rmtree",
        classmethod(lambda cls, path: removed.setdefault("path", path)),
    )

    cloned: dict[str, tuple] = {}

    def fake_clone(self, clone_url, target_path, branch_name):
        cloned["args"] = (clone_url, target_path, branch_name)

    monkeypatch.setattr(BitbucketClient, "_clone_repository", fake_clone)

    client._update_repository(repo_path, "https://example.org/repo.git", "main")

    assert removed["path"] == repo_path
    assert cloned["args"][1] == repo_path


def test_update_repository_fetch_failure_triggers_reclone(
    client_factory, monkeypatch, tmp_path
):
    client, _ = client_factory()
    repo_path = tmp_path / "repo"
    repo_path.mkdir()

    class FakeRemote:
        def __init__(self):
            self.set_url_called = False

        def set_url(self, url):
            self.set_url_called = True

        def fetch(self, branch):
            raise GitCommandError("fetch", 1, "boom")

    class FakeGit:
        def checkout(self, branch):
            return None

        def reset(self, *_args, **_kwargs):
            return None

        def clean(self, *_args, **_kwargs):
            return None

    class FakeRepo:
        def __init__(self, path):
            self.git = FakeGit()
            self._remote = FakeRemote()
            self.remote_calls = 0

        def remote(self, name="origin"):
            self.remote_calls += 1
            if self.remote_calls == 1:
                raise ValueError("no remote")
            return self._remote

        def create_remote(self, name, url):
            self._remote = FakeRemote()
            return self._remote

    monkeypatch.setattr(client_module, "Repo", FakeRepo)

    removed: list[Path] = []
    monkeypatch.setattr(
        BitbucketClient,
        "_safe_rmtree",
        classmethod(lambda cls, path: removed.append(path) or None),
    )

    cloned: dict[str, tuple] = {}

    def fake_clone(self, clone_url, target_path, branch_name):
        cloned["args"] = (clone_url, target_path, branch_name)

    monkeypatch.setattr(BitbucketClient, "_clone_repository", fake_clone)

    client._update_repository(repo_path, "https://example.org/repo.git", "main")

    assert removed and removed[0] == repo_path
    assert cloned["args"][1] == repo_path


def test_update_repository_updates_existing_remote(
    client_factory, monkeypatch, tmp_path
):
    client, _ = client_factory()
    repo_path = tmp_path / "repo"
    repo_path.mkdir()

    class FakeRemote:
        def __init__(self):
            self.set_url_called = False
            self.fetch_called = False

        def set_url(self, url):
            self.set_url_called = True

        def fetch(self, branch):
            self.fetch_called = True

    class FakeGit:
        def checkout(self, branch):
            return None

        def reset(self, *_args, **_kwargs):
            return None

        def clean(self, *_args, **_kwargs):
            return None

    created: dict[str, FakeRemote] = {}

    class FakeRepo:
        def __init__(self, path):
            self.git = FakeGit()
            self.remote_obj = FakeRemote()
            created["remote"] = self.remote_obj

        def remote(self, name="origin"):
            return self.remote_obj

    monkeypatch.setattr(client_module, "Repo", FakeRepo)
    client._update_repository(repo_path, "https://example.org/repo.git", "main")

    remote = created["remote"]
    assert remote.set_url_called is True
    assert remote.fetch_called is True


def test_update_repository_cleanup_failure_raises(
    client_factory, monkeypatch, tmp_path
):
    client, _ = client_factory()
    repo_path = tmp_path / "repo"
    repo_path.mkdir()

    class FakeRemote:
        def set_url(self, url):
            return None

        def fetch(self, branch):
            raise GitCommandError("fetch", 1, "boom")

    class FakeGit:
        def checkout(self, branch):
            return None

        def reset(self, *_args, **_kwargs):
            return None

        def clean(self, *_args, **_kwargs):
            return None

    class FakeRepo:
        def __init__(self, path):
            self.git = FakeGit()
            self.remote_obj = FakeRemote()

        def remote(self, name="origin"):
            return self.remote_obj

    monkeypatch.setattr(client_module, "Repo", FakeRepo)
    monkeypatch.setattr(
        BitbucketClient,
        "_safe_rmtree",
        classmethod(
            lambda cls, path: (_ for _ in ()).throw(RuntimeError("remove fail"))
        ),
    )

    with pytest.raises(RuntimeError):
        client._update_repository(repo_path, "https://example.org/repo.git", "main")


def test_extract_clone_url_variants(client_factory):
    client, _ = client_factory()

    repo_info = {
        "links": {
            "clone": [
                {"href": "https://example.org/repo.git", "name": "https"},
                {"href": "https://example.org/other.git", "name": "ssh"},
            ],
        }
    }
    assert (
        client._extract_clone_url(repo_info, "PROJ") == "https://example.org/repo.git"
    )

    repo_info["links"] = {"clone": {"href": "https://example.org/dict.git"}}
    assert (
        client._extract_clone_url(repo_info, "PROJ") == "https://example.org/dict.git"
    )


def test_extract_clone_url_fallback_builds_from_config(client_factory):
    config = BitbucketConfig(
        url="https://bitbucket.company.com",
        auth_type="basic",
        username="user",
        app_password="secret",
    )
    client, _ = client_factory(config=config)
    repo_info = {"slug": "repo", "project": {"key": "PROJ"}}

    expected = "https://bitbucket.company.com/scm/PROJ/repo.git"
    assert client._extract_clone_url(repo_info, "PROJ") == expected


def test_extract_clone_url_uses_first_entry_without_name(client_factory):
    client, _ = client_factory()
    repo_info = {"links": {"clone": [{"href": "https://example.org/repo.git"}]}}
    assert (
        client._extract_clone_url(repo_info, "PROJ") == "https://example.org/repo.git"
    )


def test_extract_clone_url_returns_none_for_unknown_repo_info(client_factory):
    client, _ = client_factory()
    assert client._extract_clone_url("not-a-dict", "PROJ") is None


def test_build_authenticated_clone_url_variants(client_factory):
    client, _ = client_factory()
    raw_url = "https://example.org/scm/PROJ/repo.git"

    embedded = client._build_authenticated_clone_url(raw_url)
    assert embedded.startswith("https://user%40example.com:secret@")

    client.config.app_password = None
    assert client._build_authenticated_clone_url(raw_url) == raw_url

    config = BitbucketConfig(
        url="https://bitbucket.company.com",
        auth_type="pat",
        username="svc",
        personal_token="token",
    )
    client_pat, _ = client_factory(config=config)
    clean_url = client_pat._build_authenticated_clone_url(raw_url)
    assert clean_url == raw_url


def test_build_authenticated_clone_url_with_oauth_token(client_factory):
    oauth_conf = OAuthConfig(
        client_id="id",
        client_secret="secret",
        redirect_uri="http://localhost",
        scope="scope",
        cloud_id="cloud",
        access_token="token123",
    )
    config = BitbucketConfig(
        url="https://api.bitbucket.org/2.0",
        auth_type="oauth",
        username="oauth-user",
        oauth_config=oauth_conf,
    )
    client, _ = client_factory(config=config)
    url = client._build_authenticated_clone_url("https://example.org/repo.git")
    assert "oauth-user" in url
    assert "token123" in url


def test_build_authenticated_clone_url_returns_raw_when_host_missing(client_factory):
    client, _ = client_factory()
    raw_url = "file:///C:/tmp/repo.git"
    assert client._build_authenticated_clone_url(raw_url) == raw_url


def test_execute_code_search_ignores_git_and_faulty_files(
    client_factory, tmp_path, monkeypatch
):
    client, _ = client_factory()
    repo_path = tmp_path / "repo"
    repo_path.mkdir()
    (repo_path / ".git").mkdir()
    target_file = repo_path / "match.txt"
    target_file.write_text("Needle line\nSecond", encoding="utf-8")
    faulty_file = repo_path / "faulty.txt"
    faulty_file.write_text("ignored", encoding="utf-8")
    (repo_path / "binary.bin").write_bytes(b"\x00\x01")

    original_read_text = Path.read_text

    def fake_read_text(self, *args, **kwargs):
        if self == faulty_file:
            raise OSError("cannot read")
        return original_read_text(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", fake_read_text)

    results = client._execute_code_search(
        repo_path=repo_path,
        project_key="PROJ",
        repository_slug="repo",
        branch="main",
        search_query="Needle",
        surrounding_lines=1,
        case_sensitive=True,
    )

    assert results and results[0]["matches"][0]["match_text"] == "Needle line"


def test_is_binary_file_handles_oserror(monkeypatch, tmp_path):
    file_path = tmp_path / "file.bin"

    original_open = Path.open

    def fake_open(self, path, *args, **kwargs):
        if path == file_path:
            raise OSError("open failed")
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", fake_open)

    # When OSError occurs, _is_binary_file returns False (treats as text file)
    assert BitbucketClient._is_binary_file(file_path) is False


def test_safe_rmtree_recovers_from_failure(monkeypatch, tmp_path):
    target = tmp_path / "dir"
    target.mkdir()
    (target / "file.txt").write_text("data", encoding="utf-8")

    real_rmtree = shutil.rmtree
    calls = {"count": 0}

    def flaky_rmtree(path, ignore_errors=False, onerror=None):
        calls["count"] += 1
        # Since ignore_errors=True is passed, we should not raise but succeed silently
        if ignore_errors:
            real_rmtree(path)
        else:
            raise OSError("initial failure")

    monkeypatch.setattr(client_module.shutil, "rmtree", flaky_rmtree)
    monkeypatch.setattr(
        client_module.os,
        "walk",
        lambda path: [(str(target), [], ["file.txt"])],
    )
    monkeypatch.setattr(client_module.os, "chmod", lambda *args, **kwargs: None)

    BitbucketClient._safe_rmtree(target)
    assert calls["count"] == 1  # Should only be called once
    assert not target.exists()  # Directory should be removed


def test_determine_clone_base_dir_respects_env(monkeypatch, tmp_path):
    candidate = tmp_path / "custom"
    monkeypatch.setenv("BITBUCKET_CLONE_BASE_DIR", str(candidate))

    result = BitbucketClient._determine_clone_base_dir()

    assert result == candidate.resolve()


def test_determine_clone_base_dir_fallback_to_project_root(monkeypatch, tmp_path):
    monkeypatch.delenv("BITBUCKET_CLONE_BASE_DIR", raising=False)
    temp_root = tmp_path / "temp"
    temp_root.mkdir()
    project_root = tmp_path / "project"
    project_root.mkdir()

    monkeypatch.setattr(tempfile, "gettempdir", lambda: str(temp_root))
    original_mkdir = Path.mkdir

    def fake_mkdir(self, *args, **kwargs):
        if self == temp_root / "cloned_repos":
            raise PermissionError("no access")
        return original_mkdir(self, *args, **kwargs)

    monkeypatch.setattr(Path, "mkdir", fake_mkdir)
    monkeypatch.setattr(
        BitbucketClient,
        "_find_project_root",
        classmethod(lambda cls: project_root),
    )

    result = BitbucketClient._determine_clone_base_dir()

    assert result == project_root / "cloned_repos"


def test_find_project_root_returns_existing_path():
    project_root = BitbucketClient._find_project_root()
    assert project_root.exists()


def test_determine_clone_base_dir_uses_temp_directory(monkeypatch, tmp_path):
    monkeypatch.delenv("BITBUCKET_CLONE_BASE_DIR", raising=False)
    monkeypatch.setattr(tempfile, "gettempdir", lambda: str(tmp_path))
    result = BitbucketClient._determine_clone_base_dir()
    assert result == tmp_path / "cloned_repos"


def test_resolve_cache_ttl_seconds_handles_env(monkeypatch):
    monkeypatch.setenv("BITBUCKET_CODE_SEARCH_CACHE_TTL_SECONDS", "120")
    assert BitbucketClient._resolve_cache_ttl_seconds() == 120


def test_resolve_cache_ttl_seconds_invalid_uses_default(monkeypatch):
    monkeypatch.setenv("BITBUCKET_CODE_SEARCH_CACHE_TTL_SECONDS", "invalid")
    assert BitbucketClient._resolve_cache_ttl_seconds() == 3600


def test_resolve_cleanup_interval_prefers_env(monkeypatch):
    monkeypatch.setenv("BITBUCKET_CODE_SEARCH_CLEANUP_INTERVAL_SECONDS", "180")
    assert BitbucketClient._resolve_cleanup_interval(999) == 180


def test_resolve_cleanup_interval_computes_from_ttl(monkeypatch):
    monkeypatch.delenv("BITBUCKET_CODE_SEARCH_CLEANUP_INTERVAL_SECONDS", raising=False)
    assert BitbucketClient._resolve_cleanup_interval(0) == 180
    assert BitbucketClient._resolve_cleanup_interval(200) == 100


def test_load_and_save_cache_metadata_roundtrip(tmp_path):
    metadata_path = tmp_path / "metadata.json"
    metadata_path.write_text(
        json.dumps({"valid": {"path": "x"}, "invalid": ["oops"]}),
        encoding="utf-8",
    )

    loaded = BitbucketClient._load_cache_metadata(metadata_path)
    assert loaded == {"valid": {"path": "x"}}

    BitbucketClient._code_search_metadata_path = metadata_path
    BitbucketClient._code_search_metadata = {"foo": {"path": "y"}}
    BitbucketClient._save_cache_metadata_locked()

    saved = json.loads(metadata_path.read_text(encoding="utf-8"))
    assert saved == {"foo": {"path": "y"}}


def test_save_cache_metadata_handles_write_error(tmp_path):
    directory_path = tmp_path / "dir"
    directory_path.mkdir()
    BitbucketClient._code_search_metadata_path = directory_path
    BitbucketClient._code_search_metadata = {"foo": {"path": "x"}}

    BitbucketClient._save_cache_metadata_locked()


def test_cleanup_expired_clones_removes_stale_entries(tmp_path, monkeypatch):
    base_dir = tmp_path / "cache"
    base_dir.mkdir()
    repo_dir = base_dir / "proj_repo_main"
    repo_dir.mkdir()
    (repo_dir / "file.txt").write_text("data", encoding="utf-8")

    BitbucketClient._code_search_base_dir = base_dir
    BitbucketClient._code_search_metadata_path = tmp_path / "metadata.json"
    BitbucketClient._code_search_metadata = {
        "PROJ:repo:main": {
            "path": str(repo_dir),
            "last_accessed": (
                datetime.now(timezone.utc) - timedelta(seconds=600)
            ).isoformat(),
        },
        "PROJ:repo:new": {
            "path": str(base_dir / "other"),
            "last_accessed": datetime.now(timezone.utc).isoformat(),
        },
    }
    BitbucketClient._code_search_ttl_seconds = 10

    removed: list[Path] = []
    monkeypatch.setattr(
        BitbucketClient,
        "_safe_rmtree",
        classmethod(lambda cls, path: removed.append(path) or shutil.rmtree(path)),
    )
    monkeypatch.setattr(
        BitbucketClient,
        "_cleanup_orphaned_directories_internal",
        classmethod(lambda cls: None),
    )

    BitbucketClient._cleanup_expired_clones_internal()

    assert "PROJ:repo:main" not in BitbucketClient._code_search_metadata
    assert repo_dir in removed


def test_cleanup_orphaned_directories_removes_untracked(tmp_path, monkeypatch):
    base_dir = tmp_path / "cache"
    base_dir.mkdir()
    tracked = base_dir / "tracked"
    tracked.mkdir()
    (tracked / ".git").mkdir()
    orphan = base_dir / "orphan"
    orphan.mkdir()
    (orphan / ".git").mkdir()

    BitbucketClient._code_search_base_dir = base_dir
    BitbucketClient._code_search_metadata = {"key": {"path": str(tracked)}}

    monkeypatch.setattr(
        BitbucketClient,
        "_safe_rmtree",
        classmethod(lambda cls, path: shutil.rmtree(path)),
    )

    BitbucketClient._cleanup_orphaned_directories_internal()

    assert tracked.exists()
    assert not orphan.exists()


def test_slugify_for_path_normalizes_text():
    slug = BitbucketClient._slugify_for_path("Proj Name", "Repo/Name", "Feature#1")
    assert slug == "proj_name_repo_name_feature_1"


def test_cleanup_orphaned_directories_handles_remove_failure(tmp_path, monkeypatch):
    base_dir = tmp_path / "cache"
    base_dir.mkdir()
    orphan = base_dir / "orphan"
    orphan.mkdir()
    (orphan / ".git").mkdir()
    BitbucketClient._code_search_base_dir = base_dir
    BitbucketClient._code_search_metadata = {}

    def failing_rmtree(cls, path):
        raise RuntimeError("remove failed")

    monkeypatch.setattr(
        BitbucketClient,
        "_safe_rmtree",
        classmethod(failing_rmtree),
    )

    BitbucketClient._cleanup_orphaned_directories_internal()
    assert orphan.exists()


def test_cleanup_orphaned_directories_handles_global_exception(monkeypatch, tmp_path):
    base_dir = tmp_path / "cache"
    base_dir.mkdir()
    BitbucketClient._code_search_base_dir = base_dir
    BitbucketClient._code_search_metadata = {}

    original_iterdir = Path.iterdir

    def raising_iterdir(self):
        if self == base_dir:
            raise OSError("iterdir failed")
        return original_iterdir(self)

    monkeypatch.setattr(Path, "iterdir", raising_iterdir)

    BitbucketClient._cleanup_orphaned_directories_internal()


def test_cleanup_orphaned_directories_no_base_dir():
    BitbucketClient._code_search_base_dir = Path("nonexistent-path")
    BitbucketClient._cleanup_orphaned_directories_internal()


def test_looks_like_repo_clone_returns_false_on_error(monkeypatch, tmp_path):
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    original_iterdir = Path.iterdir

    def raising_iterdir(self):
        if self == repo_dir:
            raise OSError("cannot iterate")
        return original_iterdir(self)

    monkeypatch.setattr(Path, "iterdir", raising_iterdir)

    assert BitbucketClient._looks_like_repo_clone(repo_dir) is False


def test_prepare_repository_clone_requires_base_dir(client_factory):
    client, bitbucket = client_factory()
    BitbucketClient._code_search_base_dir = None
    bitbucket.get_repo.return_value = {
        "links": {"clone": [{"href": "https://example.org/repo.git"}]}
    }

    with pytest.raises(RuntimeError):
        client._prepare_repository_clone("PROJ", "repo", "main")


def test_prepare_repository_clone_requires_clone_url(client_factory):
    client, bitbucket = client_factory()
    bitbucket.get_repo.return_value = {}

    with patch.object(client, "_extract_clone_url", return_value=None):
        with pytest.raises(RuntimeError):
            client._prepare_repository_clone("PROJ", "repo", "main")


def test_prepare_repository_clone_safe_rmtree_failure(
    client_factory, monkeypatch, tmp_path
):
    client, bitbucket = client_factory()
    clone_url = "https://example.org/repo.git"
    bitbucket.get_repo.return_value = {
        "links": {"clone": [{"href": clone_url, "name": "https"}]},
    }
    repo_path = (
        BitbucketClient._code_search_base_dir
        / BitbucketClient._slugify_for_path("PROJ", "repo", "main")
    )
    repo_path.mkdir(parents=True, exist_ok=True)

    def failing_rmtree(cls, path):
        raise RuntimeError("cleanup fail")

    monkeypatch.setattr(
        BitbucketClient,
        "_safe_rmtree",
        classmethod(failing_rmtree),
    )

    with pytest.raises(RuntimeError):
        client._prepare_repository_clone("PROJ", "repo", "main")


def test_prepare_repository_clone_propagates_clone_error(client_factory):
    client, bitbucket = client_factory()
    bitbucket.get_repo.return_value = {
        "links": {"clone": [{"href": "https://example.org/repo.git", "name": "https"}]},
    }

    with patch.object(
        client, "_clone_repository", side_effect=RuntimeError("clone failed")
    ):
        with pytest.raises(RuntimeError):
            client._prepare_repository_clone("PROJ", "repo", "main")


def test_ensure_code_search_initialized_when_already_initialized(monkeypatch):
    BitbucketClient._code_search_initialized = True
    BitbucketClient._code_search_cleanup_thread = SimpleNamespace(is_alive=lambda: True)
    flags = {"cleanup": False, "priority": False}

    def mark_cleanup(cls):
        flags["cleanup"] = True

    def mark_priority(cls):
        flags["priority"] = True

    monkeypatch.setattr(
        BitbucketClient,
        "_ensure_cleanup_worker_running",
        classmethod(mark_cleanup),
    )
    monkeypatch.setattr(
        BitbucketClient,
        "_run_priority_cleanup",
        classmethod(mark_priority),
    )

    BitbucketClient._ensure_code_search_initialized()

    assert flags["cleanup"] is True
    assert flags["priority"] is True


def test_ensure_code_search_initialized_handles_cleanup_exception(monkeypatch):
    BitbucketClient._code_search_initialized = False

    def raising_cleanup(cls):
        raise RuntimeError("cleanup error")

    monkeypatch.setattr(
        BitbucketClient,
        "_cleanup_expired_clones_internal",
        classmethod(raising_cleanup),
    )

    BitbucketClient._ensure_code_search_initialized()

    assert BitbucketClient._code_search_initialized is True


def test_run_cleanup_worker_handles_failures(monkeypatch):
    call_state = {"cleanup_calls": 0}

    def fake_sleep(_interval):
        if call_state["cleanup_calls"] >= 1:
            raise KeyboardInterrupt

    def failing_cleanup(cls):
        call_state["cleanup_calls"] += 1
        raise RuntimeError("boom")

    monkeypatch.setattr(client_module.time, "sleep", fake_sleep)
    monkeypatch.setattr(
        BitbucketClient,
        "_cleanup_expired_clones",
        classmethod(failing_cleanup),
    )

    with pytest.raises(KeyboardInterrupt):
        BitbucketClient._run_cleanup_worker()

    assert call_state["cleanup_calls"] >= 1


def test_run_priority_cleanup_invokes_cleanup(monkeypatch):
    BitbucketClient._code_search_initialized = True
    calls = {"count": 0}

    def record_cleanup(cls):
        calls["count"] += 1

    monkeypatch.setattr(
        BitbucketClient,
        "_cleanup_expired_clones",
        classmethod(record_cleanup),
    )

    BitbucketClient._run_priority_cleanup()
    assert calls["count"] == 1


def test_run_priority_cleanup_swallows_exception(monkeypatch):
    BitbucketClient._code_search_initialized = True

    def raising_cleanup(cls):
        raise RuntimeError("priority failure")

    monkeypatch.setattr(
        BitbucketClient,
        "_cleanup_expired_clones",
        classmethod(raising_cleanup),
    )

    BitbucketClient._run_priority_cleanup()


def test_cleanup_expired_clones_returns_early_for_zero_ttl():
    BitbucketClient._code_search_ttl_seconds = 0
    BitbucketClient._cleanup_expired_clones_internal()


def test_cleanup_expired_clones_skips_invalid_timestamp(tmp_path):
    base_dir = tmp_path / "cache"
    base_dir.mkdir()
    BitbucketClient._code_search_base_dir = base_dir
    BitbucketClient._code_search_metadata = {
        "bad": {"path": str(base_dir / "repo"), "last_accessed": "not-a-date"},
    }

    BitbucketClient._cleanup_expired_clones_internal()

    assert "bad" in BitbucketClient._code_search_metadata


def test_cleanup_expired_clones_logs_when_remove_fails(tmp_path, monkeypatch):
    base_dir = tmp_path / "cache"
    base_dir.mkdir()
    repo_dir = base_dir / "repo"
    repo_dir.mkdir()
    BitbucketClient._code_search_base_dir = base_dir
    BitbucketClient._code_search_metadata_path = tmp_path / "metadata.json"
    BitbucketClient._code_search_metadata = {
        "key": {
            "path": str(repo_dir),
            "last_accessed": (
                datetime.now(timezone.utc) - timedelta(seconds=600)
            ).isoformat(),
        }
    }
    BitbucketClient._code_search_ttl_seconds = 10

    def failing_rmtree(cls, path):
        raise RuntimeError("cannot remove")

    monkeypatch.setattr(
        BitbucketClient,
        "_safe_rmtree",
        classmethod(failing_rmtree),
    )
    monkeypatch.setattr(
        BitbucketClient,
        "_cleanup_orphaned_directories_internal",
        classmethod(lambda cls: None),
    )

    BitbucketClient._cleanup_expired_clones_internal()

    assert "key" not in BitbucketClient._code_search_metadata
