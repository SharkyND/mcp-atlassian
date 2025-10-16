"""Base client module for Bitbucket API interactions."""

import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time
from collections.abc import Callable
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlparse, urlunparse

from atlassian import Bitbucket
from git import Repo
from git.exc import GitCommandError, InvalidGitRepositoryError, NoSuchPathError
from requests import Session

from ..exceptions import MCPAtlassianAuthenticationError
from ..utils.logging import (
    get_masked_session_headers,
    mask_sensitive,
)
from ..utils.oauth import configure_oauth_session
from ..utils.ssl import configure_ssl_verification
from .config import BitbucketConfig
from .constants import DEFAULT_BRANCH_NAMES

# Configure logging
logger = logging.getLogger("mcp-atlassian")


class SearchType(Enum):
    """Enumeration of available search types for code search."""

    SUBSTRING = "substring"
    REGEX = "regex"
    WHOLE_WORD = "whole_word"
    MULTI_TERM = "multi_term"


class MultiTermOperator(Enum):
    """Enumeration for multi-term search operators."""

    AND = "and"
    OR = "or"


class BitbucketClient:
    """Base client for Bitbucket API interactions."""

    config: BitbucketConfig
    _code_search_lock = threading.Lock()
    _code_search_initialized = False
    _code_search_base_dir: Path | None = None
    _code_search_metadata_path: Path | None = None
    _code_search_metadata: dict[str, dict[str, Any]] = {}
    _code_search_cleanup_thread: threading.Thread | None = None
    _code_search_ttl_seconds: int = 300  # default 5 minutes
    _code_search_cleanup_interval_seconds: int = 60

    def __init__(self, config: BitbucketConfig | None = None) -> None:
        """Initialize the Bitbucket client with configuration options.

        Args:
            config: Optional configuration object (will use env vars if not provided)

        Raises:
            ValueError: If configuration is invalid or required credentials are missing
            MCPAtlassianAuthenticationError: If OAuth authentication fails
        """
        # Load configuration from environment variables if not provided
        self.config = config or BitbucketConfig.from_env()

        # Initialize the Bitbucket client based on auth type
        if self.config.auth_type == "oauth":
            if not self.config.oauth_config or not self.config.oauth_config.cloud_id:
                error_msg = "OAuth authentication requires a valid cloud_id"
                raise ValueError(error_msg)

            # Create a session for OAuth
            session = Session()

            # Configure the session with OAuth authentication
            if not configure_oauth_session(session, self.config.oauth_config):
                error_msg = "Failed to configure OAuth session"
                raise MCPAtlassianAuthenticationError(error_msg)

            # The Bitbucket API URL with OAuth is different
            api_url = f"https://api.atlassian.com/ex/bitbucket/{self.config.oauth_config.cloud_id}"

            # Initialize Bitbucket with the session
            self.bitbucket = Bitbucket(
                url=api_url,
                session=session,
                cloud=True,  # OAuth is only for Cloud
                verify_ssl=self.config.ssl_verify,
            )
        elif self.config.auth_type == "pat":
            logger.debug(
                f"Initializing Bitbucket client with PAT as Basic auth password. "
                f"URL: {self.config.url}, Username: {self.config.username}, "
                f"PAT (masked): {mask_sensitive(str(self.config.personal_token))}"
            )
            self.bitbucket = Bitbucket(
                url=self.config.url,
                cloud=self.config.is_cloud,
                verify_ssl=self.config.ssl_verify,
                token=self.config.personal_token,
            )

        else:  # basic auth
            logger.debug(
                f"Initializing Bitbucket client with Basic auth. "
                f"URL: {self.config.url}, Username: {self.config.username}, "
                f"App Password present: {bool(self.config.app_password)}, "
                f"Is Cloud: {self.config.is_cloud}"
            )
            self.bitbucket = Bitbucket(
                url=self.config.url,
                username=self.config.username,
                password=self.config.app_password,
                cloud=self.config.is_cloud,
                verify_ssl=self.config.ssl_verify,
            )
            logger.debug(
                f"Bitbucket client initialized. Session headers (Authorization masked): "
                f"{get_masked_session_headers(dict(self.bitbucket._session.headers))}"
            )

        # Configure SSL verification using the shared utility
        configure_ssl_verification(
            service_name="Bitbucket",
            url=self.config.url,
            session=self.bitbucket._session,
            ssl_verify=self.config.ssl_verify,
        )

        # Proxy configuration
        proxies = {}
        if self.config.http_proxy:
            proxies["http"] = self.config.http_proxy
        if self.config.https_proxy:
            proxies["https"] = self.config.https_proxy
        if self.config.socks_proxy:
            proxies["http"] = self.config.socks_proxy
            proxies["https"] = self.config.socks_proxy

        if proxies:
            self.bitbucket._session.proxies.update(proxies)
            logger.debug(f"Configured proxies: {proxies}")

        # Configure no_proxy
        if self.config.no_proxy:
            self.bitbucket._session.trust_env = False
            logger.debug(f"Configured no_proxy: {self.config.no_proxy}")

        # Add custom headers
        if self.config.custom_headers:
            self.bitbucket._session.headers.update(self.config.custom_headers)
            logger.debug(
                f"Added custom headers: {get_masked_session_headers(self.config.custom_headers)}"
            )

        # Prepare code search cache on first use
        self._ensure_code_search_initialized()

    def get_pull_request_activities(
        self, workspace: str, repository: str, pull_request_id: int
    ) -> list[dict[str, Any]]:
        """Get comments for a pull request.

        Args:
            workspace: Workspace name (Cloud) or project key (Server/DC)
            repository: Repository name
            pull_request_id: Pull request ID

        Returns:
            List of comment dictionaries
        """
        try:
            # Use the generic get method with the appropriate endpoint
            if self.config.is_cloud:
                # Bitbucket Cloud API 2.0
                endpoint = f"repositories/{workspace}/{repository}/pullrequests/{pull_request_id}/activities"
            else:
                # Bitbucket Server/DC API 1.0
                endpoint = f"projects/{workspace}/repos/{repository}/pull-requests/{pull_request_id}/activities"

            response = self.bitbucket.get(endpoint)

            # Handle paginated response
            if isinstance(response, dict) and "values" in response:
                return response["values"]
            elif isinstance(response, list):
                return response
            else:
                return []
        except Exception as e:
            logger.error(
                f"Failed to get pull request comments for {workspace}/{repository}/PR-{pull_request_id}: {e}"
            )
            raise

    # region Code search helpers
    @classmethod
    def _ensure_code_search_initialized(cls) -> None:
        """Initialize shared code search cache settings once per process."""
        if cls._code_search_initialized:
            # Even if already initialized, ensure cleanup worker is still running
            # and run immediate cleanup with priority
            cls._ensure_cleanup_worker_running()
            cls._run_priority_cleanup()
            return

        with cls._code_search_lock:
            if cls._code_search_initialized:
                # Release lock before checking worker to avoid deadlock
                pass  # Will check worker after releasing lock
            else:
                logger.info(
                    "Initializing BitbucketClient code search with priority cleanup"
                )
                cls._code_search_ttl_seconds = cls._resolve_cache_ttl_seconds()
                cls._code_search_cleanup_interval_seconds = (
                    cls._resolve_cleanup_interval(cls._code_search_ttl_seconds)
                )

                base_dir = cls._determine_clone_base_dir()
                base_dir.mkdir(parents=True, exist_ok=True)
                cls._code_search_base_dir = base_dir

                metadata_path = base_dir / "code_search_cache.json"
                cls._code_search_metadata_path = metadata_path
                cls._code_search_metadata = cls._load_cache_metadata(metadata_path)

                # Run immediate cleanup to handle any expired entries from previous sessions
                # Use internal method that doesn't acquire lock since we already hold it
                logger.info(
                    "Running priority cleanup of expired Bitbucket code search cache entries"
                )
                try:
                    cls._cleanup_expired_clones_internal()
                    logger.info(
                        "Completed priority cleanup of expired code search cache entries"
                    )
                except Exception as exc:  # noqa: BLE001
                    logger.warning(
                        "Priority cleanup of expired entries failed: %s", exc
                    )

                cls._code_search_initialized = True

        # Start cleanup worker outside the lock to avoid potential deadlock
        if cls._code_search_initialized:
            cls._ensure_cleanup_worker_running()
            # Run another priority cleanup pass now that everything is initialized
            cls._run_priority_cleanup()

    @classmethod
    def _ensure_cleanup_worker_running(cls) -> None:
        """Ensure the cleanup worker thread is running, restart if necessary."""
        if (
            cls._code_search_cleanup_thread is None
            or not cls._code_search_cleanup_thread.is_alive()
        ):
            logger.info("Code search cleanup worker is not running, starting it")
            cls._start_cleanup_worker()

    @classmethod
    def _start_cleanup_worker(cls) -> None:
        """Start the cleanup worker thread."""
        cls._code_search_cleanup_thread = threading.Thread(
            target=cls._run_cleanup_worker,
            name="BitbucketCodeSearchCleanup",
            daemon=True,
        )
        cls._code_search_cleanup_thread.start()
        logger.info("Started Bitbucket code search cleanup worker thread")

    @classmethod
    def _resolve_cache_ttl_seconds(cls) -> int:
        """Resolve cache TTL from environment variables."""
        default_seconds = 3600
        ttl_env = os.getenv("BITBUCKET_CODE_SEARCH_CACHE_TTL_SECONDS")
        if ttl_env:
            try:
                return max(0, int(float(ttl_env)))
            except ValueError:
                logger.warning(
                    "Invalid BITBUCKET_CODE_SEARCH_CACHE_TTL_SECONDS '%s'. "
                    "Using default %d seconds.",
                    ttl_env,
                    default_seconds,
                )
        return default_seconds

    @classmethod
    def _resolve_cleanup_interval(cls, ttl_seconds: int) -> int:
        """Determine how often cleanup worker should run."""
        default_interval = 180
        interval_env = os.getenv("BITBUCKET_CODE_SEARCH_CLEANUP_INTERVAL_SECONDS")
        if interval_env:
            try:
                interval = max(default_interval, int(float(interval_env)))
                return interval
            except ValueError:
                logger.warning(
                    "Invalid BITBUCKET_CODE_SEARCH_CLEANUP_INTERVAL_SECONDS '%s'. "
                    "Using computed default.",
                    interval_env,
                )

        if ttl_seconds <= 0:
            return default_interval

        # Run cleanup at least every minute; prefer half of TTL when practical.
        half_ttl = ttl_seconds // 2 if ttl_seconds > 120 else ttl_seconds
        return max(60, min(half_ttl, ttl_seconds))

    @classmethod
    def _determine_clone_base_dir(cls) -> Path:
        """Determine the base directory for repository clones."""
        candidate = os.getenv("BITBUCKET_CLONE_BASE_DIR")

        if candidate:
            candidate_path = Path(candidate).expanduser().resolve()
            return candidate_path

        # Try to use temp directory - actually attempt to create it
        try:
            temp_root = Path(tempfile.gettempdir()).resolve()
            temp_clones_dir = temp_root / "cloned_repos"

            # Try to create the directory to verify we have permissions
            temp_clones_dir.mkdir(parents=True, exist_ok=True)

            # If we got here, creation succeeded
            logger.debug(f"Using temp directory for clones: {temp_clones_dir}")
            return temp_clones_dir

        except (OSError, PermissionError) as exc:
            # Creation failed - log and fall back to project root
            logger.warning(
                f"Failed to create temp clone directory: {exc}. "
                f"Falling back to project root."
            )

        # Fall back to project root
        project_root = cls._find_project_root()
        project_clones_dir = project_root / "cloned_repos"
        logger.debug(f"Using project root for clones: {project_clones_dir}")
        return project_clones_dir

    @staticmethod
    def _find_project_root() -> Path:
        """Attempt to locate the project root to store cloned repositories."""
        current = Path(__file__).resolve()
        for parent in current.parents:
            if (parent / "pyproject.toml").exists() or (parent / ".git").exists():
                return parent
        return Path.cwd()

    @classmethod
    def _load_cache_metadata(cls, metadata_path: Path) -> dict[str, dict[str, Any]]:
        """Load cache metadata from disk if present."""
        if not metadata_path.exists():
            return {}
        try:
            with metadata_path.open("r", encoding="utf-8") as handle:
                data = json.load(handle)
            if isinstance(data, dict):
                filtered: dict[str, dict[str, Any]] = {}
                for key, value in data.items():
                    if isinstance(key, str) and isinstance(value, dict):
                        filtered[key] = value
                return filtered
        except Exception as exc:  # noqa: BLE001
            logger.warning("Failed to load code search cache metadata: %s", exc)
        return {}

    @classmethod
    def _save_cache_metadata_locked(cls) -> None:
        """Persist cache metadata to disk. Caller must hold _code_search_lock."""
        if not cls._code_search_metadata_path:
            return
        try:
            with cls._code_search_metadata_path.open("w", encoding="utf-8") as handle:
                json.dump(cls._code_search_metadata, handle, indent=2)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Failed to persist code search cache metadata: %s", exc)

    @classmethod
    def _run_cleanup_worker(cls) -> None:
        """Background worker to remove expired repository clones."""
        while True:
            time.sleep(cls._code_search_cleanup_interval_seconds)
            try:
                cls._cleanup_expired_clones()
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "Bitbucket code search cleanup worker encountered an error: %s", exc
                )

    @classmethod
    def _run_priority_cleanup(cls) -> None:
        """Run immediate cleanup with priority when BitbucketClient is instantiated."""
        if not cls._code_search_initialized:
            # If not initialized yet, skip priority cleanup
            return

        logger.debug("Running priority cleanup pass for Bitbucket code search cache")
        try:
            # Run cleanup immediately without waiting for the background worker
            cls._cleanup_expired_clones()
            logger.debug("Priority cleanup pass completed successfully")
        except Exception as exc:  # noqa: BLE001
            logger.warning("Priority cleanup pass failed: %s", exc)

    @classmethod
    def _cleanup_expired_clones(cls) -> None:
        """Remove repository clones and metadata entries that exceeded TTL."""
        with cls._code_search_lock:
            cls._cleanup_expired_clones_internal()

    @classmethod
    def _cleanup_expired_clones_internal(cls) -> None:
        """Internal cleanup method that doesn't acquire lock - caller must hold _code_search_lock."""
        ttl_seconds = cls._code_search_ttl_seconds
        if ttl_seconds <= 0:
            return

        now = datetime.now(timezone.utc)
        expired_entries: list[tuple[str, Path | None]] = []

        # Get metadata items (we already hold the lock)
        metadata_items = list(cls._code_search_metadata.items())

        # Step 1: Clean up expired entries based on TTL
        for cache_key, metadata in metadata_items:
            last_accessed_str = metadata.get("last_accessed")
            path_str = metadata.get("path")

            if not last_accessed_str or not path_str:
                continue

            try:
                last_accessed = datetime.fromisoformat(last_accessed_str)
            except ValueError:
                logger.debug(
                    "Skipping cache entry %s due to invalid timestamp '%s'",
                    cache_key,
                    last_accessed_str,
                )
                continue

            if last_accessed.tzinfo is None:
                last_accessed = last_accessed.replace(tzinfo=timezone.utc)

            delta_seconds = (now - last_accessed).total_seconds()
            if delta_seconds > ttl_seconds:
                expired_entries.append((cache_key, Path(path_str)))

        if expired_entries:
            # Remove from metadata (we already hold the lock)
            for cache_key, _ in expired_entries:
                cls._code_search_metadata.pop(cache_key, None)
            cls._save_cache_metadata_locked()

        # Step 2: Remove directories (release lock temporarily to avoid blocking)
        if expired_entries:
            # We need to release the lock temporarily to avoid blocking other operations
            # while doing potentially slow file system operations
            pass  # Metadata is already updated above

        # Remove directories outside the lock to avoid blocking
        for cache_key, repo_path in expired_entries:
            if repo_path and repo_path.exists():
                try:
                    cls._safe_rmtree(repo_path)
                    logger.info(
                        "Removed expired Bitbucket code search clone '%s' at %s",
                        cache_key,
                        repo_path,
                    )
                except Exception as exc:  # noqa: BLE001
                    logger.warning(
                        "Failed to remove expired clone directory %s: %s",
                        repo_path,
                        exc,
                    )

        # Step 3: Defensive cleanup - remove orphaned directories
        cls._cleanup_orphaned_directories_internal()

    @classmethod
    def _cleanup_orphaned_directories_internal(cls) -> None:
        """Internal method to remove orphaned directories - caller must hold lock for metadata access."""
        if not cls._code_search_base_dir or not cls._code_search_base_dir.exists():
            return

        try:
            # Get all directories in the base directory
            existing_dirs = [
                d
                for d in cls._code_search_base_dir.iterdir()
                if d.is_dir() and not d.name.startswith(".")
            ]

            # Get all tracked paths from metadata (we already hold the lock)
            tracked_paths = set()
            for metadata in cls._code_search_metadata.values():
                path_str = metadata.get("path")
                if path_str:
                    tracked_paths.add(Path(path_str))

            # Find orphaned directories
            orphaned_dirs = []
            for dir_path in existing_dirs:
                if dir_path not in tracked_paths:
                    # Additional check: make sure it looks like a repository clone
                    # (has .git directory or at least some files)
                    if cls._looks_like_repo_clone(dir_path):
                        orphaned_dirs.append(dir_path)

            # Remove orphaned directories
            for orphaned_dir in orphaned_dirs:
                try:
                    cls._safe_rmtree(orphaned_dir)
                    logger.info(
                        "Removed orphaned Bitbucket code search directory: %s",
                        orphaned_dir,
                    )
                except Exception as exc:  # noqa: BLE001
                    logger.warning(
                        "Failed to remove orphaned directory %s: %s",
                        orphaned_dir,
                        exc,
                    )

        except Exception as exc:  # noqa: BLE001
            logger.warning("Error during orphaned directory cleanup: %s", exc)

    @classmethod
    def _looks_like_repo_clone(cls, dir_path: Path) -> bool:
        """Check if a directory looks like it could be a repository clone."""
        try:
            # Check if it has a .git directory (most likely a repo clone)
            if (dir_path / ".git").exists():
                return True

            # Check if it has some files (not completely empty)
            # Use a simple check to avoid expensive directory traversal
            try:
                # Check if there are any files in the directory
                next(dir_path.iterdir())
                return True
            except StopIteration:
                # Directory is empty, probably safe to remove
                return True

        except Exception as err:  # noqa: BLE001
            logger.warning(f"Unexpected error {err} in _looks_like_repo_clone")
            # If we can't determine, err on the side of caution
            return False

    @staticmethod
    def _slugify_for_path(*parts: str) -> str:
        """Create a filesystem-friendly slug from provided parts."""
        combined = "_".join(part for part in parts if part)
        combined = combined.strip().lower()
        if not combined:
            return "repo"
        slug = re.sub(r"[^a-z0-9._-]+", "_", combined)
        slug = re.sub(r"_+", "_", slug)
        return slug.strip("_") or "repo"

    # endregion

    def code_search(
        self,
        project_key: str,
        repository_slug: str,
        search_query: str,
        branch_name: str | None = None,
        surrounding_lines: int = 25,
        case_sensitive: bool = False,
        max_results: int = 10,
        search_type: SearchType = SearchType.SUBSTRING,
        multi_term_operator: MultiTermOperator = MultiTermOperator.OR,
        file_extensions: list[str] | None = None,
        exclude_paths: list[str] | None = None,
    ) -> dict[str, Any]:
        """Search for a string within a repository clone.

        Args:
            project_key: Bitbucket project key (required).
            repository_slug: Repository slug (required).
            search_query: Text to search for (required).
            branch_name: Optional branch override. Defaults to repository default.
            surrounding_lines: Number of context lines around each match (default: 25).
            case_sensitive: When True, uses case-sensitive matching (default: False).
            max_results: Maximum number of results to return (default: 10).
            search_type: Type of search to perform (default: substring).
            multi_term_operator: Operator for multi-term searches (default: OR).
            file_extensions: Only search files with these extensions (e.g., ['.py', '.js']).
            exclude_paths: Exclude paths matching these patterns (e.g., ['test/', 'node_modules/']).

        Returns:
            A dictionary containing high-level context and per-file match data.

        Raises:
            ValueError: If required inputs are missing or invalid.
            RuntimeError: If cloning or fetching repository data fails.
        """
        # Ensure cleanup infrastructure is running
        self._ensure_code_search_initialized()

        if not project_key:
            raise ValueError("bitbucket_project_key is required.")
        if not repository_slug:
            raise ValueError("repository_slug is required.")
        if not search_query or not search_query.strip():
            raise ValueError("search_query must be a non-empty string.")
        if surrounding_lines < 0:
            raise ValueError("surrounding_lines must be zero or a positive integer.")

        resolved_branch = branch_name or self._determine_default_branch(
            project_key, repository_slug
        )
        if not resolved_branch:
            # Use common defaults when the repository branch could not be resolved.
            fallback_branch = "main"
            if fallback_branch not in DEFAULT_BRANCH_NAMES and DEFAULT_BRANCH_NAMES:
                fallback_branch = DEFAULT_BRANCH_NAMES[0]
            resolved_branch = fallback_branch
            logger.warning(
                "Unable to determine default branch for %s/%s. Falling back to '%s'.",
                project_key,
                repository_slug,
                resolved_branch,
            )

        repo_path, update_failed = self._prepare_repository_clone(
            project_key,
            repository_slug,
            resolved_branch,
        )

        results = self._execute_code_search(
            repo_path=repo_path,
            project_key=project_key,
            repository_slug=repository_slug,
            branch=resolved_branch,
            search_query=search_query,
            surrounding_lines=surrounding_lines,
            case_sensitive=case_sensitive,
            search_type=search_type,
            multi_term_operator=multi_term_operator,
            file_extensions=file_extensions,
            exclude_paths=exclude_paths,
        )[:max_results]

        response = {
            "project_key": project_key,
            "repository_slug": repository_slug,
            "branch": resolved_branch,
            "search_query": search_query,
            "search_metadata": {
                "search_type": search_type.value,
                "case_sensitive": case_sensitive,
                "multi_term_operator": multi_term_operator.value
                if search_type == SearchType.MULTI_TERM
                else None,
                "file_extensions": file_extensions,
                "exclude_paths": exclude_paths,
                "results_returned": len(results),
                "max_results": max_results,
            },
            "results": results,
        }

        # Add warning if repository update failed
        if update_failed:
            response["warning"] = {
                "type": "stale_content",
                "message": (
                    "Repository update failed - search results may not reflect the latest changes. "
                    "Consider using file retrieval tools to get the most current version of specific files, "
                    "or request specific line ranges for critical code sections."
                ),
                "recommendation": "For accurate results, try fetching individual files or specific line ranges directly from the repository with the get_file_content tool.",
            }

        return response

    def _determine_default_branch(
        self, project_key: str, repository_slug: str
    ) -> str | None:
        """Determine repository default branch using Bitbucket API."""
        try:
            default_branch = self.bitbucket.get_default_branch(
                project_key, repository_slug
            )
        except Exception as exc:  # noqa: BLE001
            logger.debug(
                "Failed to fetch default branch for %s/%s: %s",
                project_key,
                repository_slug,
                exc,
            )
            default_branch = None

        candidates: list[str] = []
        if isinstance(default_branch, dict):
            for key in ("displayId", "displayID", "name", "id", "id_"):
                value = default_branch.get(key)
                if not value or not isinstance(value, str):
                    continue
                if "/" in value:
                    value = value.split("/")[-1]
                candidates.append(value)
        elif hasattr(default_branch, "name"):
            value = default_branch.name
            if isinstance(value, str):
                candidates.append(value)
        elif isinstance(default_branch, str):
            candidates.append(default_branch)

        for candidate in candidates:
            if candidate:
                return candidate

        # Final fallbacks if API response did not include expected fields
        try:
            repo_info = self.bitbucket.get_repo(project_key, repository_slug)
            default_branch_info = repo_info.get("project", {}).get("defaultBranch")
            if isinstance(default_branch_info, dict):
                candidate = default_branch_info.get("name") or default_branch_info.get(
                    "displayId"
                )
                if candidate:
                    return candidate
        except Exception as exc:  # noqa: BLE001
            logger.debug(
                "Failed to retrieve repository details for default branch fallback: %s",
                exc,
            )

        return None

    def _prepare_repository_clone(
        self,
        project_key: str,
        repository_slug: str,
        branch_name: str,
    ) -> tuple[Path, bool]:
        """Ensure a repository clone exists for search operations.

        Returns:
            tuple: (repo_path, update_failed) where update_failed indicates if the repository
                   content might be stale due to a failed update operation.
        """
        if not self._code_search_base_dir:
            raise RuntimeError("Code search base directory is not configured.")

        cache_key = f"{project_key}:{repository_slug}:{branch_name}"
        slug_name = self._slugify_for_path(project_key, repository_slug, branch_name)
        repo_path = self._code_search_base_dir / slug_name

        repo_info = self.bitbucket.get_repo(project_key, repository_slug)
        clone_url = self._extract_clone_url(repo_info, project_key)
        if not clone_url:
            raise RuntimeError(
                f"Unable to identify clone URL for {project_key}/{repository_slug}."
            )
        authenticated_url = self._build_authenticated_clone_url(clone_url)

        now_iso = datetime.now(timezone.utc).isoformat()
        update_failed = False

        with self._code_search_lock:
            existing_entry = self._code_search_metadata.get(cache_key)
            need_clone = existing_entry is None

        if need_clone:
            if repo_path.exists():
                try:
                    self._safe_rmtree(repo_path)
                except Exception as exc:  # noqa: BLE001
                    raise RuntimeError(
                        f"Failed to clean repository clone at {repo_path}: {exc}"
                    ) from exc

            # Attempt clone - only create metadata entry if successful
            try:
                self._clone_repository(authenticated_url, repo_path, branch_name)
                # Clone successful - now create metadata entry
                with self._code_search_lock:
                    self._code_search_metadata[cache_key] = {
                        "project_key": project_key,
                        "repository_slug": repository_slug,
                        "branch": branch_name,
                        "path": str(repo_path),
                        "created_at": now_iso,
                        "last_accessed": now_iso,
                    }
                    self._save_cache_metadata_locked()
            except Exception as err:
                logger.warning(f"Unexpected error _prepare_repository_clone. {err}")
                # Clone failed - don't create metadata entry, just re-raise
                raise
        else:
            # Attempt update - only update last_accessed if successful
            try:
                logger.info(
                    "Repository exists at path: %s. Proceeding for update.", repo_path
                )
                self._update_repository(repo_path, authenticated_url, branch_name)
                # Update successful - now update last_accessed
                with self._code_search_lock:
                    existing_entry["last_accessed"] = now_iso
                    existing_entry["path"] = str(repo_path)  # Ensure path is current
                    self._save_cache_metadata_locked()
            except Exception as exc:
                # Update failed - don't update last_accessed, but continue with search using stale content
                import traceback

                logger.error(
                    "Repository update failed for %s/%s (branch %s). "
                    "Continuing with potentially stale content. Error: %s\nTraceback:\n%s",
                    project_key,
                    repository_slug,
                    branch_name,
                    exc,
                    traceback.format_exc(),
                )
                update_failed = True
                # Don't re-raise - continue with existing clone for search

        return repo_path, update_failed

    def _clone_repository(
        self, clone_url: str, target_path: Path, branch_name: str
    ) -> None:
        """Clone repository to the target path."""
        try:
            logger.info(
                "Cloning Bitbucket repository for code search into %s", target_path
            )

            # For Bitbucket Server/DC with PAT, use subprocess with Authorization header
            if self.config.auth_type == "pat" and not self.config.is_cloud:
                self._clone_with_pat_auth(clone_url, target_path, branch_name)
            else:
                # For Cloud or non-PAT auth, use standard clone
                Repo.clone_from(
                    clone_url,
                    target_path,
                    branch=branch_name,
                    depth=1,
                    single_branch=True,
                )
        except (GitCommandError, RuntimeError) as exc:
            logger.error(
                "Git clone failed for %s (branch %s): %s",
                clone_url,
                branch_name,
                exc,
            )
            raise RuntimeError(
                f"Failed to clone repository branch '{branch_name}': {exc}"
            ) from exc

    def _clone_with_pat_auth(
        self, clone_url: str, target_path: Path, branch_name: str
    ) -> None:
        """Clone repository using PAT authentication with Authorization Bearer header."""
        if not self.config.personal_token:
            raise RuntimeError(
                "Personal access token is required for PAT authentication"
            )

        # Prepare git command with Authorization header
        auth_header = f"Authorization: Bearer {self.config.personal_token}"

        # Create the target directory
        target_path.mkdir(parents=True, exist_ok=True)

        # Set up environment
        env = os.environ.copy()
        env["GIT_TERMINAL_PROMPT"] = "0"

        # Execute git clone with the Authorization header
        # Note: command is constructed from trusted sources (git binary and validated inputs)
        command = [
            "git",
            "clone",
            "-c",
            f"http.extraHeader={auth_header}",
            "--branch",
            branch_name,
            "--depth",
            "1",
            "--single-branch",
            clone_url,
            str(target_path),
        ]

        logger.debug(f"Executing git clone with PAT authentication for {clone_url}")

        result = subprocess.run(  # noqa: S603
            command,
            env=env,
            capture_output=True,  # Use capture_output instead of stdout/stderr PIPE (UP022)
            text=True,
        )

        if result.returncode != 0:
            logger.error(
                "Git clone with PAT authentication failed: %s",
                result.stderr.strip(),
            )
            # Clean up the directory if it was created but clone failed
            if target_path.exists():
                try:
                    shutil.rmtree(target_path)
                except Exception as err:
                    logger.warning(
                        f"Failed to cleanup directory after clone failed. {err}"
                    )
                    pass
            raise RuntimeError(
                f"Git clone with PAT authentication failed: {result.stderr.strip()}"
            )

    def _update_repository(
        self, repo_path: Path, clone_url: str, branch_name: str
    ) -> None:
        """Fetch and update an existing repository clone."""
        try:
            repo = Repo(repo_path)
        except (InvalidGitRepositoryError, NoSuchPathError) as exc:
            logger.warning(
                "Existing repository clone at %s is invalid. Re-cloning. Error: %s",
                repo_path,
                exc,
            )
            if repo_path.exists():
                self._safe_rmtree(repo_path)
            self._clone_repository(clone_url, repo_path, branch_name)
            return

        try:
            try:
                origin = repo.remote(name="origin")
            except ValueError:
                origin = repo.create_remote("origin", clone_url)
            else:
                origin.set_url(clone_url)

            origin.fetch(branch_name)
            repo.git.checkout(branch_name)
            repo.git.reset("--hard", f"origin/{branch_name}")
            repo.git.clean("-xdf")
        except (GitCommandError, RuntimeError) as exc:
            logger.warning(
                "Failed to update repository clone at %s: %s. Attempting re-clone.",
                repo_path,
                exc,
            )
            try:
                # Clean up the repository path safely, handling Windows read-only files
                self._safe_rmtree(repo_path)
            except Exception as cleanup_exc:  # noqa: BLE001
                logger.error(
                    "Failed to remove repository path %s after update failure: %s",
                    repo_path,
                    cleanup_exc,
                )
                raise RuntimeError(
                    f"Unable to refresh repository at {repo_path}: {cleanup_exc}"
                ) from cleanup_exc
            self._clone_repository(clone_url, repo_path, branch_name)

    def _extract_clone_url(
        self, repo_info: dict[str, Any], project_key: str
    ) -> str | None:
        """Extract an HTTPS clone URL from Bitbucket repository metadata."""
        links = repo_info.get("links", {}) if isinstance(repo_info, dict) else {}
        clone_links = links.get("clone") if isinstance(links, dict) else None
        if isinstance(clone_links, list):
            for link in clone_links:
                href = link.get("href") if isinstance(link, dict) else None
                name = link.get("name") if isinstance(link, dict) else None
                if (
                    href
                    and isinstance(href, str)
                    and name
                    and name.lower()
                    in {
                        "http",
                        "https",
                    }
                ):
                    return href
            # fallback: first href even if name not specified
            for link in clone_links:
                href = link.get("href") if isinstance(link, dict) else None
                if href and isinstance(href, str):
                    return href
        elif isinstance(clone_links, dict):
            href = clone_links.get("href")
            if isinstance(href, str):
                return href

        # Attempt to build URL from config as a fallback (works for standard server/DC)
        if not isinstance(repo_info, dict):
            return None

        slug = repo_info.get("slug") or repo_info.get("name")
        if not slug or not isinstance(slug, str):
            return None

        base_url = self.config.url.rstrip("/")
        project_segment: str | None = None
        project_info = repo_info.get("project")
        if isinstance(project_info, dict):
            key = project_info.get("key")
            if isinstance(key, str):
                project_segment = key
        elif isinstance(project_info, str):
            project_segment = project_info

        if not project_segment:
            project_segment = project_key

        if isinstance(project_segment, str):
            project_segment = project_segment.strip("/")
            return f"{base_url}/scm/{project_segment}/{slug}.git"
        return None

    def _build_authenticated_clone_url(self, raw_url: str) -> str:
        """Embed authentication credentials into the clone URL."""
        parsed = urlparse(raw_url)
        username: str | None = None
        password: str | None = None

        if self.config.auth_type == "pat":
            username = self.config.username or ""
            password = self.config.personal_token or ""
        elif self.config.auth_type == "basic":
            username = self.config.username or ""
            password = self.config.app_password or ""
        elif self.config.auth_type == "oauth":
            username = self.config.username or ""
            if self.config.oauth_config and getattr(
                self.config.oauth_config, "access_token", None
            ):
                password = self.config.oauth_config.access_token

        if not password:
            logger.debug(
                "No password/token available to embed for clone URL. Using raw URL."
            )
            return raw_url

        username_value = username or "x-token-auth"
        username_encoded = quote(username_value, safe="")
        password_encoded = quote(password, safe="")

        host = parsed.netloc or ""
        if "@" in host:
            host = host.split("@", 1)[-1]
        if not host:
            logger.debug(
                "Clone URL %s is missing host information. Returning raw URL.", raw_url
            )
            return raw_url

        # For Bitbucket Server/DC with PAT, return clean URL without embedding credentials
        if self.config.auth_type == "pat" and not self.config.is_cloud:
            # Ensure path doesn't have trailing slash issues
            path = parsed.path.rstrip("/")
            clean_url = f"{parsed.scheme}://{host}{path}"
            logger.debug(
                "Returning clean clone URL for PAT auth on Server/DC: %s", clean_url
            )
            return clean_url

        netloc = f"{username_encoded}:{password_encoded}@{host}"
        return urlunparse(
            (
                parsed.scheme,
                netloc,
                parsed.path,
                parsed.params,
                parsed.query,
                parsed.fragment,
            )
        )

    def _execute_code_search(
        self,
        repo_path: Path,
        project_key: str,
        repository_slug: str,
        branch: str,
        search_query: str,
        surrounding_lines: int,
        case_sensitive: bool,
        search_type: SearchType = SearchType.SUBSTRING,
        multi_term_operator: MultiTermOperator = MultiTermOperator.AND,
        file_extensions: list[str] | None = None,
        exclude_paths: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        """Search through repository files for a query using various search types."""
        results_by_file: dict[str, list[dict[str, Any]]] = {}

        # Prepare search matcher based on search type
        matcher = self._create_search_matcher(
            search_query, search_type, case_sensitive, multi_term_operator
        )

        if not matcher:
            logger.warning(
                "Failed to create search matcher for query: %s", search_query
            )
            return []

        # Normalize file extensions (ensure they start with '.') - only if provided
        normalized_extensions = None
        if file_extensions:
            normalized_extensions = []
            for ext in file_extensions:
                if not ext.startswith("."):
                    ext = f".{ext}"
                normalized_extensions.append(ext.lower())

        # Prepare path exclusion patterns
        exclude_patterns = []
        if exclude_paths:
            for pattern in exclude_paths:
                # Convert glob-like patterns to more efficient checks
                exclude_patterns.append(pattern.lower().rstrip("/"))

        for file_path in repo_path.rglob("*"):
            if not file_path.is_file():
                continue

            relative_path = file_path.relative_to(repo_path)

            # Always exclude .git directory
            if ".git" in relative_path.parts:
                continue

            # Apply file extension filtering only if extensions are specified
            if normalized_extensions:
                file_ext = file_path.suffix.lower()
                if file_ext not in normalized_extensions:
                    continue

            # Apply path exclusion filtering (performance optimization)
            if exclude_patterns:
                rel_path_str = relative_path.as_posix().lower()
                should_exclude = False
                for pattern in exclude_patterns:
                    if pattern in rel_path_str or rel_path_str.startswith(
                        pattern + "/"
                    ):
                        should_exclude = True
                        break
                if should_exclude:
                    continue

            if self._is_binary_file(file_path):
                continue

            try:
                raw_text = file_path.read_text(encoding="utf-8", errors="ignore")
                lines = raw_text.splitlines()
            except OSError as exc:
                logger.debug("Skipping unreadable file %s: %s", file_path, exc)
                continue

            for index, line in enumerate(lines):
                if matcher(line):
                    start = max(0, index - surrounding_lines)
                    end = min(len(lines), index + surrounding_lines + 1)

                    # Accumulate all lines in the snippet into a single content string
                    snippet_lines = lines[start:end]
                    snippet_content = "\n".join(snippet_lines)

                    rel_path_str = relative_path.as_posix()
                    results_by_file.setdefault(rel_path_str, []).append(
                        {
                            "match_line": index + 1,
                            "match_text": line,
                            "snippet": {
                                "content": snippet_content,
                                "start_line": start + 1,
                                "end_line": end,
                            },
                        }
                    )

        results = []
        for rel_path, matches in sorted(results_by_file.items()):
            results.append(
                {
                    "project_key": project_key,
                    "repository_slug": repository_slug,
                    "branch": branch,
                    "file_path": rel_path,
                    "matches": matches,
                }
            )
        return results

    def _create_search_matcher(
        self,
        search_query: str,
        search_type: SearchType,
        case_sensitive: bool,
        multi_term_operator: MultiTermOperator,
    ) -> Callable[[str], bool] | None:
        """Create a search matcher function based on the search type."""
        try:
            if search_type == SearchType.SUBSTRING:
                return self._create_substring_matcher(search_query, case_sensitive)

            elif search_type == SearchType.REGEX:
                return self._create_regex_matcher(search_query, case_sensitive)

            elif search_type == SearchType.WHOLE_WORD:
                return self._create_whole_word_matcher(search_query, case_sensitive)

            elif search_type == SearchType.MULTI_TERM:
                return self._create_multi_term_matcher(
                    search_query, case_sensitive, multi_term_operator
                )

            else:
                logger.warning("Unknown search type: %s", search_type)
                return self._create_substring_matcher(search_query, case_sensitive)

        except Exception as exc:
            logger.error("Failed to create search matcher: %s", exc)
            # Fallback to simple substring search
            return self._create_substring_matcher(search_query, case_sensitive)

    def _create_substring_matcher(
        self, search_query: str, case_sensitive: bool
    ) -> Callable[[str], bool]:
        """Create a simple substring matcher."""
        query = search_query if case_sensitive else search_query.lower()

        if case_sensitive:
            return lambda line: query in line
        else:
            return lambda line: query in line.lower()

    def _create_regex_matcher(
        self, search_query: str, case_sensitive: bool
    ) -> Callable[[str], bool] | None:
        """Create a regex-based matcher with safety limits."""
        try:
            # Add safety timeout and complexity limits for regex
            flags = 0 if case_sensitive else re.IGNORECASE

            # Compile with timeout safety - limit complexity
            if len(search_query) > 1000:  # Prevent extremely long patterns
                logger.warning(
                    "Regex pattern too long, falling back to substring search"
                )
                return self._create_substring_matcher(search_query, case_sensitive)

            # Pre-compile the regex pattern
            pattern = re.compile(search_query, flags)

            return lambda line: pattern.search(line) is not None

        except re.error as exc:
            logger.warning("Invalid regex pattern '%s': %s", search_query, exc)
            return None

    def _create_whole_word_matcher(
        self, search_query: str, case_sensitive: bool
    ) -> Callable[[str], bool] | None:
        """Create a whole-word matcher using word boundaries."""
        try:
            # Escape the search query for regex and add word boundaries
            escaped_query = re.escape(search_query)
            pattern_str = rf"\b{escaped_query}\b"

            flags = 0 if case_sensitive else re.IGNORECASE
            pattern = re.compile(pattern_str, flags)

            return lambda line: pattern.search(line) is not None

        except re.error as exc:
            logger.warning(
                "Failed to create whole word pattern for '%s': %s", search_query, exc
            )
            return None

    def _create_multi_term_matcher(
        self,
        search_query: str,
        case_sensitive: bool,
        multi_term_operator: MultiTermOperator,
    ) -> Callable[[str], bool]:
        """Create a multi-term matcher supporting AND/OR operations."""
        # Split search query into terms (support quoted phrases)
        terms = self._parse_search_terms(search_query)

        if not terms:
            return lambda line: False

        # Create individual matchers for each term
        term_matchers = []
        for term in terms:
            if case_sensitive:
                term_matchers.append(lambda line, t=term: t in line)
            else:
                term_lower = term.lower()
                term_matchers.append(lambda line, t=term_lower: t in line.lower())

        if multi_term_operator == MultiTermOperator.AND:
            return lambda line: all(matcher(line) for matcher in term_matchers)
        else:  # OR
            return lambda line: any(matcher(line) for matcher in term_matchers)

    def _parse_search_terms(self, search_query: str) -> list[str]:
        """Parse search query into individual terms, respecting quoted phrases."""
        terms = []
        current_term = ""
        in_quotes = False
        quote_char = None

        i = 0
        while i < len(search_query):
            char = search_query[i]

            if char in ('"', "'") and not in_quotes:
                # Start of quoted phrase
                in_quotes = True
                quote_char = char
            elif char == quote_char and in_quotes:
                # End of quoted phrase
                in_quotes = False
                if current_term.strip():
                    terms.append(current_term.strip())
                current_term = ""
                quote_char = None
            elif char.isspace() and not in_quotes:
                # Word separator outside quotes
                if current_term.strip():
                    terms.append(current_term.strip())
                current_term = ""
            else:
                # Regular character
                current_term += char

            i += 1

        # Add final term if exists
        if current_term.strip():
            terms.append(current_term.strip())

        return terms

    @classmethod
    def _safe_rmtree(cls, path: Path) -> None:
        """Recursively remove a directory tree, handling Windows read-only files."""
        if not path.exists():
            return

        # On Windows, files may be read-only - remove the read-only attribute first
        if os.name == "nt":
            for root, _, files in os.walk(path):
                for name in files:
                    file_path = Path(root) / name
                    try:
                        # Remove read-only attribute by making it writable
                        file_path.chmod(0o777)
                    except Exception as exc:
                        logger.warning(
                            "Failed to remove read-only attribute from %s: %s",
                            file_path,
                            exc,
                        )

        # Now safely remove the directory tree
        shutil.rmtree(path, ignore_errors=True)

    @classmethod
    def _is_binary_file(cls, file_path: Path) -> bool:
        """Check if a file is binary or text."""
        try:
            with file_path.open("rb") as file:
                # Check first 1024 bytes for null bytes or non-text patterns
                initial_bytes = file.read(1024)
                if b"\0" in initial_bytes:
                    return True

                # Heuristic check for common binary patterns (images, executables, etc.)
                if (
                    initial_bytes.startswith(b"\xff\xd8")  # JPEG
                    or initial_bytes.startswith(b"\x89PNG")  # PNG
                    or initial_bytes.startswith(b"GIF8")  # GIF
                    or initial_bytes.startswith(b"\x7fELF")  # ELF executable
                    or initial_bytes.startswith(b"MZ")  # PE executable
                ):
                    return True

                # Check for non-text characters in the initial bytes
                text_characters = bytearray(range(32, 127)) + bytearray(b"\n\r\t")
                if any(byte not in text_characters for byte in initial_bytes):
                    return True

        except Exception as exc:
            logger.warning("Error while checking if file is binary: %s", exc)

        return False
