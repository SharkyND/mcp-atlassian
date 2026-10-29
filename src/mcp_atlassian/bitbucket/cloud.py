"""Native Bitbucket Cloud REST API client.

The ``atlassian-python-api`` Bitbucket client primarily models the Server/Data
Center REST API.  Bitbucket Cloud has a different URL structure and response
schema, so Cloud requests are kept in this small compatibility client instead
of mixing both API dialects in the MCP operation mixins.
"""

import logging
from collections.abc import Iterator
from typing import Any
from urllib.parse import quote, urljoin, urlparse, urlunparse

from requests import Session
from requests.exceptions import HTTPError

from .constants import CLOUD_API_BASE, DEFAULT_PAGE_SIZE, MAX_FILE_SIZE_BYTES

logger = logging.getLogger("mcp-bitbucket")


class BitbucketCloudClient:
    """Synchronous client for the Bitbucket Cloud REST API 2.0."""

    def __init__(
        self,
        session: Session,
        url: str = CLOUD_API_BASE,
        timeout: float = 30.0,
        max_pages: int = 100,
    ) -> None:
        """Initialize a native Bitbucket Cloud client.

        Args:
            session: Configured requests session containing authentication.
            url: User-configured Bitbucket URL.
            timeout: Per-request timeout in seconds.
            max_pages: Safety limit for paginated operations.
        """
        self._session = session
        self.base_url = self._normalize_base_url(url)
        self.timeout = timeout
        self.max_pages = max_pages

    @staticmethod
    def _normalize_base_url(url: str) -> str:
        """Return the canonical Bitbucket Cloud API 2.0 URL."""
        if not url:
            return CLOUD_API_BASE

        parsed = urlparse(url)
        hostname = (parsed.hostname or "").lower()
        if hostname in {"bitbucket.org", "www.bitbucket.org", "api.bitbucket.org"}:
            return CLOUD_API_BASE

        # OAuth configurations created by older versions used the Atlassian
        # gateway. Bitbucket OAuth tokens are now accepted directly by the
        # canonical API, so Cloud traffic must not retain that gateway path.
        if hostname == "api.atlassian.com":
            return CLOUD_API_BASE

        return url.rstrip("/")

    @staticmethod
    def _segment(value: str | int) -> str:
        """URL-encode one path segment."""
        return quote(str(value), safe="")

    @staticmethod
    def _path(value: str) -> str:
        """URL-encode a repository path while preserving separators."""
        return quote(value.strip("/"), safe="/")

    @staticmethod
    def _sanitized_url(url: str) -> str:
        """Remove query parameters from a URL before placing it in an error."""
        parsed = urlparse(url)
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", "", ""))

    @staticmethod
    def _error_detail(response: Any) -> str:
        """Extract the useful nested Bitbucket error message."""
        try:
            payload = response.json()
        except (TypeError, ValueError):
            return str(getattr(response, "text", "")).strip()

        if not isinstance(payload, dict):
            return str(payload)
        error = payload.get("error")
        if isinstance(error, dict):
            return str(error.get("message") or error.get("detail") or error)
        return str(payload.get("message") or error or payload)

    def _request(
        self,
        method: str,
        endpoint: str,
        *,
        params: dict[str, Any] | None = None,
        json: dict[str, Any] | None = None,
        raw: bool = False,
    ) -> Any:
        """Perform one Cloud API request and return decoded data."""
        url = urljoin(self.base_url + "/", endpoint)
        parsed, base = urlparse(url), urlparse(self.base_url)
        if (
            parsed.scheme != base.scheme
            or parsed.netloc != base.netloc
            or parsed.username is not None
            or parsed.password is not None
            or not parsed.path.startswith(base.path.rstrip("/") + "/")
        ):
            raise ValueError(
                "Bitbucket pagination URL escaped the configured API origin"
            )
        response = self._session.request(
            method,
            url,
            params=params,
            json=json,
            timeout=self.timeout,
        )
        try:
            response.raise_for_status()
        except HTTPError as exc:
            detail = self._error_detail(response)
            message = (
                f"Bitbucket Cloud API {method.upper()} "
                f"{self._sanitized_url(url)} returned HTTP {response.status_code}"
            )
            if detail:
                message = f"{message}: {detail}"
            raise HTTPError(
                message,
                response=response,
                request=getattr(response, "request", None),
            ) from exc

        if raw:
            content = response.content
            if len(content) > MAX_FILE_SIZE_BYTES:
                msg = (
                    "Bitbucket file is larger than the supported "
                    f"{MAX_FILE_SIZE_BYTES}-byte limit"
                )
                raise ValueError(msg)
            return content

        if response.status_code == 204 or not response.content:
            return {}
        try:
            return response.json()
        except ValueError as exc:
            msg = (
                f"Bitbucket Cloud API returned invalid JSON for "
                f"{method.upper()} {self._sanitized_url(url)}"
            )
            raise HTTPError(msg, response=response) from exc

    def _get_paginated(
        self,
        endpoint: str,
        *,
        params: dict[str, Any] | None = None,
        limit: int | None = None,
    ) -> list[dict[str, Any]]:
        """Follow Bitbucket Cloud ``next`` links with a bounded page count."""
        values: list[dict[str, Any]] = []
        next_url: str | None = endpoint
        next_params = dict(params or {})
        next_params.setdefault("pagelen", DEFAULT_PAGE_SIZE)

        for _ in range(self.max_pages):
            if not next_url:
                break
            page = self._request("GET", next_url, params=next_params)
            next_params = {}
            if isinstance(page, list):
                page_values = page
                next_url = None
            elif isinstance(page, dict):
                page_values = page.get("values", [])
                next_url = page.get("next")
            else:
                page_values = []
                next_url = None

            values.extend(item for item in page_values if isinstance(item, dict))
            if limit is not None and len(values) >= limit:
                return values[:limit]
        else:
            logger.warning(
                "Stopped Bitbucket Cloud pagination after %s pages for %s",
                self.max_pages,
                endpoint,
            )

        return values if limit is None else values[:limit]

    def get(self, endpoint: str) -> Any:
        """Compatibility wrapper for a generic GET request."""
        return self._request("GET", endpoint)

    def project_list(self) -> list[dict[str, Any]]:
        """List workspaces visible to the authenticated principal."""
        workspace_access = self._get_paginated("user/workspaces")
        return [
            access["workspace"] if isinstance(access.get("workspace"), dict) else access
            for access in workspace_access
        ]

    def get_repositories(self, workspace: str | None = None) -> list[dict[str, Any]]:
        """List repositories for one workspace or the authenticated user."""
        if workspace:
            endpoint = f"repositories/{self._segment(workspace)}"
            return self._get_paginated(endpoint)

        repositories: list[dict[str, Any]] = []
        for workspace_data in self.project_list():
            workspace_id = workspace_data.get("slug") or workspace_data.get("uuid")
            if not workspace_id:
                logger.warning(
                    "Skipping Bitbucket workspace without a slug or UUID: %s",
                    workspace_data,
                )
                continue
            endpoint = f"repositories/{self._segment(workspace_id)}"
            repositories.extend(self._get_paginated(endpoint))
        return repositories

    def repo_list(self, workspace: str | None = None) -> Iterator[dict[str, Any]]:
        """Compatibility iterator for repository listing."""
        yield from self.get_repositories(workspace)

    def get_repo(self, workspace: str, repository: str) -> dict[str, Any]:
        """Get one repository."""
        endpoint = (
            f"repositories/{self._segment(workspace)}/{self._segment(repository)}"
        )
        return self._request("GET", endpoint)

    def get_content_of_file(
        self, workspace: str, repository: str, path: str, branch: str
    ) -> bytes:
        """Return raw file content at a branch or commit."""
        endpoint = (
            f"repositories/{self._segment(workspace)}/"
            f"{self._segment(repository)}/src/{self._segment(branch)}"
        )
        encoded_path = self._path(path)
        if encoded_path:
            endpoint = f"{endpoint}/{encoded_path}"
        return self._request("GET", endpoint, raw=True)

    def get_file_list(
        self, workspace: str, repository: str, path: str, branch: str
    ) -> list[dict[str, Any]]:
        """List entries in a repository directory."""
        endpoint = (
            f"repositories/{self._segment(workspace)}/"
            f"{self._segment(repository)}/src/{self._segment(branch)}"
        )
        encoded_path = self._path(path)
        if encoded_path:
            endpoint = f"{endpoint}/{encoded_path}"
        else:
            endpoint = f"{endpoint}/"
        return self._get_paginated(endpoint)

    def get_branches(
        self,
        workspace: str,
        repository: str,
        base: str | None = None,
        filter: str | None = None,
        start: int = 0,
        limit: int | None = None,
    ) -> list[dict[str, Any]]:
        """List repository branches using Cloud refs."""
        del base  # Server/DC-only graph traversal option.
        endpoint = (
            f"repositories/{self._segment(workspace)}/"
            f"{self._segment(repository)}/refs/branches"
        )
        fetch_limit = None if limit is None or filter else max(0, start) + max(0, limit)
        branches = self._get_paginated(endpoint, limit=fetch_limit)
        try:
            default_branch = self.get_default_branch(workspace, repository)
        except HTTPError:
            logger.warning(
                "Could not determine the default branch for %s/%s",
                workspace,
                repository,
                exc_info=True,
            )
        else:
            default_name = default_branch.get("name")
            for branch in branches:
                branch["isDefault"] = branch.get("name") == default_name
        if filter:
            branches = [
                branch
                for branch in branches
                if filter.lower() in str(branch.get("name", "")).lower()
            ]
        end = None if limit is None else max(0, start) + max(0, limit)
        return branches[max(0, start) : end]

    def get_default_branch(self, workspace: str, repository: str) -> dict[str, Any]:
        """Get the repository main branch."""
        repository_data = self.get_repo(workspace, repository)
        main_branch = repository_data.get("mainbranch")
        if not isinstance(main_branch, dict):
            return {}
        return {**main_branch, "isDefault": True}

    def get_commits(
        self,
        workspace: str,
        repository: str,
        limit: int = 25,
        until: str | None = None,
        since: str | None = None,
    ) -> list[dict[str, Any]]:
        """List commits, mapping Server/DC range names to Cloud parameters."""
        endpoint = (
            f"repositories/{self._segment(workspace)}/"
            f"{self._segment(repository)}/commits"
        )
        params: dict[str, Any] = {}
        if until:
            params["include"] = until
        if since:
            params["exclude"] = since
        return self._get_paginated(endpoint, params=params, limit=max(0, limit))

    def get_commit_changes(
        self,
        *,
        project_key: str,
        repository_slug: str,
        commit_id: str,
        hash_newest: str | None = None,
        merges: str = "include",
    ) -> dict[str, Any]:
        """Get Cloud diffstat entries for a commit or revision range."""
        del (
            merges
        )  # Cloud diffstat includes merge changes in its native representation.
        revision = f"{commit_id}..{hash_newest}" if hash_newest else commit_id
        endpoint = (
            f"repositories/{self._segment(project_key)}/"
            f"{self._segment(repository_slug)}/diffstat/{self._segment(revision)}"
        )
        values = self._get_paginated(endpoint)
        return {
            "fromHash": commit_id,
            "toHash": hash_newest or commit_id,
            "values": values,
        }

    def create_branch(
        self, workspace: str, repository: str, name: str, start_point: str
    ) -> dict[str, Any]:
        """Create a branch from an existing Cloud branch or commit hash."""
        branch_endpoint = (
            f"repositories/{self._segment(workspace)}/"
            f"{self._segment(repository)}/refs/branches/{self._segment(start_point)}"
        )
        source = self._request("GET", branch_endpoint)
        target = source.get("target", {}) if isinstance(source, dict) else {}
        target_hash = target.get("hash") or start_point
        endpoint = (
            f"repositories/{self._segment(workspace)}/"
            f"{self._segment(repository)}/refs/branches"
        )
        return self._request(
            "POST",
            endpoint,
            json={"name": name, "target": {"hash": target_hash}},
        )

    def get_pull_requests(
        self, workspace: str, repository: str, state: str = "OPEN"
    ) -> list[dict[str, Any]]:
        """List pull requests in a state."""
        endpoint = (
            f"repositories/{self._segment(workspace)}/"
            f"{self._segment(repository)}/pullrequests"
        )
        return self._get_paginated(endpoint, params={"state": state})

    def get_pull_request(
        self, workspace: str, repository: str, pull_request_id: int
    ) -> dict[str, Any]:
        """Get one pull request."""
        endpoint = (
            f"repositories/{self._segment(workspace)}/"
            f"{self._segment(repository)}/pullrequests/"
            f"{self._segment(pull_request_id)}"
        )
        return self._request("GET", endpoint)

    def get_pull_requests_commits(
        self, workspace: str, repository: str, pull_request_id: int
    ) -> list[dict[str, Any]]:
        """List commits in a pull request."""
        endpoint = (
            f"repositories/{self._segment(workspace)}/"
            f"{self._segment(repository)}/pullrequests/"
            f"{self._segment(pull_request_id)}/commits"
        )
        return self._get_paginated(endpoint)

    def get_pull_request_activities(
        self, workspace: str, repository: str, pull_request_id: int
    ) -> list[dict[str, Any]]:
        """List all pull-request activities."""
        endpoint = (
            f"repositories/{self._segment(workspace)}/"
            f"{self._segment(repository)}/pullrequests/"
            f"{self._segment(pull_request_id)}/activity"
        )
        return self._get_paginated(endpoint)

    @staticmethod
    def _branch_name(reference: Any) -> str | None:
        """Extract a branch name from Cloud or Server/DC PR input."""
        if not isinstance(reference, dict):
            return None
        branch = reference.get("branch")
        if isinstance(branch, dict) and branch.get("name"):
            return str(branch["name"])
        identifier = reference.get("id")
        if identifier:
            return str(identifier).removeprefix("refs/heads/")
        return None

    def create_pull_request(
        self, workspace: str, repository: str, pr_data: dict[str, Any]
    ) -> dict[str, Any]:
        """Create a pull request using the Cloud request schema."""
        source_name = self._branch_name(pr_data.get("source")) or self._branch_name(
            pr_data.get("fromRef")
        )
        destination_name = self._branch_name(
            pr_data.get("destination")
        ) or self._branch_name(pr_data.get("toRef"))
        if not source_name or not destination_name:
            msg = "Pull request source and destination branches are required"
            raise ValueError(msg)

        payload: dict[str, Any] = {
            "title": pr_data.get("title"),
            "source": {"branch": {"name": source_name}},
            "destination": {"branch": {"name": destination_name}},
        }
        if pr_data.get("description") is not None:
            payload["description"] = pr_data["description"]
        if "close_source_branch" in pr_data:
            payload["close_source_branch"] = bool(pr_data["close_source_branch"])
        if pr_data.get("reviewers"):
            payload["reviewers"] = pr_data["reviewers"]

        endpoint = (
            f"repositories/{self._segment(workspace)}/"
            f"{self._segment(repository)}/pullrequests"
        )
        return self._request("POST", endpoint, json=payload)

    @staticmethod
    def _comment_text(comment_data: Any) -> str:
        """Extract raw text from MCP, Cloud, or Server/DC comment input."""
        if isinstance(comment_data, str):
            return comment_data
        if not isinstance(comment_data, dict):
            return str(comment_data)
        content = comment_data.get("content")
        if isinstance(content, dict):
            return str(content.get("raw") or content.get("text") or "")
        if content is not None:
            return str(content)
        return str(comment_data.get("text") or comment_data.get("comment") or "")

    def add_pull_request_comment(
        self,
        workspace: str,
        repository: str,
        pull_request_id: int,
        comment_data: Any,
    ) -> dict[str, Any]:
        """Add a Cloud pull-request comment."""
        endpoint = (
            f"repositories/{self._segment(workspace)}/"
            f"{self._segment(repository)}/pullrequests/"
            f"{self._segment(pull_request_id)}/comments"
        )
        payload = {"content": {"raw": self._comment_text(comment_data)}}
        return self._request("POST", endpoint, json=payload)

    def add_pull_request_blocker_comment(
        self,
        workspace: str,
        repository: str,
        pull_request_id: int,
        comment: str,
        severity: str | None = None,
    ) -> dict[str, Any]:
        """Map blocker-comment semantics to Cloud comments or tasks.

        Bitbucket Cloud has no Data Center blocker-comment resource. A normal
        severity remains a PR comment, while a blocker becomes an actionable
        PR task containing the supplied text.
        """
        if severity != "BLOCKER":
            return self.add_pull_request_comment(
                workspace, repository, pull_request_id, comment
            )

        endpoint = (
            f"repositories/{self._segment(workspace)}/"
            f"{self._segment(repository)}/pullrequests/"
            f"{self._segment(pull_request_id)}/tasks"
        )
        return self._request(
            "POST",
            endpoint,
            json={"content": {"raw": comment}},
        )
