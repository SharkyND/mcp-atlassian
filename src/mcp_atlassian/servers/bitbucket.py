"""Bitbucket FastMCP server instance and tool definitions."""

import json
import logging
from typing import Annotated, Literal

from fastmcp import Context, FastMCP
from pydantic import Field
from requests.exceptions import HTTPError

from mcp_atlassian.exceptions import MCPAtlassianAuthenticationError
from mcp_atlassian.servers.dependencies import get_bitbucket_fetcher
from mcp_atlassian.utils.decorators import check_write_access

logger = logging.getLogger(__name__)

bitbucket_mcp = FastMCP(name="Bitbucket MCP Service")


@bitbucket_mcp.tool(tags={"bitbucket", "read"})
async def list_workspaces_or_projects(ctx: Context) -> str:
    """
    List all accessible workspaces (Cloud) or projects (Server/DC).

    Returns:
        JSON string containing list of workspaces/projects with their details.

    Raises:
        ValueError: If the Bitbucket client is not configured or available.
    """
    try:
        bitbucket = await get_bitbucket_fetcher(ctx)
        workspaces = bitbucket.get_all_workspaces()
        workspace_dicts = [
            ws.model_dump(mode="json", serialize_as_any=True) for ws in workspaces
        ]

        return json.dumps(workspace_dicts, indent=2)
    except Exception as e:
        error_message = ""
        log_level = logging.ERROR
        if isinstance(e, MCPAtlassianAuthenticationError):
            error_message = f"Authentication/Permission Error: {str(e)}"
        elif isinstance(e, OSError | HTTPError):
            error_message = f"Network or API Error: {str(e)}"
        elif isinstance(e, ValueError):
            error_message = f"Configuration Error: {str(e)}"
        else:
            error_message = "An unexpected error occurred while fetching workspaces."
            logger.exception("Unexpected error in bitbucket_list_workspaces:")

        error_result = {
            "success": False,
            "error": error_message,
        }
        logger.log(log_level, f"bitbucket_list_workspaces failed: {error_message}")
        return json.dumps(error_result, indent=2)


@bitbucket_mcp.tool(tags={"bitbucket", "read"})
async def list_repositories(
    ctx: Context,
    workspace: Annotated[
        str | None,
        Field(
            description="Workspace name (Cloud) or project key (Server/DC). If not provided, lists all accessible repositories.",
            default=None,
        ),
    ] = None,
) -> str:
    """
    List repositories in a workspace/project or all accessible repositories.

    Args:
        ctx: The MCP context.
        workspace: Optional workspace name or project key to filter repositories.

    Returns:
        JSON string containing list of repositories with their details.

    Raises:
        ValueError: If the Bitbucket client is not configured or available.
    """
    try:
        bitbucket = await get_bitbucket_fetcher(ctx)
        repositories = bitbucket.get_repositories(workspace)
        repositories = [
            r.model_dump(mode="json", serialize_as_any=True) for r in repositories
        ]
        return json.dumps(repositories, indent=2)
    except Exception as e:
        error_message = ""
        log_level = logging.ERROR
        if isinstance(e, MCPAtlassianAuthenticationError):
            error_message = f"Authentication/Permission Error: {str(e)}"
        elif isinstance(e, OSError | HTTPError):
            error_message = f"Network or API Error: {str(e)}"
        elif isinstance(e, ValueError):
            error_message = f"Configuration Error: {str(e)}"
        else:
            error_message = "An unexpected error occurred while fetching repositories."
            logger.exception("Unexpected error in bitbucket_list_repositories:")

        error_result = {
            "success": False,
            "error": error_message,
        }
        logger.log(log_level, f"bitbucket_list_repositories failed: {error_message}")
        return json.dumps(error_result, indent=2)


@bitbucket_mcp.tool(tags={"bitbucket", "read"})
async def get_repository_info(
    ctx: Context,
    workspace: Annotated[
        str,
        Field(description="Workspace name (Cloud) or project key (Server/DC)"),
    ],
    repository: Annotated[
        str,
        Field(description="Repository name"),
    ],
) -> str:
    """
    Get detailed information about a specific repository.

    Args:
        ctx: The MCP context.
        workspace: Workspace name or project key.
        repository: Repository name.

    Returns:
        JSON string containing repository details.

    Raises:
        ValueError: If the Bitbucket client is not configured or available.
    """
    try:
        bitbucket = await get_bitbucket_fetcher(ctx)
        repo_info = bitbucket.get_repository_info(workspace, repository)
        return json.dumps(
            repo_info.model_dump(mode="json", serialize_as_any=True), indent=2
        )
    except Exception as e:
        error_message = ""
        log_level = logging.ERROR
        if isinstance(e, MCPAtlassianAuthenticationError):
            error_message = f"Authentication/Permission Error: {str(e)}"
        elif isinstance(e, OSError | HTTPError):
            error_message = f"Network or API Error: {str(e)}"
        elif isinstance(e, ValueError):
            error_message = f"Configuration Error: {str(e)}"
        else:
            error_message = f"An unexpected error occurred while fetching repository info for {workspace}/{repository}."
            logger.exception("Unexpected error in bitbucket_get_repository_info:")

        error_result = {
            "success": False,
            "error": error_message,
        }
        logger.log(log_level, f"bitbucket_get_repository_info failed: {error_message}")
        return json.dumps(error_result, indent=2)


@bitbucket_mcp.tool(tags={"bitbucket", "read"})
async def list_branches(
    ctx: Context,
    workspace: Annotated[
        str,
        Field(description="Workspace name (Cloud) or project key (Server/DC)"),
    ],
    repository: Annotated[
        str,
        Field(description="Repository name"),
    ],
    base: Annotated[
        str,
        Field(description="The base branch"),
    ] = None,
    branch_filter: Annotated[
        str,
        Field(description="Branch pattern to filter on."),
    ] = None,
    start: Annotated[
        int,
        Field(description="Starting index."),
    ] = 0,
    limit: Annotated[
        int,
        Field(description="Maximum number of branches to return"),
    ] = None,
) -> str:
    """
    List all branches in a repository.

    Args:
        ctx: The MCP context.
        workspace: Workspace name or project key.
        repository: Repository name.
        base: The base branch from which to find branches.
        branch_filter: Branch pattern to filter on.
        start: Starting index.
        limit: Maximum number of branches to fetch.

    Returns:
        JSON string containing list of branches with their details.

    Raises:
        ValueError: If the Bitbucket client is not configured or available.
    """
    try:
        bitbucket = await get_bitbucket_fetcher(ctx)
        branches = bitbucket.get_branches(
            workspace, repository, base, branch_filter, start, limit
        )
        # Convert model objects to dictionaries for JSON serialization
        branch_dicts = [
            branch.model_dump(mode="json", serialize_as_any=True) for branch in branches
        ]
        return json.dumps(branch_dicts, indent=2)
    except Exception as e:
        error_message = ""
        log_level = logging.ERROR
        if isinstance(e, MCPAtlassianAuthenticationError):
            error_message = f"Authentication/Permission Error: {str(e)}"
        elif isinstance(e, OSError | HTTPError):
            error_message = f"Network or API Error: {str(e)}"
        elif isinstance(e, ValueError):
            error_message = f"Configuration Error: {str(e)}"
        else:
            error_message = f"An unexpected error occurred while fetching branches for {workspace}/{repository}."
            logger.exception("Unexpected error in bitbucket_list_branches:")

        error_result = {
            "success": False,
            "error": error_message,
        }
        logger.log(log_level, f"bitbucket_list_branches failed: {error_message}")
        return json.dumps(error_result, indent=2)


@bitbucket_mcp.tool(tags={"bitbucket", "read"})
async def get_default_branch(
    ctx: Context,
    workspace: Annotated[
        str,
        Field(description="Workspace name (Cloud) or project key (Server/DC)"),
    ],
    repository: Annotated[
        str,
        Field(description="Repository name"),
    ],
) -> str:
    """
    Get the default branch for a repository.

    Args:
        workspace: Workspace name or project key.
        repository: Repository name.

    Returns:
        JSON string containing default branch information.

    Raises:
        ValueError: If the Bitbucket client is not configured or available.
    """
    try:
        bitbucket = await get_bitbucket_fetcher(ctx)
        default_branch = bitbucket.get_default_branch(workspace, repository)
        if default_branch:
            return json.dumps(
                default_branch.model_dump(mode="json", serialize_as_any=True), indent=2
            )
        else:
            return json.dumps({"error": "No default branch found"})
    except Exception as e:
        error_message = ""
        log_level = logging.ERROR
        if isinstance(e, MCPAtlassianAuthenticationError):
            error_message = f"Authentication/Permission Error: {str(e)}"
        elif isinstance(e, OSError | HTTPError):
            error_message = f"Network or API Error: {str(e)}"
        elif isinstance(e, ValueError):
            error_message = f"Configuration Error: {str(e)}"
        else:
            error_message = f"An unexpected error occurred while fetching default branch for {workspace}/{repository}."
            logger.exception("Unexpected error in bitbucket_get_default_branch:")

        error_result = {
            "success": False,
            "error": error_message,
        }
        logger.log(log_level, f"bitbucket_get_default_branch failed: {error_message}")
        return json.dumps(error_result, indent=2)


@bitbucket_mcp.tool(tags={"bitbucket", "read"})
async def get_file_content(
    ctx: Context,
    workspace: Annotated[
        str,
        Field(description="Workspace name (Cloud) or project key (Server/DC)"),
    ],
    repository: Annotated[
        str,
        Field(description="Repository name"),
    ],
    file_path: Annotated[
        str,
        Field(description="Path to the file in the repository"),
    ],
    branch: Annotated[
        str,
        Field(description="Branch name to read from"),
    ] = "main",
    sample: Annotated[
        int,
        Field(
            description="Read top N lines of a file. -1 for full file content.",
            default=-1,
        ),
    ] = -1,
) -> str:
    """
    Get the content of a specific file from a repository.

    Args:
        workspace: Workspace name or project key.
        repository: Repository name.
        file_path: Path to the file in the repository.
        branch: Branch name to read from (default: main).

    Returns:
        JSON string containing file content and metadata.

    Raises:
        ValueError: If the Bitbucket client is not configured or available.
    """
    try:
        bitbucket = await get_bitbucket_fetcher(ctx)
        content = bitbucket.get_file_content(workspace, repository, file_path, branch)
        content = content.decode("utf-8")
        if sample and sample > 0:
            content = "\n".join(content.splitlines()[:sample])
        return json.dumps(
            {
                "workspace": workspace,
                "repository": repository,
                "file_path": file_path,
                "branch": branch,
                "content": content,
            },
            indent=2,
        )
    except Exception as e:
        error_message = ""
        log_level = logging.ERROR
        if isinstance(e, MCPAtlassianAuthenticationError):
            error_message = f"Authentication/Permission Error: {str(e)}"
        elif isinstance(e, OSError | HTTPError):
            error_message = f"Network or API Error: {str(e)}"
        elif isinstance(e, ValueError):
            error_message = f"Configuration Error: {str(e)}"
        else:
            error_message = f"An unexpected error occurred while fetching file content for {workspace}/{repository}/{file_path}."
            logger.exception("Unexpected error in bitbucket_get_file_content:")

        error_result = {
            "success": False,
            "error": error_message,
        }
        logger.log(log_level, f"bitbucket_get_file_content failed: {error_message}")
        return json.dumps(error_result, indent=2)


@bitbucket_mcp.tool(tags={"bitbucket", "read"})
async def list_directory(
    ctx: Context,
    workspace: Annotated[
        str,
        Field(description="Workspace name (Cloud) or project key (Server/DC)"),
    ],
    repository: Annotated[
        str,
        Field(description="Repository name"),
    ],
    path: Annotated[
        str,
        Field(description="Directory path in the repository"),
    ] = "",
    branch: Annotated[
        str,
        Field(description="Branch name to list from"),
    ] = "main",
) -> str:
    """
    List the contents of a directory in a repository.

    Args:
        workspace: Workspace name or project key.
        repository: Repository name.
        path: Directory path in the repository (empty for root).
        branch: Branch name to list from (default: main).

    Returns:
        JSON string containing directory contents.

    Raises:
        ValueError: If the Bitbucket client is not configured or available.
    """
    try:
        bitbucket = await get_bitbucket_fetcher(ctx)
        contents = list(
            bitbucket.get_directory_content(workspace, repository, path, branch)
        )
        return json.dumps(contents, indent=2)
    except Exception as e:
        error_message = ""
        log_level = logging.ERROR
        if isinstance(e, MCPAtlassianAuthenticationError):
            error_message = f"Authentication/Permission Error: {str(e)}"
        elif isinstance(e, OSError | HTTPError):
            error_message = f"Network or API Error: {str(e)}"
        elif isinstance(e, ValueError):
            error_message = f"Configuration Error: {str(e)}"
        else:
            error_message = f"An unexpected error occurred while listing directory for {workspace}/{repository}/{path}."
            logger.exception("Unexpected error in bitbucket_list_directory:")

        error_result = {
            "success": False,
            "error": error_message,
        }
        logger.log(log_level, f"bitbucket_list_directory failed: {error_message}")
        return json.dumps(error_result, indent=2)


@bitbucket_mcp.tool(tags={"bitbucket", "read"})
async def list_pull_requests(
    ctx: Context,
    workspace: Annotated[
        str,
        Field(description="Workspace name (Cloud) or project key (Server/DC)"),
    ],
    repository: Annotated[
        str,
        Field(description="Repository name"),
    ],
    state: Annotated[
        str,
        Field(description="Pull request state: OPEN, MERGED, DECLINED"),
    ] = "OPEN",
) -> str:
    """
    List pull requests for a repository.

    Args:
        workspace: Workspace name or project key.
        repository: Repository name.
        state: Pull request state filter (OPEN, MERGED, DECLINED).

    Returns:
        JSON string containing list of pull requests.

    Raises:
        ValueError: If the Bitbucket client is not configured or available.
    """
    try:
        bitbucket = await get_bitbucket_fetcher(ctx)
        pull_requests = bitbucket.get_pull_requests(workspace, repository, state)
        pr_dicts = list(pull_requests)
        return json.dumps(pr_dicts, indent=2)
    except Exception as e:
        log_level = logging.ERROR
        if isinstance(e, MCPAtlassianAuthenticationError):
            error_message = f"Authentication/Permission Error: {str(e)}"
        elif isinstance(e, OSError | HTTPError):
            error_message = f"Network or API Error: {str(e)}"
        elif isinstance(e, ValueError):
            error_message = f"Configuration Error: {str(e)}"
        else:
            error_message = f"An unexpected error occurred while fetching pull requests for {workspace}/{repository}."
            logger.exception("Unexpected error in bitbucket_list_pull_requests:")

        error_result = {
            "success": False,
            "error": error_message,
        }
        logger.log(log_level, f"bitbucket_list_pull_requests failed: {error_message}")
        return json.dumps(error_result, indent=2)


@bitbucket_mcp.tool(tags={"bitbucket", "read"})
async def pull_request_activities(
    ctx: Context,
    workspace: Annotated[
        str,
        Field(description="Workspace name (Cloud) or project key (Server/DC)"),
    ],
    repository: Annotated[
        str,
        Field(description="Repository name"),
    ],
    pull_request_id: Annotated[
        int,
        Field(description="Pull request ID to get comments for."),
    ],
) -> str:
    """
    Get all activities on a pull request.

    Args:
        workspace: Workspace name or project key.
        repository: Repository name.
        pull_request_id: Pull request ID to get comments for.

    Returns:
        JSON string containing list of pull requests.

    Raises:
        ValueError: If the Bitbucket client is not configured or available.
    """
    try:
        bitbucket = await get_bitbucket_fetcher(ctx)
        pull_requests = bitbucket.get_pull_request_activities(
            workspace, repository, pull_request_id
        )
        return json.dumps(pull_requests, indent=2)
    except Exception as e:
        log_level = logging.ERROR
        if isinstance(e, MCPAtlassianAuthenticationError):
            error_message = f"Authentication/Permission Error: {str(e)}"
        elif isinstance(e, OSError | HTTPError):
            error_message = f"Network or API Error: {str(e)}"
        elif isinstance(e, ValueError):
            error_message = f"Configuration Error: {str(e)}"
        else:
            error_message = f"An unexpected error occurred while fetching pull requests for {workspace}/{repository}."
            logger.exception("Unexpected error in bitbucket_list_pull_requests:")

        error_result = {
            "success": False,
            "error": error_message,
        }
        logger.log(log_level, f"bitbucket_list_pull_requests failed: {error_message}")
        return json.dumps(error_result, indent=2)


@bitbucket_mcp.tool(tags={"bitbucket", "read"})
async def get_pull_request(
    ctx: Context,
    workspace: Annotated[
        str,
        Field(description="Workspace name (Cloud) or project key (Server/DC)"),
    ],
    repository: Annotated[
        str,
        Field(description="Repository name"),
    ],
    pull_request_id: Annotated[
        int,
        Field(description="Pull request ID"),
    ],
) -> str:
    """
    Get detailed information about a specific pull request.

    Args:
        workspace: Workspace name or project key.
        repository: Repository name.
        pull_request_id: Pull request ID.

    Returns:
        JSON string containing pull request details.

    Raises:
        ValueError: If the Bitbucket client is not configured or available.
    """
    try:
        bitbucket = await get_bitbucket_fetcher(ctx)
        pull_request = bitbucket.get_pull_request(
            workspace, repository, pull_request_id
        )
        return json.dumps(
            pull_request.model_dump(mode="json", serialize_as_any=True), indent=2
        )
    except Exception as e:
        log_level = logging.ERROR
        if isinstance(e, MCPAtlassianAuthenticationError):
            error_message = f"Authentication/Permission Error: {str(e)}"
        elif isinstance(e, OSError | HTTPError):
            error_message = f"Network or API Error: {str(e)}"
        elif isinstance(e, ValueError):
            error_message = f"Configuration Error: {str(e)}"
        else:
            error_message = f"An unexpected error occurred while fetching pull request {pull_request_id} for {workspace}/{repository}."
            logger.exception("Unexpected error in bitbucket_get_pull_request:")

        error_result = {
            "success": False,
            "error": error_message,
        }
        logger.log(log_level, f"bitbucket_get_pull_request failed: {error_message}")
        return json.dumps(error_result, indent=2)


@bitbucket_mcp.tool(tags={"bitbucket", "read"})
async def get_commit_changes(
    ctx: Context,
    workspace: Annotated[
        str,
        Field(description="Workspace name (Cloud) or project key (Server/DC)"),
    ],
    repository: Annotated[
        str,
        Field(description="Repository name"),
    ],
    commit_id: Annotated[
        str,
        Field(description="ID of the commit whose changes are being fetched."),
    ],
    merges: Annotated[
        Literal["include", "exclude", "only"],
        Field(
            description="Filter merges ('include', 'exclude', 'only') (default: include)"
        ),
    ] = "include",
    hash_newest: Annotated[
        str,
        Field(description="Fetch changes for a particular commit hash."),
    ] = None,
) -> str:
    """
    Get commit history for a repository branch.

    Args:
        workspace: Workspace name or project key.
        repository: Repository name.
        commit_id: ID of the commit whose changes are being fetched.
        merges: Filter merges ('include', 'exclude', 'only') (default: include)
        hash_newest: Fetch changes for a particular commit hash.

    Returns:
        JSON string containing commit history.

    Raises:
        ValueError: If the Bitbucket client is not configured or available.
    """
    try:
        bitbucket = await get_bitbucket_fetcher(ctx)
        commits = bitbucket.get_commit_changes(
            workspace, repository, commit_id, merges, hash_newest
        )
        return json.dumps(
            commits.model_dump(mode="json", serialize_as_any=True), indent=2
        )
    except Exception as e:
        log_level = logging.ERROR
        if isinstance(e, MCPAtlassianAuthenticationError):
            error_message = f"Authentication/Permission Error: {str(e)}"
        elif isinstance(e, OSError | HTTPError):
            error_message = f"Network or API Error: {str(e)}"
        elif isinstance(e, ValueError):
            error_message = f"Configuration Error: {str(e)}"
        else:
            error_message = f"An unexpected error occurred while fetching commits for {workspace}/{repository}."
            logger.exception("Unexpected error in bitbucket_get_commits:")

        error_result = {
            "success": False,
            "error": error_message,
        }
        logger.log(log_level, f"bitbucket_get_commits failed: {error_message}")
        return json.dumps(error_result, indent=2)


@bitbucket_mcp.tool(tags={"bitbucket", "read"})
async def get_commits(
    ctx: Context,
    workspace: Annotated[
        str,
        Field(description="Workspace name (Cloud) or project key (Server/DC)"),
    ],
    repository: Annotated[
        str,
        Field(description="Repository name"),
    ],
    limit: Annotated[
        int,
        Field(description="Maximum number of commits to return"),
    ] = 25,
    until: Annotated[
        str,
        Field(
            description="The commit ID or ref (inclusively) to retrieve commits before"
        ),
    ] = None,
    since: Annotated[
        str,
        Field(
            description="The commit ID or ref (inclusively) to retrieve commits after"
        ),
    ] = None,
) -> str:
    """
    Get commit history for a repository branch.

    Args:
        workspace: Workspace name or project key.
        repository: Repository name.
        until: The commit ID or ref (inclusively) to retrieve commits before
        limit: Maximum number of commits to return (default: 25).
        since: The commit ID or ref (inclusively) to retrieve commits after

    Returns:
        JSON string containing commit history.

    Raises:
        ValueError: If the Bitbucket client is not configured or available.
    """
    try:
        bitbucket = await get_bitbucket_fetcher(ctx)
        commits = bitbucket.get_commits(
            workspace, repository, limit=limit, until=until, since=since
        )

        commit_dicts = [
            commit.model_dump(mode="json", serialize_as_any=True) for commit in commits
        ]
        return json.dumps(commit_dicts, indent=2)
    except Exception as e:
        log_level = logging.ERROR
        if isinstance(e, MCPAtlassianAuthenticationError):
            error_message = f"Authentication/Permission Error: {str(e)}"
        elif isinstance(e, OSError | HTTPError):
            error_message = f"Network or API Error: {str(e)}"
        elif isinstance(e, ValueError):
            error_message = f"Configuration Error: {str(e)}"
        else:
            error_message = f"An unexpected error occurred while fetching commits for {workspace}/{repository}."
            logger.exception("Unexpected error in bitbucket_get_commits:")

        error_result = {
            "success": False,
            "error": error_message,
        }
        logger.log(log_level, f"bitbucket_get_commits failed: {error_message}")
        return json.dumps(error_result, indent=2)


@bitbucket_mcp.tool(tags={"bitbucket", "write"})
@check_write_access
async def create_pull_request(
    ctx: Context,
    workspace: Annotated[
        str,
        Field(description="Workspace name (Cloud) or project key (Server/DC)"),
    ],
    repository: Annotated[
        str,
        Field(description="Repository name"),
    ],
    title: Annotated[
        str,
        Field(description="Pull request title"),
    ],
    source_branch: Annotated[
        str,
        Field(description="Source branch name"),
    ],
    destination_branch: Annotated[
        str,
        Field(description="Destination branch name"),
    ] = "main",
    description: Annotated[
        str | None,
        Field(description="Pull request description"),
    ] = None,
) -> str:
    """
    Create a new pull request.

    Args:
        workspace: Workspace name or project key.
        repository: Repository name.
        title: Pull request title.
        source_branch: Source branch name.
        destination_branch: Destination branch name (default: main).
        description: Optional pull request description.

    Returns:
        JSON string containing the created pull request details.

    Raises:
        ValueError: If the Bitbucket client is not configured or available.
    """
    try:
        bitbucket = await get_bitbucket_fetcher(ctx)

        pr_data = {
            "title": title,
            "description": description,
            "state": "OPEN",
            "open": True,
            "closed": False,
            "fromRef": {
                "id": f"refs/heads/{source_branch}",
                "repository": {
                    "slug": repository,
                    "name": None,
                    "project": {"key": workspace},
                },
            },
            "toRef": {
                "id": f"refs/heads/{destination_branch}",
                "repository": {
                    "slug": repository,
                    "name": None,
                    "project": {"key": workspace},
                },
            },
            "locked": False,
            "reviewers": [],
        }

        result = bitbucket.create_pull_request(workspace, repository, pr_data)

        return json.dumps(
            {
                "success": True,
                "pull_request": result,
            },
            indent=2,
        )
    except Exception as e:
        log_level = logging.ERROR
        if isinstance(e, MCPAtlassianAuthenticationError):
            error_message = f"Authentication/Permission Error: {str(e)}"
        elif isinstance(e, OSError | HTTPError):
            error_message = f"Network or API Error: {str(e)}"
        elif isinstance(e, ValueError):
            error_message = f"Configuration Error: {str(e)}"
        else:
            error_message = f"An unexpected error occurred while creating pull request in {workspace}/{repository}."
            logger.exception("Unexpected error in bitbucket_create_pull_request:")

        error_result = {
            "success": False,
            "error": error_message,
        }
        logger.log(log_level, f"bitbucket_create_pull_request failed: {error_message}")
        return json.dumps(error_result, indent=2)


@bitbucket_mcp.tool(tags={"bitbucket", "write"})
@check_write_access
async def create_branch(
    ctx: Context,
    workspace: Annotated[
        str,
        Field(description="Workspace name (Cloud) or project key (Server/DC)"),
    ],
    repository: Annotated[
        str,
        Field(description="Repository name"),
    ],
    branch_name: Annotated[
        str,
        Field(description="New branch name"),
    ],
    source_branch: Annotated[
        str,
        Field(description="Source branch to create from"),
    ] = "main",
) -> str:
    """
    Create a new branch in a repository.

    Args:
        workspace: Workspace name or project key.
        repository: Repository name.
        branch_name: New branch name.
        source_branch: Source branch to create from (default: main).

    Returns:
        JSON string containing the created branch details.

    Raises:
        ValueError: If the Bitbucket client is not configured or available.
    """
    try:
        bitbucket = await get_bitbucket_fetcher(ctx)

        branch_data = {
            "name": branch_name,
            "target": {"branch": {"name": source_branch}},
        }

        result = bitbucket.create_branch(workspace, repository, branch_data)

        return json.dumps(
            {
                "success": True,
                "branch": result,
                "source_branch": source_branch,
            },
            indent=2,
        )
    except Exception as e:
        log_level = logging.ERROR
        if isinstance(e, MCPAtlassianAuthenticationError):
            error_message = f"Authentication/Permission Error: {str(e)}"
        elif isinstance(e, OSError | HTTPError):
            error_message = f"Network or API Error: {str(e)}"
        elif isinstance(e, ValueError):
            error_message = f"Configuration Error: {str(e)}"
        else:
            error_message = f"An unexpected error occurred while creating branch {branch_name} in {workspace}/{repository}."
            logger.exception("Unexpected error in bitbucket_create_branch:")

        error_result = {
            "success": False,
            "error": error_message,
        }
        logger.log(log_level, f"bitbucket_create_branch failed: {error_message}")
        return json.dumps(error_result, indent=2)


@bitbucket_mcp.tool(tags={"bitbucket", "write"})
@check_write_access
async def add_pull_request_blocker_comment(
    ctx: Context,
    workspace: Annotated[
        str,
        Field(description="Workspace name (Cloud) or project key (Server/DC)"),
    ],
    repository: Annotated[
        str,
        Field(description="Repository name"),
    ],
    pull_request_id: Annotated[
        int,
        Field(description="Pull request ID"),
    ],
    comment: Annotated[
        str,
        Field(description="Comment text"),
    ],
    severity: Annotated[
        Literal["NORMAL", "BLOCKER"],
        Field(description="Severity of the blocker."),
    ] = "NORMAL",
) -> str:
    """
    Add a comment to a pull request.

    Args:
        workspace: Workspace name or project key.
        repository: Repository name.
        pull_request_id: Pull request ID.
        comment: Comment text.
        severity: Severity of the blocker. (Normal or Blocker) (default: NORMAL)

    Returns:
        JSON string containing the created comment details.

    Raises:
        ValueError: If the Bitbucket client is not configured or available.
    """
    try:
        bitbucket = await get_bitbucket_fetcher(ctx)

        result = bitbucket.add_pull_request_blocker_comment(
            workspace, repository, pull_request_id, comment, severity
        )

        return json.dumps(
            {
                "success": True,
                "comment": result,
                "pull_request_id": pull_request_id,
            },
            indent=2,
        )
    except Exception as e:
        log_level = logging.ERROR
        if isinstance(e, MCPAtlassianAuthenticationError):
            error_message = f"Authentication/Permission Error: {str(e)}"
        elif isinstance(e, OSError | HTTPError):
            error_message = f"Network or API Error: {str(e)}"
        elif isinstance(e, ValueError):
            error_message = f"Configuration Error: {str(e)}"
        else:
            error_message = f"An unexpected error occurred while adding blocker comment to PR {pull_request_id} in {workspace}/{repository}."
            logger.exception(
                "Unexpected error in bitbucket_add_pull_request_blocker_comment:"
            )

        error_result = {
            "success": False,
            "error": error_message,
        }
        logger.log(
            log_level,
            f"bitbucket_add_pull_request_blocker_comment failed: {error_message}",
        )
        return json.dumps(error_result, indent=2)


@bitbucket_mcp.tool(tags={"bitbucket", "write"})
@check_write_access
async def add_pull_request_comment(
    ctx: Context,
    workspace: Annotated[
        str,
        Field(description="Workspace name (Cloud) or project key (Server/DC)"),
    ],
    repository: Annotated[
        str,
        Field(description="Repository name"),
    ],
    pull_request_id: Annotated[
        int,
        Field(description="Pull request ID"),
    ],
    comment: Annotated[
        str,
        Field(description="Comment text"),
    ],
) -> str:
    """
    Add a comment to a pull request.

    Args:
        workspace: Workspace name or project key.
        repository: Repository name.
        pull_request_id: Pull request ID.
        comment: Comment text.

    Returns:
        JSON string containing the created comment details.

    Raises:
        ValueError: If the Bitbucket client is not configured or available.
    """
    try:
        bitbucket = await get_bitbucket_fetcher(ctx)

        result = bitbucket.add_pull_request_comment(
            workspace, repository, pull_request_id, comment
        )

        return json.dumps(
            {
                "success": True,
                "comment": result,
                "pull_request_id": pull_request_id,
            },
            indent=2,
        )
    except Exception as e:
        log_level = logging.ERROR
        if isinstance(e, MCPAtlassianAuthenticationError):
            error_message = f"Authentication/Permission Error: {str(e)}"
        elif isinstance(e, OSError | HTTPError):
            error_message = f"Network or API Error: {str(e)}"
        elif isinstance(e, ValueError):
            error_message = f"Configuration Error: {str(e)}"
        else:
            error_message = f"An unexpected error occurred while adding comment to PR {pull_request_id} in {workspace}/{repository}."
            logger.exception("Unexpected error in bitbucket_add_pull_request_comment:")

        error_result = {
            "success": False,
            "error": error_message,
        }
        logger.log(
            log_level, f"bitbucket_add_pull_request_comment failed: {error_message}"
        )
        return json.dumps(error_result, indent=2)


@bitbucket_mcp.tool(tags={"bitbucket", "write"})
@check_write_access
async def add_pull_request_inline_comment(
    ctx: Context,
    workspace: Annotated[
        str,
        Field(description="Workspace name (Cloud) or project key (Server/DC)"),
    ],
    repository: Annotated[
        str,
        Field(description="Repository name"),
    ],
    pull_request_id: Annotated[
        int,
        Field(description="Pull request ID"),
    ],
    comment: Annotated[
        str,
        Field(description="Comment text"),
    ],
    file_path: Annotated[
        str,
        Field(description="Path to the file being commented on (e.g. 'src/main.py')"),
    ],
    line: Annotated[
        int,
        Field(description="Line number in the file to attach the comment to", ge=1),
    ],
    line_type: Annotated[
        Literal["ADDED", "REMOVED", "CONTEXT"],
        Field(
            description=(
                "Type of the line being commented on. Only used for Bitbucket Server/DC. "
                "'ADDED' for new lines, 'REMOVED' for deleted lines, 'CONTEXT' for unchanged lines."
            ),
            default="ADDED",
        ),
    ] = "ADDED",
) -> str:
    """
    Add an inline comment on a specific line of a file in a pull request.

    Args:
        workspace: Workspace name or project key.
        repository: Repository name.
        pull_request_id: Pull request ID.
        comment: Comment text.
        file_path: Path to the file to comment on.
        line: Line number to attach the comment to.
        line_type: Line type for Server/DC ('ADDED', 'REMOVED', or 'CONTEXT').

    Returns:
        JSON string containing the created comment details.

    Raises:
        ValueError: If the Bitbucket client is not configured or available.
    """
    try:
        bitbucket = await get_bitbucket_fetcher(ctx)

        result = bitbucket.add_pull_request_inline_comment(
            workspace, repository, pull_request_id, comment, file_path, line, line_type
        )

        inline_info = result.get("inline") if isinstance(result, dict) else None
        anchor_info = result.get("anchor") if isinstance(result, dict) else None
        resolved_path = None
        resolved_line = None

        if isinstance(inline_info, dict):
            resolved_path = inline_info.get("path")
            resolved_line = inline_info.get("to") or inline_info.get("from")
        elif isinstance(anchor_info, dict):
            resolved_path = anchor_info.get("path")
            resolved_line = anchor_info.get("line")

        response_payload = {
            "success": True,
            "comment": result,
            "pull_request_id": pull_request_id,
            "requested_file_path": file_path,
            "requested_line": line,
            "anchored": resolved_line is not None,
            "file_path": resolved_path,
            "line": resolved_line,
        }

        if resolved_line is None:
            response_payload["warning"] = (
                "Bitbucket accepted the comment but did not return a line anchor. "
                "This usually means the supplied path/line did not match the PR diff "
                "or the API created a general PR comment instead."
            )

        return json.dumps(
            response_payload,
            indent=2,
        )
    except Exception as e:
        log_level = logging.ERROR
        if isinstance(e, MCPAtlassianAuthenticationError):
            error_message = f"Authentication/Permission Error: {str(e)}"
        elif isinstance(e, OSError | HTTPError):
            error_message = f"Network or API Error: {str(e)}"
        elif isinstance(e, ValueError):
            error_message = f"Configuration Error: {str(e)}"
        else:
            error_message = f"An unexpected error occurred while adding inline comment to PR {pull_request_id} in {workspace}/{repository}."
            logger.exception(
                "Unexpected error in bitbucket_add_pull_request_inline_comment:"
            )

        error_result = {
            "success": False,
            "error": error_message,
        }
        logger.log(
            log_level,
            f"bitbucket_add_pull_request_inline_comment failed: {error_message}",
        )
        return json.dumps(error_result, indent=2)


@bitbucket_mcp.tool(tags={"bitbucket", "read"})
async def analyze_pr_review_status(
    ctx: Context,
    workspace: Annotated[
        str,
        Field(description="Workspace name (Cloud) or project key (Server/DC)"),
    ],
    repository: Annotated[
        str,
        Field(description="Repository name"),
    ],
    pull_request_id: Annotated[
        int,
        Field(description="Pull request ID to analyze"),
    ],
) -> str:
    """
    Analyze a pull request's comment threads to determine which review feedback
    has been addressed and which is still pending.

    For each comment thread the tool inspects:
    - Whether the comment is explicitly resolved/marked done (Server/DC ``state`` field,
      Cloud ``resolved`` flag).
    - Replies in the thread — if a reply contains completion keywords
      ("done", "fixed", "addressed", "resolved", "updated", "completed") it is
      considered addressed even when no formal resolve action was taken.

    Returns a structured summary with:
    - ``total_comments``: number of top-level review comments found
    - ``addressed``: list of comments considered done (resolved or positively replied)
    - ``pending``: list of comments that still need attention
    - ``overall_status``: "ALL_ADDRESSED" | "PARTIALLY_ADDRESSED" | "NONE_ADDRESSED"

    Args:
        workspace: Workspace name or project key.
        repository: Repository name.
        pull_request_id: Pull request ID.

    Returns:
        JSON string with the review status analysis.

    Raises:
        ValueError: If the Bitbucket client is not configured or available.
    """
    # Keywords in a reply that signal the author considers the work done
    _done_keywords = {
        "done",
        "fixed",
        "addressed",
        "resolved",
        "updated",
        "completed",
        "applied",
        "changed",
    }

    def _reply_indicates_done(replies: list[dict]) -> bool:
        for reply in replies:
            text = ""
            # Cloud uses content.raw; Server uses text
            content = reply.get("content") or {}
            text = (content.get("raw") or reply.get("text") or "").lower()
            if any(kw in text for kw in _done_keywords):
                return True
        return False

    def _is_comment_addressed(activity: dict) -> bool:
        """Return True if an activity's comment is considered addressed."""
        comment = activity.get("comment") or activity
        # Explicit resolve: Server/DC sets state="RESOLVED"; Cloud sets resolved=True
        if comment.get("state") == "RESOLVED":
            return True
        if comment.get("resolved") is True:
            return True
        # Check replies
        replies = comment.get("comments") or []  # Server nests as 'comments'
        if replies:
            return _reply_indicates_done(replies)
        return False

    def _summarise_comment(activity: dict) -> dict:
        comment = activity.get("comment") or activity
        content = comment.get("content") or {}
        text = content.get("raw") or comment.get("text") or "(no text)"
        author_info = comment.get("author") or {}
        return {
            "id": comment.get("id"),
            "author": author_info.get("display_name")
            or author_info.get("displayName")
            or author_info.get("name")
            or "unknown",
            "text": text[:300],  # truncate for readability
            "created_on": comment.get("created_on") or comment.get("createdDate"),
            "state": comment.get("state")
            or ("resolved" if comment.get("resolved") else "open"),
            "reply_count": len(comment.get("comments") or []),
        }

    try:
        bitbucket = await get_bitbucket_fetcher(ctx)
        activities = bitbucket.get_pull_request_activities(
            workspace, repository, pull_request_id
        )

        addressed = []
        pending = []

        for activity in activities:
            # Filter to comment activities only
            event = activity.get("action") or activity.get("event") or ""
            has_comment = "comment" in activity or event.upper() in (
                "COMMENTED",
                "COMMENT",
            )
            if not has_comment:
                continue

            summary = _summarise_comment(activity)
            if _is_comment_addressed(activity):
                addressed.append(summary)
            else:
                pending.append(summary)

        total = len(addressed) + len(pending)
        if total == 0:
            overall_status = "NO_COMMENTS"
        elif len(pending) == 0:
            overall_status = "ALL_ADDRESSED"
        elif len(addressed) == 0:
            overall_status = "NONE_ADDRESSED"
        else:
            overall_status = "PARTIALLY_ADDRESSED"

        result = {
            "pull_request_id": pull_request_id,
            "workspace": workspace,
            "repository": repository,
            "total_comments": total,
            "addressed_count": len(addressed),
            "pending_count": len(pending),
            "overall_status": overall_status,
            "addressed": addressed,
            "pending": pending,
        }
        return json.dumps(result, indent=2)
    except Exception as e:
        log_level = logging.ERROR
        if isinstance(e, MCPAtlassianAuthenticationError):
            error_message = f"Authentication/Permission Error: {str(e)}"
        elif isinstance(e, OSError | HTTPError):
            error_message = f"Network or API Error: {str(e)}"
        elif isinstance(e, ValueError):
            error_message = f"Configuration Error: {str(e)}"
        else:
            error_message = f"An unexpected error occurred while analyzing review status for PR {pull_request_id} in {workspace}/{repository}."
            logger.exception("Unexpected error in bitbucket_analyze_pr_review_status:")

        error_result = {"success": False, "error": error_message}
        logger.log(
            log_level, f"bitbucket_analyze_pr_review_status failed: {error_message}"
        )
        return json.dumps(error_result, indent=2)


@bitbucket_mcp.tool(tags={"bitbucket", "read"})
async def get_pull_request_diff(
    ctx: Context,
    workspace: Annotated[
        str,
        Field(description="Workspace name (Cloud) or project key (Server/DC)"),
    ],
    repository: Annotated[
        str,
        Field(description="Repository name"),
    ],
    pull_request_id: Annotated[
        int,
        Field(description="Pull request ID"),
    ],
) -> str:
    """
    Get the full code diff (all changed files and lines) for a pull request.

    Returns the unified diff of all changes included in the PR so you can
    review exactly what new code was added, modified, or removed.

    For Bitbucket Cloud the response is a raw unified diff string.
    For Bitbucket Server/DC the response is structured JSON containing per-file
    diff hunks.

    Args:
        workspace: Workspace name or project key.
        repository: Repository name.
        pull_request_id: Pull request ID.

    Returns:
        JSON string wrapping the diff content and metadata.

    Raises:
        ValueError: If the Bitbucket client is not configured or available.
    """
    try:
        bitbucket = await get_bitbucket_fetcher(ctx)
        diff_content = bitbucket.get_pull_request_diff(
            workspace, repository, pull_request_id
        )
        return json.dumps(
            {
                "pull_request_id": pull_request_id,
                "workspace": workspace,
                "repository": repository,
                "diff": diff_content,
            },
            indent=2,
        )
    except Exception as e:
        log_level = logging.ERROR
        if isinstance(e, MCPAtlassianAuthenticationError):
            error_message = f"Authentication/Permission Error: {str(e)}"
        elif isinstance(e, OSError | HTTPError):
            error_message = f"Network or API Error: {str(e)}"
        elif isinstance(e, ValueError):
            error_message = f"Configuration Error: {str(e)}"
        else:
            error_message = f"An unexpected error occurred while fetching diff for PR {pull_request_id} in {workspace}/{repository}."
            logger.exception("Unexpected error in bitbucket_get_pull_request_diff:")

        error_result = {"success": False, "error": error_message}
        logger.log(
            log_level, f"bitbucket_get_pull_request_diff failed: {error_message}"
        )
        return json.dumps(error_result, indent=2)
