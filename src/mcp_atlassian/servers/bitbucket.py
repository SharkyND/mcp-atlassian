"""Bitbucket FastMCP server instance and tool definitions."""

import json
import logging
from typing import Annotated, Literal

from fastmcp import Context, FastMCP
from pydantic import Field
from requests.exceptions import HTTPError

from ..exceptions import MCPAtlassianAuthenticationError
from ..utils.decorators import check_write_access
from .dependencies import get_bitbucket_fetcher

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
    starting_line: Annotated[
        int,
        Field(
            description="The line to start sampling from. -1 to start sampling from the start.",
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
        sample: Number of lines from the top to read.
        starting_line: The line to start sampling from. -1 to sample from the start.

    Returns:
        JSON string containing file content and metadata.

    Raises:
        ValueError: If the Bitbucket client is not configured or available.
    """
    try:
        bitbucket = await get_bitbucket_fetcher(ctx)
        content = bitbucket.get_file_content(workspace, repository, file_path, branch)
        content = content.decode("utf-8")

        # Split content into lines for processing
        lines = content.splitlines()
        total_lines = len(lines)

        # Handle starting_line parameter
        if starting_line != -1:
            # Check if starting_line is out of range
            if starting_line > total_lines:
                error_result = {
                    "success": False,
                    "error": f"Starting line {starting_line} is out of range. File has only {total_lines} lines.",
                    "total_lines": total_lines,
                    "workspace": workspace,
                    "repository": repository,
                    "file_path": file_path,
                    "branch": branch,
                }
                logger.warning(
                    f"Starting line {starting_line} out of range for {workspace}/{repository}/{file_path}. "
                    f"File has {total_lines} lines."
                )
                return json.dumps(error_result, indent=2)

            # Adjust for 1-based line numbering (starting_line is 1-based, but list indexing is 0-based)
            start_index = max(0, starting_line - 1)
            lines = lines[start_index:]

        # Handle sample parameter (number of lines to return)
        if sample and sample > 0:
            lines = lines[:sample]

        # Reconstruct content from processed lines
        processed_content = "\n".join(lines)

        result = {
            "workspace": workspace,
            "repository": repository,
            "file_path": file_path,
            "branch": branch,
            "content": processed_content,
            "total_lines": total_lines,
        }

        # Add sampling information if applicable
        if starting_line != -1:
            result["started_from_line"] = starting_line
        if sample and sample > 0:
            result["lines_returned"] = len(lines)

        return json.dumps(result, indent=2)
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
async def code_search(
    ctx: Context,
    bitbucket_project_key: Annotated[
        str,
        Field(description="Bitbucket project key (Server/DC) or workspace (Cloud)."),
    ],
    repository_slug: Annotated[
        str,
        Field(description="Repository slug to search within."),
    ],
    search_query: Annotated[
        str,
        Field(
            description=(
                "Text to search for within repository files. "
                "For basic searches, use simple text. "
                "For multi_term searches, separate terms with SPACES and use quotes for exact phrases: "
                "'error timeout connection' (space-separated terms) or "
                "'error \"database connection\" timeout' (quoted phrases mixed with terms). "
                "The multi_term_operator determines if ALL terms must match (AND) or ANY term can match (OR)."
            )
        ),
    ],
    branch_name: Annotated[
        str | None,
        Field(
            description="Optional branch override; defaults to the repository default.",
            default=None,
        ),
    ] = None,
    surrounding_lines: Annotated[
        int,
        Field(
            description="Context lines before and after each match.",
            ge=0,
            default=25,
        ),
    ] = 25,
    max_results: Annotated[
        int,
        Field(
            description="Number of search results to return.",
            ge=0,
            default=10,
        ),
    ] = 10,
    case_sensitive: Annotated[
        bool,
        Field(
            description="Whether to perform case-sensitive matching.",
            default=False,
        ),
    ] = False,
    search_type: Annotated[
        Literal["substring", "regex", "whole_word", "multi_term"],
        Field(
            description="Type of search: 'substring' (default), 'regex' (regular expressions), 'whole_word' (complete words only), 'multi_term' (multiple terms with AND/OR logic).",
            default="substring",
        ),
    ] = "substring",
    multi_term_operator: Annotated[
        Literal["and", "or"],
        Field(
            description="For multi_term searches: 'and' (all terms must match), 'or' (any term can match). Default is 'or'.",
            default="or",
        ),
    ] = "or",
    file_extensions: Annotated[
        list[str] | None,
        Field(
            description="Optional list of file extensions to search (e.g., ['.py', '.js', '.ts']). If not provided, searches all text files excluding .git.",
            default=None,
        ),
    ] = None,
    exclude_paths: Annotated[
        list[str] | None,
        Field(
            description="Optional list of path patterns to exclude (e.g., ['test/', 'node_modules/', '__pycache__/']). Paths are matched as substrings.",
            default=None,
        ),
    ] = None,
) -> str:
    """
    Search repository code with advanced search capabilities including regex, whole word, and multi-term search.

    This tool provides powerful code search functionality with multiple search types:
    - substring: Simple text matching (default)
    - regex: Regular expression pattern matching
    - whole_word: Match complete words only (great for variable/function names)
    - multi_term: Search for multiple terms with AND/OR logic, supports quoted phrases

    Performance features:
    - File extension filtering for faster searches on large repos
    - Path exclusion to skip irrelevant directories
    - Binary file detection and skipping
    - Automatic .git directory exclusion

    Args:
        bitbucket_project_key: Bitbucket project key (Server/DC) or workspace (Cloud).
        repository_slug: Repository slug to search.
        search_query: Text to search for. For multi_term, supports quoted phrases like: 'error "database connection" timeout'
        branch_name: Optional branch name override.
        surrounding_lines: Number of context lines around each match.
        max_results: Number of search results to return.
        case_sensitive: Whether to perform case-sensitive matching.
        search_type: Type of search to perform.
        multi_term_operator: For multi_term searches, whether all terms or any term must match.
        file_extensions: File extensions to search (searches all text files if not specified).
        exclude_paths: Path patterns to exclude from search.

    Returns:
        JSON string containing the search results with enhanced metadata.

    Raises:
        ValueError: If Bitbucket client configuration is invalid.
    """
    try:
        # Import the search enums
        from ..bitbucket.client import MultiTermOperator, SearchType

        # Convert string literals to enums
        search_type_enum = SearchType(search_type)
        multi_term_operator_enum = MultiTermOperator(multi_term_operator)

        bitbucket = await get_bitbucket_fetcher(ctx)
        search_result = bitbucket.code_search(
            project_key=bitbucket_project_key,
            repository_slug=repository_slug,
            search_query=search_query,
            branch_name=branch_name,
            surrounding_lines=surrounding_lines,
            case_sensitive=case_sensitive,
            max_results=max_results,
            search_type=search_type_enum,
            multi_term_operator=multi_term_operator_enum,
            file_extensions=file_extensions,
            exclude_paths=exclude_paths,
        )
        return json.dumps({"success": True, **search_result}, indent=2)
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
            error_message = (
                f"An unexpected error occurred while running code search in "
                f"{bitbucket_project_key}/{repository_slug}. Error: {e}"
            )
            logger.exception("Unexpected error in bitbucket_code_search:")

        error_result = {
            "success": False,
            "error": error_message,
        }
        logger.log(log_level, f"bitbucket_code_search failed: {error_message}")
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
