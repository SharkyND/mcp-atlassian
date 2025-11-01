"""Bitbucket module for MCP Atlassian integration."""

from atlassian.bitbucket import Bitbucket

from .branches import BranchesMixin
from .client import BitbucketClient
from .config import BitbucketConfig
from .pullrequests import PullRequestsMixin
from .repositories import RepositoriesMixin
from .users import UsersMixin
from .workspaces import WorkspacesMixin


class BitbucketFetcher(
    UsersMixin,
    WorkspacesMixin,
    RepositoriesMixin,
    BranchesMixin,
    PullRequestsMixin,
):
    """
    The main Bitbucket client class providing access to all Bitbucket operations.

    This class inherits from multiple mixins that provide specific functionality:
    - UsersMixin: User-related operations and authentication validation
    - WorkspacesMixin: Workspace-related operations and filtering
    - RepositoriesMixin: Repository operations, file content, and directory listing
    - BranchesMixin: Branch operations and commit history
    - PullRequestsMixin: Pull request operations and related functionality

    The class follows the same mixin architecture pattern as JiraFetcher and ConfluenceFetcher,
    providing a unified interface for all Bitbucket API operations while maintaining
    separation of concerns through focused mixins.
    """

    pass


__all__ = [
    "BitbucketClient",
    "BitbucketConfig",
    "BitbucketFetcher",
    "UsersMixin",
    "WorkspacesMixin",
    "RepositoriesMixin",
    "BranchesMixin",
    "PullRequestsMixin",
    "Bitbucket",
]
