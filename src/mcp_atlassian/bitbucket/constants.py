"""Bitbucket API constants and default values."""

# Default branch names to try when branch is not specified
DEFAULT_BRANCH_NAMES = ["main", "master", "develop"]

# Pull request states
PR_STATES = {
    "OPEN": "OPEN",
    "MERGED": "MERGED",
    "DECLINED": "DECLINED",
    "SUPERSEDED": "SUPERSEDED",
}

# Repository types
REPO_TYPES = {
    "GIT": "git",
    "HG": "hg",
}

# Bitbucket Cloud API base paths
CLOUD_API_BASE = "https://api.bitbucket.org/2.0"
CLOUD_WORKSPACE_PATH = "/workspaces"
CLOUD_REPOSITORIES_PATH = "/repositories"

# Default limits for paginated requests
DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE = 100

# File size limits (in bytes)
MAX_FILE_SIZE_BYTES = 1024 * 1024  # 1MB for file content retrieval

# Commit message length limit
MAX_COMMIT_MESSAGE_LENGTH = 1000
