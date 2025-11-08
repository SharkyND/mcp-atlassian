"""
Utility functions for the MCP Atlassian integration.
This package provides various utility functions used throughout the codebase.
"""

from .date import parse_date
from .io import (
    get_cli_read_only_flag,
    get_env_read_only_flag,
    is_read_only_mode,
    resolve_read_only_mode,
)

# Export lifecycle utilities
from .lifecycle import (
    ensure_clean_exit,
    setup_signal_handlers,
)
from .logging import setup_logging

# Export OAuth utilities
from .oauth import OAuthConfig, configure_oauth_session
from .ssl import SSLIgnoreAdapter, configure_ssl_verification
from .urls import is_atlassian_cloud_url

# Export all utility functions for backward compatibility
__all__ = [
    "SSLIgnoreAdapter",
    "configure_ssl_verification",
    "is_atlassian_cloud_url",
    "is_read_only_mode",
    "get_cli_read_only_flag",
    "get_env_read_only_flag",
    "resolve_read_only_mode",
    "setup_logging",
    "parse_date",
    "OAuthConfig",
    "configure_oauth_session",
    "setup_signal_handlers",
    "ensure_clean_exit",
]
