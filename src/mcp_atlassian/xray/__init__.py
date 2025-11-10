"""Xray module for MCP Atlassian integration."""

from atlassian.xray import Xray

from .client import XrayClient
from .config import XrayConfig
from .user import MixUsers


class XrayFetcher(
    MixUsers,
    XrayClient,
):
    """
    The main Xray client class providing access to all Xray operations.

    The class follows the same mixin architecture pattern as JiraFetcher and
    ConfluenceFetcher, providing a unified interface for all Xray API operations
    while maintaining separation of concerns through focused mixins.
    """

    pass


__all__ = [
    "XrayClient",
    "XrayConfig",
    "XrayFetcher",
    "MixUsers",
    "Xray",
]
