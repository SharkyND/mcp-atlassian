from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from mcp_atlassian.bitbucket.config import BitbucketConfig
    from mcp_atlassian.confluence.config import ConfluenceConfig
    from mcp_atlassian.jira.config import JiraConfig
    from mcp_atlassian.xray.config import XrayConfig


@dataclass(frozen=True)
class MainAppContext:
    """
    Context holding fully configured Jira, Confluence, and Bitbucket configurations
    loaded from environment variables at server startup.
    These configurations include any global/default authentication details.
    """

    full_jira_config: JiraConfig | None = None
    full_confluence_config: ConfluenceConfig | None = None
    full_bitbucket_config: BitbucketConfig | None = None
    full_xray_config: XrayConfig | None = None

    read_only: bool = False
    cli_read_only: bool | None = None
    env_read_only: bool | None = None
    enabled_tools: list[str] | None = None

    # Per-product read_only overrides. When set, these take precedence over
    # the global read_only flag for the corresponding product. When None the
    # global flag applies.
    jira_read_only: bool | None = None
    confluence_read_only: bool | None = None
    bitbucket_read_only: bool | None = None
