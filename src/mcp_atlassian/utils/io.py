"""I/O utility functions for MCP Atlassian."""

from __future__ import annotations

import os
from typing import Final

TRUTHY_VALUES: Final[set[str]] = {"true", "1", "yes", "y", "on"}
FALSY_VALUES: Final[set[str]] = {"false", "0", "no", "n", "off"}


def parse_extended_bool(value: str | bool | None) -> bool | None:
    """Convert a string or boolean flag into a canonical bool value.

    Returns:
        True/False when the value is recognized, otherwise None.
    """
    if isinstance(value, bool):
        return value

    if value is None:
        return None

    normalized = value.strip().lower()
    if not normalized:
        return None

    if normalized in TRUTHY_VALUES:
        return True
    if normalized in FALSY_VALUES:
        return False
    return None


def get_env_read_only_flag() -> bool | None:
    """Return the READ_ONLY_MODE environment flag, if provided."""
    return parse_extended_bool(os.getenv("READ_ONLY_MODE"))


def get_cli_read_only_flag() -> bool | None:
    """Return the CLI read-only flag captured in CLI_READ_ONLY_MODE."""
    return parse_extended_bool(os.getenv("CLI_READ_ONLY_MODE"))


def resolve_read_only_mode(
    cli_read_only: bool | None,
    env_read_only: bool | None,
    header_read_only: str | bool | None,
) -> bool:
    """Resolve read-only mode across CLI, environment, and request header."""
    header_value = parse_extended_bool(header_read_only)
    if header_value is not None:
        return header_value

    if env_read_only is not None:
        return env_read_only

    if cli_read_only is not None:
        return cli_read_only

    return False


def is_read_only_mode() -> bool:
    """Check if the server is running in read-only mode by default."""
    return resolve_read_only_mode(
        cli_read_only=get_cli_read_only_flag(),
        env_read_only=get_env_read_only_flag(),
        header_read_only=None,
    )
