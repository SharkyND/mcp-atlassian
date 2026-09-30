"""Environment variable utility functions for MCP Atlassian."""

import logging
import os

logger = logging.getLogger("mcp-atlassian.utils.env")


def is_env_truthy(env_var_name: str, default: str = "") -> bool:
    """Check if environment variable is set to a standard truthy value.

    Considers 'true', '1', 'yes' as truthy values (case-insensitive).
    Used for most MCP environment variables.

    Args:
        env_var_name: Name of the environment variable to check
        default: Default value if environment variable is not set

    Returns:
        True if the environment variable is set to a truthy value, False otherwise
    """
    return os.getenv(env_var_name, default).lower() in ("true", "1", "yes")


def is_env_extended_truthy(env_var_name: str, default: str = "") -> bool:
    """Check if environment variable is set to an extended truthy value.

    Considers 'true', '1', 'yes', 'y', 'on' as truthy values (case-insensitive).
    Used for READ_ONLY_MODE and similar flags.

    Args:
        env_var_name: Name of the environment variable to check
        default: Default value if environment variable is not set

    Returns:
        True if the environment variable is set to a truthy value, False otherwise
    """
    return os.getenv(env_var_name, default).lower() in ("true", "1", "yes", "y", "on")


def is_env_ssl_verify(env_var_name: str, default: str = "true") -> bool:
    """Check SSL verification setting with secure defaults.

    Defaults to true unless explicitly set to false values.
    Used for SSL_VERIFY environment variables.

    Args:
        env_var_name: Name of the environment variable to check
        default: Default value if environment variable is not set

    Returns:
        True unless explicitly set to false values
    """
    return os.getenv(env_var_name, default).lower() not in ("false", "0", "no")


DEFAULT_HTTP_TIMEOUT_SECONDS = 30

# Atlassian SDK calls are synchronous, so every in-flight tool call occupies one
# worker thread for its full duration. Python's default executor sizes itself
# from ``os.cpu_count()``, which inside a container reports the *node's* CPUs
# rather than the cgroup quota (``os.process_cpu_count()`` only exists on 3.13+).
# Identical pods therefore get wildly different capacity depending on which node
# they land on, so the size is pinned explicitly instead.
DEFAULT_MAX_WORKER_THREADS = 32


def _get_positive_int_env(env_var_name: str, default: int, unit: str) -> int:
    """Read a positive integer from an environment variable.

    Values that are unset, blank, non-numeric, or non-positive fall back to the
    default rather than silently disabling the setting.

    Args:
        env_var_name: Name of the environment variable to read
        default: Value to use when the variable is unset or invalid
        unit: Human-readable unit used in warning messages (e.g. "seconds")

    Returns:
        A positive integer
    """
    raw_value = os.getenv(env_var_name)
    if raw_value is None or not raw_value.strip():
        return default
    try:
        value = int(raw_value)
    except ValueError:
        logger.warning(
            "Invalid %s=%r; expected an integer number of %s. Using %s.",
            env_var_name,
            raw_value,
            unit,
            default,
        )
        return default
    if value <= 0:
        logger.warning(
            "Invalid %s=%r; value must be positive. Using %s.",
            env_var_name,
            raw_value,
            default,
        )
        return default
    return value


def get_env_timeout(
    env_var_name: str, default: int = DEFAULT_HTTP_TIMEOUT_SECONDS
) -> int:
    """Read an HTTP timeout (in seconds) from an environment variable.

    Atlassian API calls block a worker thread for their full duration, so an
    unbounded timeout lets a single slow upstream request stall the server and
    trip Kubernetes liveness probes. Values that are unset, non-numeric, or
    non-positive fall back to the default rather than disabling the timeout.

    Args:
        env_var_name: Name of the environment variable to read
        default: Timeout to use when the variable is unset or invalid

    Returns:
        A positive timeout in seconds
    """
    return _get_positive_int_env(env_var_name, default, "seconds")


def get_max_worker_threads(
    env_var_name: str = "MCP_MAX_WORKER_THREADS",
    default: int = DEFAULT_MAX_WORKER_THREADS,
) -> int:
    """Read the worker-thread pool size used for blocking Atlassian calls.

    Args:
        env_var_name: Name of the environment variable to read
        default: Pool size to use when the variable is unset or invalid

    Returns:
        A positive worker count
    """
    return _get_positive_int_env(env_var_name, default, "threads")


def get_custom_headers(env_var_name: str) -> dict[str, str]:
    """Parse custom headers from environment variable containing comma-separated key=value pairs.

    Args:
        env_var_name: Name of the environment variable to read

    Returns:
        Dictionary of parsed headers

    Examples:
        >>> # With CUSTOM_HEADERS="X-Custom=value1,X-Other=value2"
        >>> parse_custom_headers("CUSTOM_HEADERS")
        {'X-Custom': 'value1', 'X-Other': 'value2'}
        >>> # With unset environment variable
        >>> parse_custom_headers("UNSET_VAR")
        {}
    """
    header_string = os.getenv(env_var_name)
    if not header_string or not header_string.strip():
        return {}

    headers = {}
    pairs = header_string.split(",")

    for pair in pairs:
        pair = pair.strip()
        if not pair:
            continue

        if "=" not in pair:
            continue

        key, value = pair.split("=", 1)  # Split on first = only
        key = key.strip()
        value = value.strip()

        if key:  # Only add if key is not empty
            headers[key] = value

    return headers
