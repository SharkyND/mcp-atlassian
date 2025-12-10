import logging
from collections.abc import Awaitable, Callable
from functools import wraps
from typing import Any, TypeVar

import requests
from fastmcp import Context
from requests.exceptions import HTTPError

from mcp_atlassian.exceptions import MCPAtlassianAuthenticationError
from mcp_atlassian.utils.io import (
    get_cli_read_only_flag,
    get_env_read_only_flag,
    resolve_read_only_mode,
)

logger = logging.getLogger(__name__)


F = TypeVar("F", bound=Callable[..., Awaitable[Any]])


def check_write_access(func: F) -> F:
    """
    Decorator for FastMCP tools to check if the application is in read-only mode.
    If in read-only mode, it raises a ValueError.
    Assumes the decorated function is async and has `ctx: Context` as its first argument.
    """

    @wraps(func)
    async def wrapper(ctx: Context, *args: Any, **kwargs: Any) -> Any:
        req_context = getattr(ctx, "request_context", None)
        lifespan_ctx_dict = (
            req_context.lifespan_context if req_context else {}  # type: ignore[attr-defined]
        )
        app_lifespan_ctx = (
            lifespan_ctx_dict.get("app_lifespan_context")
            if isinstance(lifespan_ctx_dict, dict)
            else None
        )  # type: ignore

        if app_lifespan_ctx is not None:
            base_read_only = getattr(app_lifespan_ctx, "read_only", None)
            cli_read_only = getattr(app_lifespan_ctx, "cli_read_only", None)
            env_read_only = getattr(app_lifespan_ctx, "env_read_only", None)
        else:
            base_read_only = None
            cli_read_only = get_cli_read_only_flag()
            env_read_only = get_env_read_only_flag()

        header_read_only = None
        if (
            req_context
            and hasattr(req_context, "request")
            and hasattr(req_context.request, "state")
        ):
            header_read_only = getattr(
                req_context.request.state, "read_only_mode_header", None
            )

        effective_read_only = resolve_read_only_mode(
            cli_read_only=cli_read_only,
            env_read_only=env_read_only,
            header_read_only=header_read_only,
        )

        if (
            header_read_only is None
            and env_read_only is None
            and cli_read_only is None
            and base_read_only is not None
        ):
            effective_read_only = bool(base_read_only)

        if effective_read_only:
            tool_name = func.__name__
            action_description = tool_name.replace(
                "_", " "
            )  # e.g., "create_issue" -> "create issue"
            logger.warning(f"Attempted to call tool '{tool_name}' in read-only mode.")
            msg = f"Cannot {action_description} in read-only mode."
            raise ValueError(msg)

        return await func(ctx, *args, **kwargs)

    return wrapper  # type: ignore


def handle_atlassian_api_errors(service_name: str = "Atlassian API") -> Callable:
    """
    Decorator to handle common Atlassian API exceptions (Jira, Confluence, etc.).

    Args:
        service_name: Name of the service for error logging (e.g., "Jira API").
    """

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(self: Any, *args: Any, **kwargs: Any) -> Any:
            try:
                return func(self, *args, **kwargs)
            except HTTPError as http_err:
                if http_err.response is not None and http_err.response.status_code in [
                    401,
                    403,
                ]:
                    error_msg = (
                        f"Authentication failed for {service_name} "
                        f"({http_err.response.status_code}). "
                        "Token may be expired or invalid. Please verify credentials."
                    )
                    logger.error(error_msg)
                    raise MCPAtlassianAuthenticationError(error_msg) from http_err
                else:
                    operation_name = getattr(func, "__name__", "API operation")
                    logger.error(
                        f"HTTP error during {operation_name}: {http_err}",
                        exc_info=False,
                    )
                    raise http_err
            except KeyError as e:
                operation_name = getattr(func, "__name__", "API operation")
                logger.error(f"Missing key in {operation_name} results: {str(e)}")
                return []
            except requests.RequestException as e:
                operation_name = getattr(func, "__name__", "API operation")
                logger.error(f"Network error during {operation_name}: {str(e)}")
                return []
            except (ValueError, TypeError) as e:
                operation_name = getattr(func, "__name__", "API operation")
                logger.error(f"Error processing {operation_name} results: {str(e)}")
                return []
            except Exception as e:  # noqa: BLE001 - Intentional fallback with logging
                operation_name = getattr(func, "__name__", "API operation")
                logger.error(f"Unexpected error during {operation_name}: {str(e)}")
                logger.debug(
                    f"Full exception details for {operation_name}:", exc_info=True
                )
                return []

        return wrapper

    return decorator
