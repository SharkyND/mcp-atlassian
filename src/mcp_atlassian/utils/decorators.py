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
    parse_extended_bool,
    resolve_read_only_mode,
)

# Maps a tool module path to:
#   (context_attr, request_state_header_attr, display_name)
_MODULE_TO_PRODUCT: dict[str, tuple[str, str, str]] = {
    "mcp_atlassian.servers.jira": (
        "jira_read_only",
        "jira_read_only_mode_header",
        "Jira",
    ),
    "mcp_atlassian.servers.confluence": (
        "confluence_read_only",
        "confluence_read_only_mode_header",
        "Confluence",
    ),
    "mcp_atlassian.servers.bitbucket": (
        "bitbucket_read_only",
        "bitbucket_read_only_mode_header",
        "Bitbucket",
    ),
}

logger = logging.getLogger(__name__)


F = TypeVar("F", bound=Callable[..., Awaitable[Any]])


def check_write_access(func: F) -> F:
    """
    Decorator for FastMCP tools to check if the application is in read-only mode.
    If in read-only mode, it raises a ValueError.
    Assumes the decorated function is async and has `ctx: Context` as its first argument.

    Per-product read-only flags are respected: a tool belonging to a specific product
    (Jira, Confluence, Bitbucket) uses that product's effective read-only state, which
    may differ from the global flag.  Priority (highest first):
      product-specific header > global header > product startup value > global effective.
    """
    # Determine the product for this tool once at decoration time.
    product_info: tuple[str, str, str] | None = _MODULE_TO_PRODUCT.get(
        getattr(func, "__module__", ""), None
    )

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

        request_state = None
        if (
            req_context
            and hasattr(req_context, "request")
            and hasattr(req_context.request, "state")
        ):
            request_state = req_context.request.state

        header_read_only = (
            getattr(request_state, "read_only_mode_header", None)
            if request_state is not None
            else None
        )

        # --- Global effective read-only (same logic as before) ---
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

        # --- Per-product override ---
        # If this tool belongs to a known product, resolve its effective read-only
        # using the same priority chain as _mcp_list_tools:
        #   product header > global header > product startup value > global effective
        if product_info is not None:
            ctx_attr, hdr_attr, product_name = product_info

            product_header = (
                getattr(request_state, hdr_attr, None)
                if request_state is not None
                else None
            )
            product_hdr_bool = parse_extended_bool(product_header)
            if product_hdr_bool is not None:
                # Product-specific header wins.
                effective_read_only = product_hdr_bool
            else:
                global_hdr_bool = parse_extended_bool(header_read_only)
                if global_hdr_bool is not None:
                    # Global header applies to this product (no product override).
                    effective_read_only = global_hdr_bool
                else:
                    # No header at all — check the startup-resolved product value.
                    product_startup = (
                        getattr(app_lifespan_ctx, ctx_attr, None)
                        if app_lifespan_ctx is not None
                        else None
                    )
                    if product_startup is not None:
                        effective_read_only = bool(product_startup)
                    # else: keep effective_read_only from global resolution above.

        if effective_read_only:
            tool_name = func.__name__
            action_description = tool_name.replace("_", " ")
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
