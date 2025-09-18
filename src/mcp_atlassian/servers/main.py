"""Main FastMCP server setup for Atlassian integration."""

import logging
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from typing import Any, Literal, Optional

from cachetools import TTLCache
from fastmcp import FastMCP
from fastmcp.tools import Tool as FastMCPTool
from mcp.types import Tool as MCPTool
from mcp_atlassian.confluence import ConfluenceFetcher
from mcp_atlassian.confluence.config import ConfluenceConfig
from mcp_atlassian.jira import JiraFetcher
from mcp_atlassian.jira.config import JiraConfig
from mcp_atlassian.utils.environment import get_available_services
from mcp_atlassian.utils.io import is_read_only_mode
from mcp_atlassian.utils.logging import mask_sensitive
from mcp_atlassian.utils.tools import get_enabled_tools, should_include_tool
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from .confluence import confluence_mcp
from .context import MainAppContext
from .jira import jira_mcp

logger = logging.getLogger("mcp-atlassian.server.main")


async def health_check(request: Request) -> JSONResponse:
    return JSONResponse({"status": "ok"})


@asynccontextmanager
async def main_lifespan(app: FastMCP[MainAppContext]) -> AsyncIterator[dict]:
    logger.info("Main Atlassian MCP server lifespan starting...")
    services = get_available_services()
    read_only = is_read_only_mode()
    enabled_tools = get_enabled_tools()

    loaded_jira_config: JiraConfig | None = None
    loaded_confluence_config: ConfluenceConfig | None = None

    if services.get("jira"):
        try:
            jira_config = JiraConfig.from_env()
            if jira_config.is_auth_configured():
                loaded_jira_config = jira_config
                logger.info(
                    "Jira configuration loaded and authentication is configured."
                )
            else:
                logger.warning(
                    "Jira URL found, but authentication is not fully configured. Jira tools will be unavailable."
                )
        except Exception as e:
            logger.error(f"Failed to load Jira configuration: {e}", exc_info=True)

    if services.get("confluence"):
        try:
            confluence_config = ConfluenceConfig.from_env()
            if confluence_config.is_auth_configured():
                loaded_confluence_config = confluence_config
                logger.info(
                    "Confluence configuration loaded and authentication is configured."
                )
            else:
                logger.warning(
                    "Confluence URL found, but authentication is not fully configured. Confluence tools will be unavailable."
                )
        except Exception as e:
            logger.error(f"Failed to load Confluence configuration: {e}", exc_info=True)

    app_context = MainAppContext(
        full_jira_config=loaded_jira_config,
        full_confluence_config=loaded_confluence_config,
        read_only=read_only,
        enabled_tools=enabled_tools,
    )
    logger.info(f"Read-only mode: {'ENABLED' if read_only else 'DISABLED'}")
    logger.info(f"Enabled tools filter: {enabled_tools or 'All tools enabled'}")

    try:
        yield {"app_lifespan_context": app_context}
    except Exception as e:
        logger.error(f"Error during lifespan: {e}", exc_info=True)
        raise
    finally:
        logger.info("Main Atlassian MCP server lifespan shutting down...")
        # Perform any necessary cleanup here
        try:
            # Close any open connections if needed
            if loaded_jira_config:
                logger.debug("Cleaning up Jira resources...")
            if loaded_confluence_config:
                logger.debug("Cleaning up Confluence resources...")
        except Exception as e:
            logger.error(f"Error during cleanup: {e}", exc_info=True)
        logger.info("Main Atlassian MCP server lifespan shutdown complete.")


class AtlassianMCP(FastMCP[MainAppContext]):
    """Custom FastMCP server class for Atlassian integration with tool filtering."""

    async def _mcp_list_tools(self) -> list[MCPTool]:
        # Filter tools based on enabled_tools, read_only mode, and service configuration from the lifespan context.
        req_context = self._mcp_server.request_context
        if req_context is None or req_context.lifespan_context is None:
            logger.warning(
                "Lifespan context not available during _main_mcp_list_tools call."
            )
            return []

        lifespan_ctx_dict = req_context.lifespan_context
        app_lifespan_state: MainAppContext | None = (
            lifespan_ctx_dict.get("app_lifespan_context")
            if isinstance(lifespan_ctx_dict, dict)
            else None
        )
        read_only = (
            getattr(app_lifespan_state, "read_only", False)
            if app_lifespan_state
            else False
        )
        enabled_tools_filter = (
            getattr(app_lifespan_state, "enabled_tools", None)
            if app_lifespan_state
            else None
        )

        header_based_services = {"jira": False, "confluence": False}
        if hasattr(req_context, "request") and hasattr(req_context.request, "state"):
            service_headers = getattr(
                req_context.request.state, "atlassian_service_headers", {}
            )
            if service_headers:
                header_based_services = get_available_services(service_headers)
                logger.debug(
                    f"Header-based service availability: {header_based_services}"
                )

        logger.debug(
            f"_main_mcp_list_tools: read_only={read_only}, enabled_tools_filter={enabled_tools_filter}, header_services={header_based_services}"
        )

        all_tools: dict[str, FastMCPTool] = await self.get_tools()
        logger.debug(
            f"Aggregated {len(all_tools)} tools before filtering: {list(all_tools.keys())}"
        )

        filtered_tools: list[MCPTool] = []
        for registered_name, tool_obj in all_tools.items():
            tool_tags = tool_obj.tags

            if not should_include_tool(registered_name, enabled_tools_filter):
                logger.debug(f"Excluding tool '{registered_name}' (not enabled)")
                continue

            if tool_obj and read_only and "write" in tool_tags:
                logger.debug(
                    f"Excluding tool '{registered_name}' due to read-only mode and 'write' tag"
                )
                continue

            # Exclude Jira/Confluence tools if config is not fully authenticated
            is_jira_tool = "jira" in tool_tags
            is_confluence_tool = "confluence" in tool_tags
            service_configured_and_available = True
            if app_lifespan_state:
                jira_available = (
                    app_lifespan_state.full_jira_config is not None
                ) or header_based_services.get("jira", False)
                confluence_available = (
                    app_lifespan_state.full_confluence_config is not None
                ) or header_based_services.get("confluence", False)

                if is_jira_tool and not jira_available:
                    logger.debug(
                        f"Excluding Jira tool '{registered_name}' as Jira configuration/authentication is incomplete and no header-based auth available."
                    )
                    service_configured_and_available = False
                if is_confluence_tool and not confluence_available:
                    logger.debug(
                        f"Excluding Confluence tool '{registered_name}' as Confluence configuration/authentication is incomplete and no header-based auth available."
                    )
                    service_configured_and_available = False
            elif is_jira_tool or is_confluence_tool:
                jira_available = header_based_services.get("jira", False)
                confluence_available = header_based_services.get("confluence", False)

                if is_jira_tool and not jira_available:
                    logger.debug(
                        f"Excluding Jira tool '{registered_name}' as no Jira authentication available."
                    )
                    service_configured_and_available = False
                if is_confluence_tool and not confluence_available:
                    logger.debug(
                        f"Excluding Confluence tool '{registered_name}' as no Confluence authentication available."
                    )
                    service_configured_and_available = False

            if not service_configured_and_available:
                continue

            filtered_tools.append(tool_obj.to_mcp_tool(name=registered_name))

        logger.debug(
            f"_main_mcp_list_tools: Total tools after filtering: {len(filtered_tools)}"
        )
        return filtered_tools

    def http_app(
        self,
        path: str | None = None,
        middleware: list[Middleware] | None = None,
        transport: Literal["streamable-http", "sse"] = "streamable-http",
    ) -> "Starlette":
        user_token_mw = Middleware(UserTokenMiddleware, mcp_server_ref=self)
        final_middleware_list = [user_token_mw]
        if middleware:
            final_middleware_list.extend(middleware)
        app = super().http_app(
            path=path, middleware=final_middleware_list, transport=transport
        )
        return app


token_validation_cache: TTLCache[
    int, tuple[bool, str | None, JiraFetcher | None, ConfluenceFetcher | None]
] = TTLCache(maxsize=100, ttl=300)


class UserTokenMiddleware:
    """ASGI-compliant middleware to extract Atlassian user tokens/credentials from Authorization headers."""

    def __init__(
        self, app: Any, mcp_server_ref: Optional["AtlassianMCP"] = None
    ) -> None:
        self.app = app
        self.mcp_server_ref = mcp_server_ref
        if not self.mcp_server_ref:
            logger.warning(
                "UserTokenMiddleware initialized without mcp_server_ref. Path matching for MCP endpoint might fail if settings are needed."
            )

    async def __call__(self, scope: dict, receive: Callable, send: Callable) -> None:
        """ASGI-compliant middleware following official ASGI specification."""
        logger.debug(
            f"UserTokenMiddleware.__call__: ENTERED for scope type='{scope.get('type')}', path='{scope.get('path', 'N/A')}', method='{scope.get('method', 'N/A')}'"
        )

        if scope["type"] != "http":
            # For non-HTTP requests, pass through directly
            await self.app(scope, receive, send)
            return

        # According to ASGI spec, middleware should copy scope when modifying it
        scope_copy = scope.copy()

        # Ensure state exists in scope - this is where Starlette stores request state
        if "state" not in scope_copy:
            scope_copy["state"] = {}

        mcp_server_instance = self.mcp_server_ref
        if mcp_server_instance is None:
            logger.debug(
                "UserTokenMiddleware.__call__: self.mcp_server_ref is None. Skipping MCP auth logic."
            )
            await self.app(scope_copy, receive, send)
            return

        mcp_path = mcp_server_instance.settings.streamable_http_path.rstrip("/")
        request_path = scope.get("path", "").rstrip("/")
        method = scope.get("method", "")

        logger.debug(
            f"UserTokenMiddleware.__call__: Comparing request_path='{request_path}' with mcp_path='{mcp_path}'. Request method='{method}'"
        )

        if request_path == mcp_path and method == "POST":
            # Parse headers from scope (headers are byte tuples per ASGI spec)
            headers = dict(scope.get("headers", []))

            # Convert bytes to strings (ASGI headers are always bytes)
            auth_header = headers.get(b"authorization")
            auth_header_str = auth_header.decode("latin-1") if auth_header else None

            cloud_id_header = headers.get(b"x-atlassian-cloud-id")
            cloud_id_header_str = cloud_id_header.decode("latin-1") if cloud_id_header else None

            # Extract additional Atlassian headers for service availability detection
            jira_token_header = headers.get(b"x-atlassian-jira-personal-token")
            jira_token_header_str = jira_token_header.decode("latin-1") if jira_token_header else None

            jira_url_header = headers.get(b"x-atlassian-jira-url")
            jira_url_header_str = jira_url_header.decode("latin-1") if jira_url_header else None

            confluence_token_header = headers.get(b"x-atlassian-confluence-personal-token")
            confluence_token_header_str = confluence_token_header.decode("latin-1") if confluence_token_header else None

            confluence_url_header = headers.get(b"x-atlassian-confluence-url")
            confluence_url_header_str = confluence_url_header.decode("latin-1") if confluence_url_header else None

            token_for_log = mask_sensitive(
                auth_header_str.split(" ", 1)[1].strip()
                if auth_header_str and " " in auth_header_str
                else auth_header_str
            )
            logger.debug(
                f"UserTokenMiddleware: Path='{request_path}', AuthHeader='{mask_sensitive(auth_header_str)}', ParsedToken(masked)='{token_for_log}', CloudId='{cloud_id_header_str}'"
            )

            # Extract and save cloudId if provided
            if cloud_id_header_str and cloud_id_header_str.strip():
                scope_copy["state"]["user_atlassian_cloud_id"] = cloud_id_header_str.strip()
                logger.debug(
                    f"UserTokenMiddleware: Extracted cloudId from header: {cloud_id_header_str.strip()}"
                )
            else:
                scope_copy["state"]["user_atlassian_cloud_id"] = None
                logger.debug(
                    "UserTokenMiddleware: No cloudId header provided, will use global config"
                )

            service_headers = {}
            if jira_token_header_str:
                service_headers["X-Atlassian-Jira-Personal-Token"] = jira_token_header_str
            if jira_url_header_str:
                service_headers["X-Atlassian-Jira-Url"] = jira_url_header_str
            if confluence_token_header_str:
                service_headers["X-Atlassian-Confluence-Personal-Token"] = confluence_token_header_str
            if confluence_url_header_str:
                service_headers["X-Atlassian-Confluence-Url"] = confluence_url_header_str

            scope_copy["state"]["atlassian_service_headers"] = service_headers
            if service_headers:
                logger.debug(
                    f"UserTokenMiddleware: Extracted service headers: {list(service_headers.keys())}"
                )

            # Check for mcp-session-id header for debugging
            mcp_session_id_header = headers.get(b"mcp-session-id")
            mcp_session_id = mcp_session_id_header.decode("latin-1") if mcp_session_id_header else None
            if mcp_session_id:
                logger.debug(
                    f"UserTokenMiddleware: MCP-Session-ID header found: {mcp_session_id}"
                )

            if auth_header_str and auth_header_str.startswith("Bearer "):
                token = auth_header_str.split(" ", 1)[1].strip()
                if not token:
                    # Send 401 response for empty Bearer token
                    await self._send_error_response(send, "Unauthorized: Empty Bearer token", 401)
                    return

                logger.debug(
                    f"UserTokenMiddleware.__call__: Bearer token extracted (masked): ...{mask_sensitive(token, 8)}"
                )
                scope_copy["state"]["user_atlassian_token"] = token
                scope_copy["state"]["user_atlassian_auth_type"] = "oauth"
                scope_copy["state"]["user_atlassian_email"] = None
                logger.debug(
                    f"UserTokenMiddleware.__call__: Set scope state (pre-validation): "
                    f"auth_type='oauth', token_present={bool(token)}"
                )
            elif auth_header_str and auth_header_str.startswith("Token "):
                token = auth_header_str.split(" ", 1)[1].strip()
                if not token:
                    # Send 401 response for empty Token (PAT)
                    await self._send_error_response(send, "Unauthorized: Empty Token (PAT)", 401)
                    return

                logger.debug(
                    f"UserTokenMiddleware.__call__: PAT (Token scheme) extracted (masked): ...{mask_sensitive(token, 8)}"
                )
                scope_copy["state"]["user_atlassian_token"] = token
                scope_copy["state"]["user_atlassian_auth_type"] = "pat"
                scope_copy["state"]["user_atlassian_email"] = None  # PATs don't carry email in the token itself
                logger.debug(
                    "UserTokenMiddleware.__call__: Set scope state for PAT auth."
                )
            elif auth_header_str:
                logger.warning(
                    f"Unsupported Authorization type for {request_path}: {auth_header_str.split(' ', 1)[0] if ' ' in auth_header_str else 'UnknownType'}"
                )
                await self._send_error_response(
                    send,
                    "Unauthorized: Only 'Bearer <OAuthToken>' or 'Token <PAT>' types are supported.",
                    401
                )
                return
            else:
                if (jira_token_header_str and jira_url_header_str) or (
                    confluence_token_header_str and confluence_url_header_str
                ):
                    logger.debug(
                        f"Header-based authentication detected for {request_path}. Setting PAT auth type."
                    )
                    scope_copy["state"]["user_atlassian_auth_type"] = "pat"
                    scope_copy["state"]["user_atlassian_email"] = None
                else:
                    logger.debug(
                        f"No Authorization header provided for {request_path}. Will proceed with global/fallback server configuration if applicable."
                    )

        # Create a safe send wrapper to handle client disconnections
        async def safe_send(message: dict) -> None:
            try:
                await send(message)
            except (ConnectionResetError, BrokenPipeError, OSError) as e:
                # Client disconnected - log but don't propagate to avoid ASGI violations
                logger.debug(f"Client disconnected during response: {type(e).__name__}: {e}")
                # Don't re-raise - this prevents the ASGI protocol violation
                return
            except Exception:
                # Re-raise unexpected errors
                raise

        # Continue with the request using the modified scope
        await self.app(scope_copy, receive, safe_send)

        logger.debug(
            f"UserTokenMiddleware.__call__: EXITED for request path='{request_path}'"
        )

    async def _send_error_response(self, send: Callable, error_message: str, status_code: int) -> None:
        """Send an HTTP error response following ASGI protocol."""
        try:
            response_body = f'{{"error": "{error_message}"}}'.encode("utf-8")

            await send({
                "type": "http.response.start",
                "status": status_code,
                "headers": [
                    [b"content-type", b"application/json"],
                    [b"content-length", str(len(response_body)).encode()],
                ],
            })

            await send({
                "type": "http.response.body",
                "body": response_body,
            })
        except (ConnectionResetError, BrokenPipeError, OSError) as e:
            # Client disconnected during error response - log but don't propagate
            logger.debug(f"Client disconnected during error response: {type(e).__name__}: {e}")
        except Exception:
            # Re-raise unexpected errors
            raise


main_mcp = AtlassianMCP(name="Atlassian MCP", lifespan=main_lifespan)
main_mcp.mount("jira", jira_mcp)
main_mcp.mount("confluence", confluence_mcp)


@main_mcp.custom_route("/healthz", methods=["GET"], include_in_schema=False)
async def _health_check_route(request: Request) -> JSONResponse:
    return await health_check(request)


logger.info("Added /healthz endpoint for Kubernetes probes")
