"""Main FastMCP server setup for Atlassian integration."""

import json
import logging
import os
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from typing import Any, Literal, Optional

from cachetools import TTLCache
from fastmcp import FastMCP, settings
from fastmcp.tools import Tool as FastMCPTool
from mcp.types import Tool as MCPTool
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from mcp_atlassian.bitbucket import BitbucketFetcher
from mcp_atlassian.bitbucket.config import BitbucketConfig
from mcp_atlassian.confluence import ConfluenceFetcher
from mcp_atlassian.confluence.config import ConfluenceConfig
from mcp_atlassian.jira import JiraFetcher
from mcp_atlassian.jira.config import JiraConfig
from mcp_atlassian.utils.environment import get_available_services
from mcp_atlassian.utils.io import is_read_only_mode
from mcp_atlassian.utils.logging import mask_sensitive
from mcp_atlassian.utils.prometheus_metrics import get_metrics, initialize_metrics
from mcp_atlassian.utils.tools import get_enabled_tools, should_include_tool
from mcp_atlassian.Xray import XrayFetcher
from mcp_atlassian.Xray.config import XrayConfig

from .bitbucket import bitbucket_mcp
from .confluence import confluence_mcp
from .context import MainAppContext
from .jira import jira_mcp
from .xray import xray_mcp

logger = logging.getLogger("mcp-atlassian.server.main")

# Initialize metrics immediately when module is loaded
pod_name = os.environ.get("POD_NAME")
initialize_metrics(pod_name)
logger.info(f"Metrics collection initialized for pod: {pod_name}")


async def health_check() -> JSONResponse:
    return JSONResponse({"status": "ok"})


async def metrics_endpoint(request: Request) -> Response:
    """Prometheus metrics endpoint for scraping."""
    metrics_collector = get_metrics()
    logger.debug(
        f"Metrics endpoint called. Collector: {metrics_collector}, Enabled: {metrics_collector.is_enabled if metrics_collector else 'N/A'}"
    )
    if not metrics_collector or not metrics_collector.is_enabled:
        return Response(
            "# Metrics collection not enabled\n",
            media_type="text/plain",
            status_code=503,
        )

    content, content_type = metrics_collector.generate_metrics()
    return Response(content, media_type=content_type)


@asynccontextmanager
async def main_lifespan(app: FastMCP[MainAppContext]) -> AsyncIterator[dict]:
    logger.info("Main Atlassian MCP server lifespan starting...")
    services = get_available_services()
    read_only = is_read_only_mode()
    enabled_tools = get_enabled_tools()

    loaded_jira_config: JiraConfig | None = None
    loaded_confluence_config: ConfluenceConfig | None = None
    loaded_bitbucket_config: BitbucketConfig | None = None
    loaded_xray_config: XrayConfig | None = None

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
                    "Jira URL found, but authentication is not fully configured. "
                    "Jira tools will be unavailable."
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
                    "Confluence URL found, but authentication is not fully configured. "
                    "Confluence tools will be unavailable."
                )
        except Exception as e:
            logger.error(f"Failed to load Confluence configuration: {e}", exc_info=True)

    if services.get("bitbucket"):
        try:
            bitbucket_config = BitbucketConfig.from_env()
            loaded_bitbucket_config = bitbucket_config
            logger.info(
                "Bitbucket configuration loaded and authentication is configured."
            )
        except Exception as e:
            logger.error(f"Failed to load Bitbucket configuration: {e}", exc_info=True)
    if services.get("xray"):
        try:
            xray_config = XrayConfig.from_env()
            if xray_config.is_auth_configured():
                loaded_xray_config = xray_config
                logger.info(
                    "Xray configuration loaded and authentication is configured."
                )
            else:
                logger.warning(
                    "Xray URL found, but authentication is not fully configured. "
                    "Xray tools will be unavailable."
                )
        except Exception as e:
            logger.error(f"Failed to load Xray configuration: {e}", exc_info=True)

    app_context = MainAppContext(
        full_jira_config=loaded_jira_config,
        full_confluence_config=loaded_confluence_config,
        full_bitbucket_config=loaded_bitbucket_config,
        full_xray_config=loaded_xray_config,
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
            if loaded_bitbucket_config:
                logger.debug("Cleaning up Bitbucket resources...")
            if loaded_xray_config:
                logger.debug("Cleaning up Xray resources...")
        except Exception as e:
            logger.error(f"Error during cleanup: {e}", exc_info=True)
        logger.info("Main Atlassian MCP server lifespan shutdown complete.")


class AtlassianMCP(FastMCP[MainAppContext]):
    """Custom FastMCP server class for Atlassian integration with tool filtering."""

    async def _mcp_list_tools(self) -> list[MCPTool]:
        # Filter tools based on enabled_tools, read_only mode, and service configuration
        # from the lifespan context.
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

        header_based_services = {
            "jira": False,
            "confluence": False,
            "bitbucket": False,
            "xray": False,
        }
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
            f"_main_mcp_list_tools: read_only={read_only}, "
            f"enabled_tools_filter={enabled_tools_filter}, "
            f"header_services={header_based_services}"
        )

        all_tools: dict[str, FastMCPTool] = await self.get_tools()
        logger.debug(
            f"Aggregated {len(all_tools)} tools before filtering: "
            f"{list(all_tools.keys())}"
        )

        filtered_tools: list[MCPTool] = []
        for registered_name, tool_obj in all_tools.items():
            tool_tags = tool_obj.tags

            if not should_include_tool(registered_name, enabled_tools_filter):
                logger.debug(f"Excluding tool '{registered_name}' (not enabled)")
                continue

            if tool_obj and read_only and "write" in tool_tags:
                logger.debug(
                    f"Excluding tool '{registered_name}' due to read-only mode "
                    f"and 'write' tag"
                )
                continue

            # Exclude Jira/Confluence tools if config is not fully authenticated
            is_jira_tool = "jira" in tool_tags
            is_confluence_tool = "confluence" in tool_tags
            is_bitbucket_tool = "bitbucket" in tool_tags
            is_xray_tool = "xray" in tool_tags
            service_configured_and_available = True
            if app_lifespan_state:
                jira_available = (
                    app_lifespan_state.full_jira_config is not None
                ) or header_based_services.get("jira", False)
                confluence_available = (
                    app_lifespan_state.full_confluence_config is not None
                ) or header_based_services.get("confluence", False)
                bitbucket_available = (
                    app_lifespan_state.full_bitbucket_config is not None
                ) or header_based_services.get("bitbucket", False)
                xray_available = (
                    app_lifespan_state.full_xray_config is not None
                ) or header_based_services.get("xray", False)

                if is_jira_tool and not jira_available:
                    logger.debug(
                        f"Excluding Jira tool '{registered_name}' as Jira "
                        f"configuration/authentication is incomplete and no "
                        f"header-based auth available."
                    )
                    service_configured_and_available = False

                if is_confluence_tool and not confluence_available:
                    logger.debug(
                        f"Excluding Confluence tool '{registered_name}' as Confluence "
                        f"configuration/authentication is incomplete and no "
                        f"header-based auth available."
                    )
                    service_configured_and_available = False

                if is_bitbucket_tool and not bitbucket_available:
                    logger.debug(
                        f"Excluding Bitbucket tool '{registered_name}' as Bitbucket configuration/authentication is incomplete and no header-based auth available."
                    )
                    service_configured_and_available = False

                if is_xray_tool and not xray_available:
                    logger.debug(
                        f"Excluding Xray tool '{registered_name}' as Xray configuration/authentication is incomplete and no header-based auth available."
                    )
                    service_configured_and_available = False

            elif (
                is_jira_tool or is_confluence_tool or is_bitbucket_tool or is_xray_tool
            ):
                jira_available = header_based_services.get("jira", False)
                confluence_available = header_based_services.get("confluence", False)
                bitbucket_available = header_based_services.get("bitbucket", False)
                xray_available = header_based_services.get("xray", False)

                if is_jira_tool and not jira_available:
                    logger.debug(
                        f"Excluding Jira tool '{registered_name}' as no Jira "
                        f"authentication available."
                    )
                    service_configured_and_available = False
                if is_confluence_tool and not confluence_available:
                    logger.debug(
                        f"Excluding Confluence tool '{registered_name}' as no "
                        f"Confluence authentication available."
                    )
                    service_configured_and_available = False
                if is_bitbucket_tool and not bitbucket_available:
                    logger.debug(
                        f"Excluding Bitbucket tool '{registered_name}' as no Bitbucket authentication available."
                    )
                    service_configured_and_available = False
                if is_xray_tool and not xray_available:
                    logger.debug(
                        f"Excluding Xray tool '{registered_name}' as no Xray authentication available."
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
        stateless_http: bool = False,
        **kwargs: Any,
    ) -> "Starlette":
        user_token_mw = Middleware(UserTokenMiddleware, mcp_server_ref=self)
        final_middleware_list = [user_token_mw]
        if middleware:
            final_middleware_list.extend(middleware)
        app = super().http_app(
            path=path,
            middleware=final_middleware_list,
            transport=transport,
            stateless_http=stateless_http,
            **kwargs,
        )

        # Add metrics endpoint
        app.router.routes.append(Route("/metrics", metrics_endpoint, methods=["GET"]))

        return app


token_validation_cache: TTLCache[
    int,
    tuple[
        bool,
        str | None,
        JiraFetcher | None,
        ConfluenceFetcher | None,
        BitbucketFetcher | None,
        XrayFetcher | None,
    ],
] = TTLCache(maxsize=100, ttl=300)


class UserTokenMiddleware:
    """ASGI-compliant middleware to extract Atlassian user tokens/credentials from
    Authorization headers."""

    def __init__(
        self, app: Any, mcp_server_ref: Optional["AtlassianMCP"] = None
    ) -> None:
        self.app = app
        self.mcp_server_ref = mcp_server_ref
        if not self.mcp_server_ref:
            logger.warning(
                "UserTokenMiddleware initialized without mcp_server_ref. "
                "Path matching for MCP endpoint might fail if settings are needed."
            )

    async def __call__(self, scope: dict, receive: Callable, send: Callable) -> None:
        """ASGI-compliant middleware following official ASGI specification."""
        logger.debug(
            f"UserTokenMiddleware.__call__: ENTERED for scope "
            f"type='{scope.get('type')}', path='{scope.get('path', 'N/A')}', "
            f"method='{scope.get('method', 'N/A')}'"
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

        # Start metrics tracking for HTTP request
        metrics_collector = get_metrics()
        request_path = scope.get("path", "")
        method = scope.get("method", "")
        metrics_context = None

        # Start request tracking
        if metrics_collector:
            metrics_context = metrics_collector.start_request_tracking(
                method, request_path
            )

        mcp_server_instance = self.mcp_server_ref
        if mcp_server_instance is None:
            logger.debug(
                "UserTokenMiddleware.__call__: self.mcp_server_ref is None. "
                "Skipping MCP auth logic."
            )
            await self.app(scope_copy, receive, send)
            return

        mcp_path = settings.streamable_http_path.rstrip("/")
        request_path = scope.get("path", "").rstrip("/")
        method = scope.get("method", "")

        logger.debug(
            f"UserTokenMiddleware.__call__: Comparing request_path='{request_path}' "
            f"with mcp_path='{mcp_path}'. Request method='{method}'"
        )

        if request_path == mcp_path and method == "POST":
            # Parse headers from scope (headers are byte tuples per ASGI spec)
            headers = dict(scope.get("headers", []))

            # Extract User-Agent header for tracking and make it lowercase
            user_agent_header = headers.get(b"user-agent")
            user_agent = (
                user_agent_header.decode("latin-1") if user_agent_header else None
            )
            user_agent = user_agent.lower() if user_agent else None

            # get username if present
            username_header = headers.get(b"x-atlassian-username")
            username = username_header.decode("latin-1") if username_header else None
            username = username.lower() if username else None

            # Check username requirement - validate that at least one username is provided
            if os.environ.get("REQUIRE_USERNAME") == "true":
                if not username:
                    logger.error(
                        "Username validation failed: REQUIRE_USERNAME is enabled but no username header provided"
                    )
                    error_response = json.dumps(
                        {
                            "error": "Username required",
                            "message": '"X-Atlassian-Username" must be provided in headers when REQUIRE_USERNAME is enabled',
                        }
                    ).encode()

                    await send(
                        {
                            "type": "http.response.start",
                            "status": 400,
                            "headers": [(b"content-type", b"application/json")],
                        }
                    )
                    await send({"type": "http.response.body", "body": error_response})
                    return

            # Convert bytes to strings (ASGI headers are always bytes)
            auth_header = headers.get(b"authorization")
            auth_header_str = auth_header.decode("latin-1") if auth_header else None

            cloud_id_header = headers.get(b"x-atlassian-cloud-id")
            cloud_id_header_str = (
                cloud_id_header.decode("latin-1") if cloud_id_header else None
            )

            # Extract additional Atlassian headers for service availability detection
            jira_token_header = headers.get(b"x-atlassian-jira-personal-token")
            jira_token_header_str = (
                jira_token_header.decode("latin-1") if jira_token_header else None
            )

            jira_url_header = headers.get(b"x-atlassian-jira-url")
            jira_url_header_str = (
                jira_url_header.decode("latin-1") if jira_url_header else None
            )

            confluence_token_header = headers.get(
                b"x-atlassian-confluence-personal-token"
            )
            confluence_token_header_str = (
                confluence_token_header.decode("latin-1")
                if confluence_token_header
                else None
            )

            confluence_url_header = headers.get(b"x-atlassian-confluence-url")
            confluence_url_header_str = (
                confluence_url_header.decode("latin-1")
                if confluence_url_header
                else None
            )

            bitbucket_token_header = headers.get(
                b"x-atlassian-bitbucket-personal-token"
            )
            bitbucket_token_header_str = (
                bitbucket_token_header.decode("latin-1")
                if bitbucket_token_header
                else None
            )

            bitbucket_url_header = headers.get(b"x-atlassian-bitbucket-url")
            bitbucket_url_header_str = (
                bitbucket_url_header.decode("latin-1") if bitbucket_url_header else None
            )
            xray_token_header = headers.get(b"x-atlassian-xray-personal-token")
            xray_token_header_str = (
                xray_token_header.decode("latin-1") if xray_token_header else None
            )
            xray_url_header = headers.get(b"x-atlassian-xray-url")
            xray_url_header_str = (
                xray_url_header.decode("latin-1") if xray_url_header else None
            )

            # Track service-specific user activity for business intelligence
            activity_type = None
            cached_messages = []
            message_index = 0

            # Create a wrapper to cache the request body without consuming it
            async def cached_receive() -> dict:
                nonlocal cached_messages, message_index

                # If we already have this message cached, return it
                if message_index < len(cached_messages):
                    message = cached_messages[message_index]
                    message_index += 1
                    return message

                # Otherwise, receive and cache the message
                message = await receive()
                cached_messages.append(message)
                message_index += 1
                return message

            if metrics_collector:
                try:
                    # Read the request body to extract activity type
                    body_parts = []
                    while True:
                        message = await cached_receive()
                        if message["type"] == "http.request":
                            body_parts.append(message.get("body", b""))
                            if not message.get("more_body", False):
                                break
                        else:
                            break

                    # Combine all body parts
                    full_body = b"".join(body_parts)
                    if full_body:
                        body_data = json.loads(full_body.decode("utf-8"))
                        activity_type = body_data.get("params", {}).get("name")

                    # Reset message index for the actual app to consume from the beginning
                    message_index = 0

                except (json.JSONDecodeError, UnicodeDecodeError, KeyError):
                    # If we can't parse the body, continue without activity type
                    activity_type = None
                    # Reset message index for the actual app
                    message_index = 0
                # Only track when service-specific headers are provided (header-based auth)
                # Track activity only once per request, using the appropriate service

                # Determine which service to use based on activity type, or fallback to first available
                service_to_use = None
                username_to_use = None

                if activity_type:
                    if (
                        activity_type.startswith("jira_")
                        and jira_token_header_str
                        and jira_url_header_str
                    ):
                        service_to_use = "jira"
                        username_to_use = username
                    elif (
                        activity_type.startswith("confluence_")
                        and confluence_token_header_str
                        and confluence_url_header_str
                    ):
                        service_to_use = "confluence"
                        username_to_use = username
                    elif (
                        activity_type.startswith("bitbucket_")
                        and bitbucket_token_header_str
                        and bitbucket_url_header_str
                    ):
                        service_to_use = "bitbucket"
                        username_to_use = username

                # If no specific service determined from activity type, use first available service
                if not service_to_use:
                    if jira_token_header_str and jira_url_header_str:
                        service_to_use = "jira"
                        username_to_use = username
                        activity_type = activity_type or "jira_access"
                    elif confluence_token_header_str and confluence_url_header_str:
                        service_to_use = "confluence"
                        username_to_use = username
                        activity_type = activity_type or "confluence_access"
                    elif bitbucket_token_header_str and bitbucket_url_header_str:
                        service_to_use = "bitbucket"
                        username_to_use = username
                        activity_type = activity_type or "bitbucket_access"

                # Track the activity for the determined service
                if service_to_use:
                    metrics_collector.track_user_activity(
                        username=username_to_use,
                        user_agent=user_agent,
                        activity_type=activity_type,
                    )

            token_for_log = mask_sensitive(
                auth_header_str.split(" ", 1)[1].strip()
                if auth_header_str and " " in auth_header_str
                else auth_header_str
            )
            logger.debug(
                f"UserTokenMiddleware: Path='{request_path}', "
                f"AuthHeader='{mask_sensitive(auth_header_str)}', "
                f"ParsedToken(masked)='{token_for_log}', "
                f"CloudId='{cloud_id_header_str}'"
            )

            # Extract and save cloudId if provided
            if cloud_id_header_str and cloud_id_header_str.strip():
                scope_copy["state"]["user_atlassian_cloud_id"] = (
                    cloud_id_header_str.strip()
                )
                logger.debug(
                    f"UserTokenMiddleware: Extracted cloudId from header: "
                    f"{cloud_id_header_str.strip()}"
                )
            else:
                scope_copy["state"]["user_atlassian_cloud_id"] = None
                logger.debug(
                    "UserTokenMiddleware: No cloudId header provided, "
                    "will use global config"
                )
            service_headers = {}
            if jira_token_header_str:
                service_headers["X-Atlassian-Jira-Personal-Token"] = (
                    jira_token_header_str
                )
            if jira_url_header_str:
                service_headers["X-Atlassian-Jira-Url"] = jira_url_header_str
            if confluence_token_header_str:
                service_headers["X-Atlassian-Confluence-Personal-Token"] = (
                    confluence_token_header_str
                )
            if confluence_url_header_str:
                service_headers["X-Atlassian-Confluence-Url"] = (
                    confluence_url_header_str
                )
            if bitbucket_token_header_str:
                service_headers["X-Atlassian-Bitbucket-Personal-Token"] = (
                    bitbucket_token_header_str
                )
            if bitbucket_url_header_str:
                service_headers["X-Atlassian-Bitbucket-Url"] = bitbucket_url_header_str
            if xray_token_header_str:
                service_headers["X-Atlassian-Xray-Personal-Token"] = (
                    xray_token_header_str
                )
            if xray_url_header_str:
                service_headers["X-Atlassian-Xray-Url"] = xray_url_header_str

            scope_copy["state"]["atlassian_service_headers"] = service_headers
            if service_headers:
                logger.debug(
                    f"UserTokenMiddleware: Extracted service headers: "
                    f"{list(service_headers.keys())}"
                )

            # Check for mcp-session-id header for debugging
            mcp_session_id_header = headers.get(b"mcp-session-id")
            mcp_session_id = (
                mcp_session_id_header.decode("latin-1")
                if mcp_session_id_header
                else None
            )
            if mcp_session_id:
                logger.debug(
                    f"UserTokenMiddleware: MCP-Session-ID header found: "
                    f"{mcp_session_id}"
                )

            if auth_header_str and auth_header_str.startswith("Bearer "):
                token = auth_header_str.split(" ", 1)[1].strip()
                if not token:
                    # Send 401 response for empty Bearer token
                    await self._send_error_response(
                        send, "Unauthorized: Empty Bearer token", 401
                    )
                    return

                logger.debug(
                    f"UserTokenMiddleware.__call__: Bearer token extracted "
                    f"(masked): ...{mask_sensitive(token, 8)}"
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
                    await self._send_error_response(
                        send, "Unauthorized: Empty Token (PAT)", 401
                    )
                    return

                logger.debug(
                    f"UserTokenMiddleware.__call__: PAT (Token scheme) extracted "
                    f"(masked): ...{mask_sensitive(token, 8)}"
                )
                scope_copy["state"]["user_atlassian_token"] = token
                scope_copy["state"]["user_atlassian_auth_type"] = "pat"
                scope_copy["state"]["user_atlassian_email"] = None
                logger.debug(
                    "UserTokenMiddleware.__call__: Set scope state for PAT auth."
                )
            elif auth_header_str:
                auth_type = (
                    auth_header_str.split(" ", 1)[0]
                    if " " in auth_header_str
                    else "UnknownType"
                )
                logger.warning(
                    f"Unsupported Authorization type for {request_path}: {auth_type}"
                )
                await self._send_error_response(
                    send,
                    "Unauthorized: Only 'Bearer <OAuthToken>' or 'Token <PAT>' "
                    "types are supported.",
                    401,
                )
                return
            else:
                if (
                    (jira_token_header_str and jira_url_header_str)
                    or (confluence_token_header_str and confluence_url_header_str)
                    or (xray_token_header_str and xray_url_header_str)
                ):
                    logger.debug(
                        f"Header-based authentication detected for {request_path}. "
                        f"Setting PAT auth type."
                    )
                    scope_copy["state"]["user_atlassian_auth_type"] = "pat"
                    scope_copy["state"]["user_atlassian_email"] = None
                else:
                    logger.debug(
                        f"No Authorization header provided for {request_path}. "
                        f"Will proceed with global/fallback server configuration "
                        f"if applicable."
                    )

        # Create a safe send wrapper to handle client disconnections and track metrics
        response_status = 200  # Default status

        async def safe_send(message: dict) -> None:
            nonlocal response_status
            try:
                # Track response status for metrics
                if message.get("type") == "http.response.start":
                    response_status = message.get("status", 200)

                await send(message)
            except (ConnectionResetError, BrokenPipeError, OSError) as e:
                # Client disconnected - log but don't propagate to avoid ASGI violations
                logger.debug(
                    f"Client disconnected during response: {type(e).__name__}: {e}"
                )
                # Don't re-raise - this prevents the ASGI protocol violation
                return
            except Exception:
                # Re-raise unexpected errors
                raise

        # Continue with the request using the modified scope and cached receive
        receive_func = cached_receive if "cached_receive" in locals() else receive
        await self.app(scope_copy, receive_func, safe_send)

        # End metrics tracking
        if metrics_collector and metrics_context:
            metrics_collector.end_request_tracking(metrics_context, response_status)

        logger.debug(
            f"UserTokenMiddleware.__call__: EXITED for request path='{request_path}'"
        )

    async def _send_error_response(
        self, send: Callable, error_message: str, status_code: int
    ) -> None:
        """Send an HTTP error response following ASGI protocol."""
        try:
            response_body = f'{{"error": "{error_message}"}}'.encode()

            await send(
                {
                    "type": "http.response.start",
                    "status": status_code,
                    "headers": [
                        [b"content-type", b"application/json"],
                        [b"content-length", str(len(response_body)).encode()],
                    ],
                }
            )

            await send(
                {
                    "type": "http.response.body",
                    "body": response_body,
                }
            )
        except (ConnectionResetError, BrokenPipeError, OSError) as e:
            # Client disconnected during error response - log but don't propagate
            logger.debug(
                f"Client disconnected during error response: {type(e).__name__}: {e}"
            )
        except Exception:
            # Re-raise unexpected errors
            raise


main_mcp = AtlassianMCP(name="Atlassian MCP")
# Set the lifespan after construction to avoid deprecation warnings
main_mcp._lifespan = main_lifespan
main_mcp.mount(xray_mcp, prefix="xray")
main_mcp.mount(jira_mcp, prefix="jira")
main_mcp.mount(confluence_mcp, prefix="confluence")
main_mcp.mount(bitbucket_mcp, prefix="bitbucket")


@main_mcp.custom_route("/healthz", methods=["GET"], include_in_schema=False)
async def _health_check_route(request: Request) -> JSONResponse:
    return await health_check()


@main_mcp.custom_route("/readyz", methods=["GET"], include_in_schema=False)
async def _ready_check_route(request: Request) -> JSONResponse:
    """Readiness check for Kubernetes probes."""
    return JSONResponse({"status": "ready", "server": "mcp-atlassian"})
