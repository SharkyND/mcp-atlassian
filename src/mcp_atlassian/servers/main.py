"""Main FastMCP server setup for Atlassian integration."""

import asyncio
import json
import logging
import os
from collections.abc import AsyncIterator, Callable
from contextlib import AsyncExitStack, asynccontextmanager
from typing import Any, Literal, Optional
from urllib.parse import quote, urlparse

from cachetools import TTLCache
from fastmcp import FastMCP, settings
from fastmcp.tools import Tool as FastMCPTool
from mcp.types import Tool as MCPTool
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Mount, Route

from mcp_atlassian.bitbucket import BitbucketFetcher
from mcp_atlassian.bitbucket.config import BitbucketConfig
from mcp_atlassian.confluence import ConfluenceFetcher
from mcp_atlassian.confluence.config import ConfluenceConfig
from mcp_atlassian.jira import JiraFetcher
from mcp_atlassian.jira.attachment_cache import get_attachment_cache
from mcp_atlassian.jira.config import JiraConfig
from mcp_atlassian.jira.upload_staging import get_upload_staging
from mcp_atlassian.utils.env import is_env_truthy
from mcp_atlassian.utils.environment import get_available_services
from mcp_atlassian.utils.io import (
    get_cli_bitbucket_read_only_flag,
    get_cli_confluence_read_only_flag,
    get_cli_jira_read_only_flag,
    get_cli_read_only_flag,
    get_env_bitbucket_read_only_flag,
    get_env_confluence_read_only_flag,
    get_env_jira_read_only_flag,
    get_env_read_only_flag,
    parse_extended_bool,
    resolve_product_read_only_mode,
    resolve_read_only_mode,
)
from mcp_atlassian.utils.logging import mask_sensitive
from mcp_atlassian.utils.oauth import (
    DC_AUTHORIZE_PATH,
    DC_TOKEN_PATH,
)
from mcp_atlassian.utils.prometheus_metrics import get_metrics, initialize_metrics
from mcp_atlassian.utils.token_verifier import AtlassianDataCenterTokenVerifier
from mcp_atlassian.utils.tools import get_enabled_tools, should_include_tool
from mcp_atlassian.utils.urls import is_atlassian_cloud_url
from mcp_atlassian.xray import XrayFetcher
from mcp_atlassian.xray.config import XrayConfig

from .bitbucket import bitbucket_mcp
from .confluence import confluence_mcp
from .context import MainAppContext
from .jira import jira_mcp
from .oauth_proxy import HardenedOAuthProxy, parse_env_list
from .xray import xray_mcp

logger = logging.getLogger("mcp-atlassian.server.main")

DEFAULT_ALLOWED_REDIRECT_URIS = [
    "http://localhost:*",
    "http://127.0.0.1:*",
]
DEFAULT_ALLOWED_GRANT_TYPES = ["authorization_code", "refresh_token"]
OAUTH_PROXY_ENABLE_ENV = "ATLASSIAN_OAUTH_PROXY_ENABLE"
DATA_CENTER_OAUTH_PRODUCTS = ("jira", "confluence", "bitbucket")

# Initialize metrics immediately when module is loaded
pod_name = os.environ.get("POD_NAME")
initialize_metrics(pod_name)
logger.info(f"Metrics collection initialized for pod: {pod_name}")


async def health_check() -> JSONResponse:
    return JSONResponse({"status": "ok"})


async def upload_endpoint(request: Request) -> JSONResponse:
    """Receive multipart file uploads and stage them for Jira attachment.

    Expects:
      - Header:  Mcp-Session-Id: <session_id>  (from construct_upload_endpoint)
      - Body:    multipart/form-data with one or more file fields

    Returns JSON:
      {"uploaded": [{"filename": "...", "uri": "upload://sessions/…", "size": …}]}
    """
    from pathlib import Path

    session_id = request.headers.get("mcp-session-id")
    if not session_id:
        return JSONResponse(
            {"error": "Mcp-Session-Id header is required"},
            status_code=400,
        )

    staging = get_upload_staging()
    if not staging.is_valid_session(session_id):
        return JSONResponse(
            {
                "error": (
                    "Invalid or expired upload session. "
                    "Call construct_upload_endpoint to create a new session."
                )
            },
            status_code=403,
        )

    try:
        form = await request.form()
    except Exception as exc:
        logger.error("Failed to parse upload form: %s", exc)
        return JSONResponse({"error": "Invalid multipart form data"}, status_code=400)

    uploaded = []
    max_file_bytes = staging.max_file_bytes
    for _field_name, file_field in form.multi_items():
        if not hasattr(file_field, "filename") or not file_field.filename:
            continue
        # Prevent path traversal: keep only the basename
        safe_name = Path(file_field.filename).name
        if not safe_name:
            continue
        try:
            # Stream-read in chunks and enforce size limit early to prevent
            # memory exhaustion from oversized uploads.
            chunks: list[bytes] = []
            total_read = 0
            chunk_size = 64 * 1024  # 64 KB
            while True:
                chunk = await file_field.read(chunk_size)
                if not chunk:
                    break
                total_read += len(chunk)
                if total_read > max_file_bytes:
                    return JSONResponse(
                        {
                            "error": (
                                f"File '{safe_name}' exceeds maximum allowed size "
                                f"({max_file_bytes} bytes). Upload rejected."
                            )
                        },
                        status_code=413,
                    )
                chunks.append(chunk)
            content: bytes = b"".join(chunks)
        except Exception as exc:
            logger.error("Failed to read uploaded file '%s': %s", safe_name, exc)
            continue
        mime_type: str = (
            getattr(file_field, "content_type", None) or "application/octet-stream"
        )
        try:
            file_id = staging.store(session_id, safe_name, content, mime_type)
        except PermissionError as exc:
            return JSONResponse({"error": str(exc)}, status_code=403)
        except ValueError as exc:
            return JSONResponse({"error": str(exc)}, status_code=413)
        uri = staging.make_uri(session_id, file_id)
        uploaded.append({"filename": safe_name, "uri": uri, "size": len(content)})

    if not uploaded:
        return JSONResponse(
            {
                "error": "No files found in request. Use multipart/form-data with file fields."
            },
            status_code=400,
        )

    logger.info(
        "Staged %d file(s) for session %s: %s",
        len(uploaded),
        session_id,
        [u["filename"] for u in uploaded],
    )
    return JSONResponse({"success": True, "uploaded": uploaded})


async def download_endpoint(request: Request) -> Response:
    """Serve a cached Jira attachment via a short-lived download token."""
    token = request.path_params.get("token")
    if not token:
        return JSONResponse({"error": "Download token is required"}, status_code=400)

    attachment = get_attachment_cache().get_by_download_token(token)
    if not attachment:
        return JSONResponse(
            {
                "error": (
                    "Invalid or expired download token. "
                    "Generate a new download URL and try again."
                )
            },
            status_code=403,
        )

    encoded_name = quote(attachment["filename"], safe="")
    headers = {
        "Content-Disposition": f"attachment; filename*=UTF-8''{encoded_name}",
        "Cache-Control": "private, max-age=0, no-store",
    }
    return Response(
        content=attachment["content"],
        media_type=attachment["mime_type"],
        headers=headers,
    )


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


def _cleanup_interval_seconds() -> int:
    """Resolve the staging cleanup sweep interval in seconds; 0 disables it."""
    raw = os.environ.get("STAGING_CLEANUP_INTERVAL_MINUTES", "15")
    try:
        minutes = int(raw)
    except (TypeError, ValueError):
        logger.warning(
            "Invalid STAGING_CLEANUP_INTERVAL_MINUTES=%r; using default of 15.", raw
        )
        minutes = 15
    return max(0, minutes) * 60


async def _sweep_staging_once() -> None:
    """Run one cleanup pass over download tokens and staged uploads."""
    try:
        tokens = await asyncio.to_thread(get_attachment_cache().sweep_expired)
        staged = await asyncio.to_thread(get_upload_staging().sweep_expired)
        if tokens or staged:
            logger.info(
                "Staging cleanup reclaimed %d expired download token(s)/cache "
                "entr(ies) and %d expired staged upload(s).",
                tokens,
                staged,
            )
        else:
            logger.debug("Staging cleanup: nothing to reclaim.")
    except Exception as exc:  # keep the sweeper loop alive across failures
        logger.warning("Staging cleanup sweep failed: %s", exc, exc_info=True)


async def _run_staging_cleanup(interval_seconds: int) -> None:
    """Periodically reclaim expired download tokens and staged uploads.

    Runs in-process so entries are reclaimed even when a minted download URL is
    never fetched (nothing reads it to trigger the lazy per-request cleanup).
    Deletes are idempotent, so every instance can safely sweep a shared volume.
    """
    while True:
        await asyncio.sleep(interval_seconds)
        await _sweep_staging_once()


@asynccontextmanager
async def main_lifespan(app: FastMCP[MainAppContext]) -> AsyncIterator[dict]:
    logger.info("Main Atlassian MCP server lifespan starting...")
    services = get_available_services()
    oauth_product = getattr(app, "oauth_product", None)
    if oauth_product in DATA_CENTER_OAUTH_PRODUCTS:
        services = {
            service: available
            and (
                service == oauth_product
                or (oauth_product == "jira" and service == "xray")
            )
            for service, available in services.items()
        }
    cli_read_only = get_cli_read_only_flag()
    env_read_only = get_env_read_only_flag()
    read_only = resolve_read_only_mode(cli_read_only, env_read_only, None)
    enabled_tools = get_enabled_tools()

    # Resolve per-product read_only flags (no header at startup time)
    jira_read_only = resolve_product_read_only_mode(
        product_cli=get_cli_jira_read_only_flag(),
        product_env=get_env_jira_read_only_flag(),
        global_cli=cli_read_only,
        global_env=env_read_only,
        header_read_only=None,
    )
    confluence_read_only = resolve_product_read_only_mode(
        product_cli=get_cli_confluence_read_only_flag(),
        product_env=get_env_confluence_read_only_flag(),
        global_cli=cli_read_only,
        global_env=env_read_only,
        header_read_only=None,
    )
    bitbucket_read_only = resolve_product_read_only_mode(
        product_cli=get_cli_bitbucket_read_only_flag(),
        product_env=get_env_bitbucket_read_only_flag(),
        global_cli=cli_read_only,
        global_env=env_read_only,
        header_read_only=None,
    )

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
            if bitbucket_config.is_auth_configured():
                loaded_bitbucket_config = bitbucket_config
                logger.info(
                    "Bitbucket configuration loaded and authentication is configured."
                )
            else:
                logger.warning(
                    "Bitbucket URL found, but authentication is not fully configured. "
                    "Bitbucket tools will be unavailable."
                )
        except Exception as e:
            logger.error(f"Failed to load Bitbucket configuration: {e}", exc_info=True)
    if services.get("xray"):
        if not loaded_jira_config:
            logger.warning(
                "Xray for Jira is enabled but Jira configuration is unavailable. "
                "Xray tools will be disabled."
            )
        else:
            try:
                xray_config = XrayConfig.from_jira_config(loaded_jira_config)
                if xray_config.is_auth_configured():
                    loaded_xray_config = xray_config
                    logger.info(
                        "Xray for Jira configuration loaded using Jira credentials."
                    )
                else:
                    logger.warning(
                        "Jira configuration loaded but authentication is not fully "
                        "configured for Xray for Jira. Xray tools will be unavailable."
                    )
            except Exception as e:
                logger.error(
                    f"Failed to load Xray for Jira configuration: {e}", exc_info=True
                )

    app_context = MainAppContext(
        full_jira_config=loaded_jira_config,
        full_confluence_config=loaded_confluence_config,
        full_bitbucket_config=loaded_bitbucket_config,
        full_xray_config=loaded_xray_config,
        read_only=read_only,
        cli_read_only=cli_read_only,
        env_read_only=env_read_only,
        enabled_tools=enabled_tools,
        jira_read_only=jira_read_only,
        confluence_read_only=confluence_read_only,
        bitbucket_read_only=bitbucket_read_only,
    )
    logger.info(
        "Read-only mode resolved: global=%s, jira=%s, confluence=%s, bitbucket=%s "
        "(cli=%s, env=%s)",
        "ENABLED" if read_only else "DISABLED",
        "ENABLED" if jira_read_only else "DISABLED",
        "ENABLED" if confluence_read_only else "DISABLED",
        "ENABLED" if bitbucket_read_only else "DISABLED",
        cli_read_only,
        env_read_only,
    )
    logger.info(f"Enabled tools filter: {enabled_tools or 'All tools enabled'}")

    cleanup_interval = _cleanup_interval_seconds()
    cleanup_task: asyncio.Task | None = None
    if cleanup_interval > 0:
        cleanup_task = asyncio.create_task(_run_staging_cleanup(cleanup_interval))
        logger.info(
            "Started staging cleanup sweeper (every %d min).", cleanup_interval // 60
        )
    else:
        logger.info("Staging cleanup sweeper disabled (interval=0).")

    try:
        yield {"app_lifespan_context": app_context}
    except Exception as e:
        logger.error(f"Error during lifespan: {e}", exc_info=True)
        raise
    finally:
        logger.info("Main Atlassian MCP server lifespan shutting down...")
        # Perform any necessary cleanup here
        try:
            if cleanup_task is not None:
                cleanup_task.cancel()
                try:
                    await cleanup_task
                except asyncio.CancelledError:
                    pass
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

    oauth_product: str | None = None

    async def _list_tools_mcp(self) -> list[MCPTool]:
        # Filter tools based on enabled_tools, read_only mode, and service configuration
        # from the lifespan context.
        req_context = self._mcp_server.request_context
        if req_context is None or req_context.lifespan_context is None:
            logger.warning(
                "Lifespan context not available during _main_mcp_list_tools call."
            )
            return []

        lifespan_ctx = req_context.lifespan_context
        if isinstance(lifespan_ctx, MainAppContext):
            app_lifespan_state: MainAppContext | None = lifespan_ctx
        elif isinstance(lifespan_ctx, dict):
            app_lifespan_state = lifespan_ctx.get("app_lifespan_context")
        else:
            app_lifespan_state = None
        enabled_tools_filter = (
            getattr(app_lifespan_state, "enabled_tools", None)
            if app_lifespan_state
            else None
        )

        base_read_only = (
            getattr(app_lifespan_state, "read_only", None)
            if app_lifespan_state
            else None
        )

        if app_lifespan_state:
            cli_read_only = getattr(app_lifespan_state, "cli_read_only", None)
            env_read_only = getattr(app_lifespan_state, "env_read_only", None)
        else:
            cli_read_only = get_cli_read_only_flag()
            env_read_only = get_env_read_only_flag()

        header_read_only = None
        header_jira_read_only = None
        header_confluence_read_only = None
        header_bitbucket_read_only = None
        enable_xray_header = None
        header_based_services = {
            "jira": False,
            "confluence": False,
            "bitbucket": False,
            "xray": False,
        }
        service_headers: dict = {}
        if hasattr(req_context, "request") and hasattr(req_context.request, "state"):
            request_state = req_context.request.state
            service_headers = getattr(request_state, "atlassian_service_headers", {})
            header_read_only = getattr(request_state, "read_only_mode_header", None)
            header_jira_read_only = getattr(
                request_state, "jira_read_only_mode_header", None
            )
            header_confluence_read_only = getattr(
                request_state, "confluence_read_only_mode_header", None
            )
            header_bitbucket_read_only = getattr(
                request_state, "bitbucket_read_only_mode_header", None
            )
            enable_xray_header = getattr(request_state, "enable_xray_header", None)

            if service_headers:
                header_based_services = get_available_services(service_headers)
                logger.debug(
                    f"Header-based service availability: {header_based_services}"
                )

        # When no service-identifying headers are present, list all tools so clients
        # can discover the full tool catalogue without needing to provide URLs upfront.
        # Auth will still be enforced at call time.
        has_service_headers = bool(service_headers)

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

        # Resolve per-product effective read_only.
        # Priority (highest first):
        #   product-specific header > global header > product-specific startup value > effective_read_only
        def _product_read_only(
            product_header: str | None,
            context_attr: str,
        ) -> bool:
            product_hdr_bool = parse_extended_bool(product_header)
            if product_hdr_bool is not None:
                return product_hdr_bool
            global_hdr_bool = parse_extended_bool(header_read_only)
            if global_hdr_bool is not None:
                return global_hdr_bool
            stored = (
                getattr(app_lifespan_state, context_attr, None)
                if app_lifespan_state
                else None
            )
            return bool(stored) if stored is not None else effective_read_only

        effective_jira_read_only = _product_read_only(
            header_jira_read_only, "jira_read_only"
        )
        effective_confluence_read_only = _product_read_only(
            header_confluence_read_only, "confluence_read_only"
        )
        effective_bitbucket_read_only = _product_read_only(
            header_bitbucket_read_only, "bitbucket_read_only"
        )

        logger.debug(
            "_main_mcp_list_tools: base_read_only=%s, cli_read_only=%s, "
            "env_read_only=%s, header_read_only=%s (jira=%s, confluence=%s, bitbucket=%s), "
            "effective_read_only=%s, jira_read_only=%s, confluence_read_only=%s, "
            "bitbucket_read_only=%s, enabled_tools_filter=%s, header_services=%s",
            base_read_only,
            cli_read_only,
            env_read_only,
            header_read_only,
            header_jira_read_only,
            header_confluence_read_only,
            header_bitbucket_read_only,
            effective_read_only,
            effective_jira_read_only,
            effective_confluence_read_only,
            effective_bitbucket_read_only,
            enabled_tools_filter,
            header_based_services,
        )

        xray_header_enabled = enable_xray_header == "true"
        xray_header_log_value = enable_xray_header or "missing"

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

            if tool_obj and "write" in tool_tags:
                is_jira_write = "jira" in tool_tags
                is_confluence_write = "confluence" in tool_tags
                is_bitbucket_write = "bitbucket" in tool_tags
                if is_jira_write and effective_jira_read_only:
                    logger.debug(
                        f"Excluding tool '{registered_name}' due to Jira read-only mode"
                    )
                    continue
                if is_confluence_write and effective_confluence_read_only:
                    logger.debug(
                        f"Excluding tool '{registered_name}' due to Confluence read-only mode"
                    )
                    continue
                if is_bitbucket_write and effective_bitbucket_read_only:
                    logger.debug(
                        f"Excluding tool '{registered_name}' due to Bitbucket read-only mode"
                    )
                    continue
                # Fallback for write tools not tagged to a specific product (e.g. xray)
                if (
                    not any([is_jira_write, is_confluence_write, is_bitbucket_write])
                    and effective_read_only
                ):
                    logger.debug(
                        f"Excluding tool '{registered_name}' due to global read-only mode "
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
                    (app_lifespan_state.full_jira_config is not None)
                    or header_based_services.get("jira", False)
                    or (not has_service_headers)
                )
                confluence_available = (
                    (app_lifespan_state.full_confluence_config is not None)
                    or header_based_services.get("confluence", False)
                    or (not has_service_headers)
                )
                bitbucket_available = (
                    (app_lifespan_state.full_bitbucket_config is not None)
                    or header_based_services.get("bitbucket", False)
                    or (not has_service_headers)
                )
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

                if is_xray_tool and service_configured_and_available:
                    if not xray_header_enabled:
                        logger.debug(
                            f"Excluding Xray tool '{registered_name}' because "
                            f"X-Atlassian-Enable-Xray header is missing or not 'true' "
                            f"(value: {xray_header_log_value})"
                        )
                        service_configured_and_available = False

            elif (
                is_jira_tool or is_confluence_tool or is_bitbucket_tool or is_xray_tool
            ):
                jira_available = (
                    header_based_services.get("jira", False) or not has_service_headers
                )

                confluence_available = (
                    header_based_services.get("confluence", False)
                    or not has_service_headers
                )

                bitbucket_available = (
                    header_based_services.get("bitbucket", False)
                    or not has_service_headers
                )

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

                if is_xray_tool and service_configured_and_available:
                    if not xray_header_enabled:
                        logger.debug(
                            f"Excluding Xray tool '{registered_name}' because "
                            f"X-Atlassian-Enable-Xray header is missing or not 'true' "
                            f"(value: {xray_header_log_value})"
                        )
                        service_configured_and_available = False

            if not service_configured_and_available:
                continue

            filtered_tools.append(tool_obj.to_mcp_tool(name=registered_name))

        logger.debug(
            f"_main_mcp_list_tools: Total tools after filtering: {len(filtered_tools)}"
        )
        return filtered_tools

    async def _mcp_list_tools(self) -> list[MCPTool]:
        """Backward-compatible alias for tests and older FastMCP versions."""
        return await self._list_tools_mcp()

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
        # Add file upload endpoint (used by construct_upload_endpoint / jira_upload_attachment flow)
        app.router.routes.append(Route("/upload", upload_endpoint, methods=["POST"]))
        # Add short-lived attachment download endpoint (used by construct_download_endpoint)
        app.router.routes.append(
            Route("/download/{token}", download_endpoint, methods=["GET"])
        )

        # Serve both `/mcp` and `/mcp/` directly. FastMCP registers the
        # streamable-http handler at a single path (e.g. `/mcp`); without this,
        # requests to the trailing-slash variant trigger Starlette's
        # `redirect_slashes`, issuing a 307 that can drop the original scheme
        # (HTTPS -> HTTP) behind a TLS-terminating proxy and break clients.
        # Register an explicit alias route for the trailing-slash path that
        # points at the same ASGI handler so both paths are served identically.
        mcp_path = (path or settings.streamable_http_path).rstrip("/")
        if mcp_path:
            alias_path = f"{mcp_path}/"
            for route in list(app.router.routes):
                if isinstance(route, Route) and route.path == mcp_path:
                    app.router.routes.append(
                        Route(
                            alias_path,
                            route.endpoint,
                            methods=route.methods,
                            name=f"{route.name}_slash" if route.name else None,
                            include_in_schema=False,
                        )
                    )
                    break

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
        root_path = scope.get("root_path", "").rstrip("/")
        local_request_path = request_path
        if root_path and request_path.startswith(root_path):
            local_request_path = request_path[len(root_path) :] or "/"
        method = scope.get("method", "")

        logger.debug(
            "UserTokenMiddleware.__call__: Comparing "
            f"local_request_path='{local_request_path}' "
            f"with mcp_path='{mcp_path}'. Request method='{method}'"
        )

        if local_request_path == mcp_path and method == "POST":
            # Parse headers from scope (headers are byte tuples per ASGI spec)
            headers = dict(scope.get("headers", []))

            read_only_header_bytes = headers.get(b"x-atlassian-read-only-mode")
            read_only_header_value = (
                read_only_header_bytes.decode("latin-1")
                if read_only_header_bytes
                else None
            )
            read_only_header_value = (
                read_only_header_value.strip() if read_only_header_value else None
            )
            scope_copy["state"]["read_only_mode_header"] = read_only_header_value
            if read_only_header_value:
                logger.debug(
                    "UserTokenMiddleware: X-Atlassian-Read-Only-Mode header: %s",
                    read_only_header_value,
                )

            # Per-product read-only headers
            def _extract_header(key: bytes) -> str | None:
                raw = headers.get(key)
                val = raw.decode("latin-1").strip() if raw else None
                return val if val else None

            jira_ro_hdr = _extract_header(b"x-atlassian-jira-read-only-mode")
            confluence_ro_hdr = _extract_header(
                b"x-atlassian-confluence-read-only-mode"
            )
            bitbucket_ro_hdr = _extract_header(b"x-atlassian-bitbucket-read-only-mode")
            scope_copy["state"]["jira_read_only_mode_header"] = jira_ro_hdr
            scope_copy["state"]["confluence_read_only_mode_header"] = confluence_ro_hdr
            scope_copy["state"]["bitbucket_read_only_mode_header"] = bitbucket_ro_hdr
            for hdr_name, hdr_val in (
                ("X-Atlassian-Jira-Read-Only-Mode", jira_ro_hdr),
                ("X-Atlassian-Confluence-Read-Only-Mode", confluence_ro_hdr),
                ("X-Atlassian-Bitbucket-Read-Only-Mode", bitbucket_ro_hdr),
            ):
                if hdr_val:
                    logger.debug(
                        "UserTokenMiddleware: %s header: %s", hdr_name, hdr_val
                    )

            # Extract X-Atlassian-Enable-Xray header
            enable_xray_header_bytes = headers.get(b"x-atlassian-enable-xray")
            enable_xray_header_value = (
                enable_xray_header_bytes.decode("latin-1")
                if enable_xray_header_bytes
                else None
            )
            enable_xray_header_value = (
                enable_xray_header_value.strip().lower()
                if enable_xray_header_value
                else None
            )
            scope_copy["state"]["enable_xray_header"] = enable_xray_header_value
            if enable_xray_header_value:
                logger.debug(
                    "UserTokenMiddleware: X-Atlassian-Enable-Xray header: %s",
                    enable_xray_header_value,
                )

            # Extract X-MCP-Upload-Base-URL header for the file upload endpoint
            upload_base_url_header = headers.get(b"x-mcp-upload-base-url")
            upload_base_url_header_str = (
                upload_base_url_header.decode("latin-1")
                if upload_base_url_header
                else None
            )
            upload_base_url_header_str = (
                upload_base_url_header_str.strip()
                if upload_base_url_header_str
                else None
            )
            scope_copy["state"]["upload_base_url"] = upload_base_url_header_str
            if upload_base_url_header_str:
                logger.debug(
                    "UserTokenMiddleware: X-MCP-Upload-Base-URL header: %s",
                    upload_base_url_header_str,
                )

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
            effective_xray_token = None
            effective_xray_url = None

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
                    elif effective_xray_token and effective_xray_url:
                        service_to_use = "xray"
                        username_to_use = username
                        activity_type = activity_type or "xray_access"

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
            if enable_xray_header_value is not None:
                service_headers["X-Atlassian-Enable-Xray"] = enable_xray_header_value

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
                    "UserTokenMiddleware.__call__: Bearer token extracted "
                    "(token_present=true)"
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
                    "UserTokenMiddleware.__call__: PAT extracted (token_present=true)"
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
                    or (bitbucket_token_header_str and bitbucket_url_header_str)
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
                    response_status = int(message.get("status", 200))

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


def _get_allowed_redirect_uris() -> list[str]:
    parsed = parse_env_list(os.getenv("ATLASSIAN_OAUTH_ALLOWED_CLIENT_REDIRECT_URIS"))
    return DEFAULT_ALLOWED_REDIRECT_URIS if parsed is None else parsed


def _get_allowed_grant_types() -> list[str]:
    parsed = parse_env_list(os.getenv("ATLASSIAN_OAUTH_ALLOWED_GRANT_TYPES"))
    return DEFAULT_ALLOWED_GRANT_TYPES if not parsed else parsed


def _resolve_upstream_oauth_endpoints(instance_url: str) -> tuple[str, str]:
    if is_atlassian_cloud_url(instance_url):
        raise ValueError(
            "Browser OAuth proxy mode currently supports Atlassian Data Center "
            "only; use the existing Cloud OAuth setup or BYOT flow for Cloud"
        )
    base_url = instance_url.rstrip("/")
    return f"{base_url}{DC_AUTHORIZE_PATH}", f"{base_url}{DC_TOKEN_PATH}"


def _get_product_oauth_value(product: str, name: str) -> str | None:
    """Return a product-specific Data Center browser OAuth value."""
    return os.getenv(f"{product.upper()}_OAUTH_{name}")


def _is_data_center_product_url(product: str, instance_url: str) -> bool:
    """Return whether a product URL targets Server or Data Center."""
    if product == "bitbucket" and "bitbucket.org" in instance_url.lower():
        return False
    return not is_atlassian_cloud_url(instance_url)


def _get_configured_data_center_oauth_products() -> list[str]:
    """Return Data Center products with complete browser OAuth configuration."""
    if not is_env_truthy(OAUTH_PROXY_ENABLE_ENV, "false"):
        return []

    configured: list[str] = []
    for product in DATA_CENTER_OAUTH_PRODUCTS:
        instance_url = os.getenv(f"{product.upper()}_URL")
        if not instance_url or not _is_data_center_product_url(product, instance_url):
            continue
        if all(
            _get_product_oauth_value(product, name)
            for name in ("CLIENT_ID", "CLIENT_SECRET", "REDIRECT_URI")
        ):
            configured.append(product)
    return configured


def _product_public_base_url(product: str) -> str:
    """Build the public issuer URL for a mounted product OAuth application."""
    public_base_url = os.getenv("PUBLIC_BASE_URL", "").rstrip("/")
    if not public_base_url:
        raise ValueError(
            "Multi-product Data Center OAuth requires PUBLIC_BASE_URL, for example "
            "https://mcp.example.com"
        )

    configured_products = _get_configured_data_center_oauth_products()
    base_path_parts = [
        part.lower() for part in urlparse(public_base_url).path.split("/") if part
    ]
    configured_suffix = (
        base_path_parts[-1]
        if base_path_parts and base_path_parts[-1] in DATA_CENTER_OAUTH_PRODUCTS
        else None
    )
    if configured_suffix:
        if len(configured_products) > 1:
            raise ValueError(
                "PUBLIC_BASE_URL must be the common public origin when multiple "
                "Data Center OAuth products are configured; remove the product "
                f"suffix '/{configured_suffix}'"
            )
        if configured_suffix != product:
            raise ValueError(
                f"PUBLIC_BASE_URL ends in '/{configured_suffix}' but the configured "
                f"OAuth product is '{product}'"
            )
        return public_base_url
    return f"{public_base_url}/{product}"


def _build_product_oauth_storage(
    product: str, client_secret: str
) -> tuple[object, bytes]:
    """Create an encrypted, product-isolated FastMCP OAuth store."""
    from cryptography.fernet import Fernet
    from fastmcp.server.auth.jwt_issuer import derive_jwt_key
    from key_value.aio.stores.disk import DiskStore
    from key_value.aio.wrappers.encryption import FernetEncryptionWrapper

    jwt_signing_key = derive_jwt_key(
        high_entropy_material=client_secret,
        salt="fastmcp-jwt-signing-key",
    )
    storage_encryption_key = derive_jwt_key(
        high_entropy_material=jwt_signing_key.decode(),
        salt="fastmcp-storage-encryption-key",
    )
    storage_directory = settings.home / "oauth-proxy" / product
    storage_directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.name != "nt":
        storage_directory.chmod(0o700)
    storage = FernetEncryptionWrapper(
        key_value=DiskStore(
            directory=storage_directory,
        ),
        fernet=Fernet(key=storage_encryption_key),
    )
    return storage, jwt_signing_key


def _build_auth_provider(
    product: str | None = None,
    public_base_url: str | None = None,
    isolate_storage: bool = False,
) -> HardenedOAuthProxy | None:
    """Build the opt-in OAuth provider used by remote HTTP MCP clients."""
    if not is_env_truthy(OAUTH_PROXY_ENABLE_ENV, "false"):
        return None

    oauth_product = product
    if oauth_product not in DATA_CENTER_OAUTH_PRODUCTS:
        raise ValueError(
            "Browser OAuth proxy mode requires a configured Data Center product: "
            "jira, confluence, or bitbucket"
        )

    instance_url = os.getenv(f"{oauth_product.upper()}_URL")
    client_id = _get_product_oauth_value(oauth_product, "CLIENT_ID")
    client_secret = _get_product_oauth_value(oauth_product, "CLIENT_SECRET")
    redirect_uri = _get_product_oauth_value(oauth_product, "REDIRECT_URI")

    if not instance_url or not client_id or not client_secret or not redirect_uri:
        missing = [
            name
            for name, value in (
                ("instance URL", instance_url),
                ("OAuth client ID", client_id),
                ("OAuth client secret", client_secret),
                ("OAuth redirect URI", redirect_uri),
            )
            if not value
        ]
        raise ValueError(
            "OAuth mode is enabled but required configuration is missing: "
            + ", ".join(missing)
        )

    scope_value = _get_product_oauth_value(oauth_product, "SCOPE")
    scopes = parse_env_list(scope_value) or []
    upstream_authorize, upstream_token = _resolve_upstream_oauth_endpoints(instance_url)
    parsed_redirect = urlparse(redirect_uri)
    redirect_path = parsed_redirect.path or "/callback"
    base_url = public_base_url or os.getenv("PUBLIC_BASE_URL")
    if not base_url and parsed_redirect.scheme and parsed_redirect.netloc:
        redirect_dir = redirect_path.rsplit("/", 1)[0]
        base_url = f"{parsed_redirect.scheme}://{parsed_redirect.netloc}{redirect_dir}"
    if not base_url:
        raise ValueError(
            "OAuth mode requires PUBLIC_BASE_URL or an absolute "
            "ATLASSIAN_OAUTH_REDIRECT_URI"
        )

    base_path = urlparse(base_url).path.rstrip("/")
    if base_path and redirect_path.startswith(base_path + "/"):
        redirect_path = redirect_path[len(base_path) :]
    if not redirect_path.startswith("/"):
        redirect_path = f"/{redirect_path}"

    verifier = AtlassianDataCenterTokenVerifier(
        instance_url=instance_url,
        product=oauth_product,
        required_scopes=scopes,
    )
    storage_options: dict[str, object] = {}
    if isolate_storage and oauth_product:
        client_storage, jwt_signing_key = _build_product_oauth_storage(
            oauth_product, client_secret
        )
        storage_options = {
            "client_storage": client_storage,
            "jwt_signing_key": jwt_signing_key,
        }

    return HardenedOAuthProxy(
        upstream_authorization_endpoint=upstream_authorize,
        upstream_token_endpoint=upstream_token,
        upstream_client_id=client_id,
        upstream_client_secret=client_secret,
        token_verifier=verifier,
        base_url=base_url,
        redirect_path=redirect_path,
        allowed_client_redirect_uris=_get_allowed_redirect_uris(),
        valid_scopes=scopes or None,
        allowed_grant_types=_get_allowed_grant_types(),
        forced_scopes=scopes or None,
        token_endpoint_auth_method="client_secret_post",  # noqa: S106
        require_authorization_consent=is_env_truthy(
            "ATLASSIAN_OAUTH_REQUIRE_CONSENT", "true"
        ),
        **storage_options,
    )


def _build_product_mcp(product: str) -> AtlassianMCP:
    """Build one independently authenticated Data Center product server."""
    provider = _build_auth_provider(
        product=product,
        public_base_url=_product_public_base_url(product),
        isolate_storage=True,
    )
    if provider is None:
        raise ValueError(f"OAuth provider is not enabled for {product}")

    product_mcp = AtlassianMCP(
        name=f"Atlassian {product.title()} MCP",
        lifespan=main_lifespan,
        auth=provider,
    )
    product_mcp.oauth_product = product
    if product == "jira":
        product_mcp.mount(jira_mcp, prefix="jira")
        product_mcp.mount(xray_mcp, prefix="xray")
    elif product == "confluence":
        product_mcp.mount(confluence_mcp, prefix="confluence")
    elif product == "bitbucket":
        product_mcp.mount(bitbucket_mcp, prefix="bitbucket")
    return product_mcp


def _copy_route(app: Starlette, source_path: str, target_path: str) -> Route:
    """Copy an unprotected metadata route to its RFC-required external path."""
    for route in app.routes:
        if isinstance(route, Route) and route.path == source_path:
            return Route(
                target_path,
                endpoint=route.endpoint,
                methods=route.methods,
                name=f"{route.name}_{target_path}" if route.name else None,
                include_in_schema=False,
            )
    raise ValueError(f"OAuth metadata route not found: {source_path}")


class MultiProductDataCenterMCP(AtlassianMCP):
    """One HTTP process hosting isolated Data Center OAuth applications."""

    def __init__(self, product_servers: dict[str, AtlassianMCP]) -> None:
        super().__init__(name="Atlassian Data Center MCP")
        self.product_servers = product_servers

    def http_app(
        self,
        path: str | None = None,
        middleware: list[Middleware] | None = None,
        transport: Literal["streamable-http", "sse"] = "streamable-http",
        stateless_http: bool = False,
        **kwargs: Any,
    ) -> Starlette:
        if transport != "streamable-http":
            raise ValueError(
                "Multi-product Data Center OAuth requires streamable-http transport"
            )

        mcp_path = path or settings.streamable_http_path
        product_apps: dict[str, Starlette] = {}
        routes: list[Route | Mount] = [
            Route("/healthz", _health_check_route, methods=["GET"]),
            Route("/readyz", _ready_check_route, methods=["GET"]),
            Route("/metrics", metrics_endpoint, methods=["GET"]),
        ]
        for product, server in self.product_servers.items():
            product_app = server.http_app(
                path=mcp_path,
                middleware=middleware,
                transport="streamable-http",
                stateless_http=stateless_http,
                **kwargs,
            )
            product_apps[product] = product_app
            protected_metadata_path = next(
                route.path
                for route in product_app.routes
                if isinstance(route, Route)
                and route.path.startswith("/.well-known/oauth-protected-resource/")
            )
            routes.append(
                _copy_route(
                    product_app,
                    protected_metadata_path,
                    protected_metadata_path,
                )
            )
            routes.append(
                _copy_route(
                    product_app,
                    "/.well-known/oauth-authorization-server",
                    f"/.well-known/oauth-authorization-server/{product}",
                )
            )

        routes.extend(
            Mount(f"/{product}", app=product_app)
            for product, product_app in product_apps.items()
        )

        @asynccontextmanager
        async def lifespan(app: Starlette) -> AsyncIterator[None]:
            async with AsyncExitStack() as stack:
                for product_app in product_apps.values():
                    await stack.enter_async_context(
                        product_app.router.lifespan_context(product_app)
                    )
                yield

        app = Starlette(routes=routes, lifespan=lifespan)
        app.state.path = "/"
        app.state.fastmcp_server = self
        return app


def _build_main_mcp() -> AtlassianMCP:
    data_center_products = _get_configured_data_center_oauth_products()
    if data_center_products:
        logger.info(
            "Starting multi-product Data Center OAuth routes for: %s",
            ", ".join(data_center_products),
        )
        return MultiProductDataCenterMCP(
            {product: _build_product_mcp(product) for product in data_center_products}
        )

    if is_env_truthy(OAUTH_PROXY_ENABLE_ENV, "false"):
        raise ValueError(
            "Browser OAuth proxy mode requires complete Jira, Confluence, or "
            "Bitbucket Data Center OAuth configuration. Cloud browser proxy "
            "support is not enabled."
        )

    server = AtlassianMCP(
        name="Atlassian MCP",
        lifespan=main_lifespan,
        auth=None,
    )
    server.mount(jira_mcp, prefix="jira")
    server.mount(confluence_mcp, prefix="confluence")
    server.mount(bitbucket_mcp, prefix="bitbucket")
    server.mount(xray_mcp, prefix="xray")
    return server


main_mcp = _build_main_mcp()


@main_mcp.custom_route("/healthz", methods=["GET"], include_in_schema=False)
async def _health_check_route(request: Request) -> JSONResponse:
    return await health_check()


@main_mcp.custom_route("/readyz", methods=["GET"], include_in_schema=False)
async def _ready_check_route(request: Request) -> JSONResponse:
    """Readiness check for Kubernetes probes."""
    return JSONResponse({"status": "ready", "server": "mcp-atlassian"})
