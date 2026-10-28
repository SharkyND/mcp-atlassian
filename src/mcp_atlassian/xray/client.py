import logging
import os
from typing import Any

from atlassian import Xray
from requests import Session

from mcp_atlassian.exceptions import MCPAtlassianAuthenticationError
from mcp_atlassian.utils.env import get_env_retries
from mcp_atlassian.utils.logging import (
    get_masked_session_headers,
    log_config_param,
    mask_sensitive,
)
from mcp_atlassian.utils.oauth import configure_oauth_session
from mcp_atlassian.utils.retry import configure_retries
from mcp_atlassian.utils.ssl import configure_ssl_verification

from .config import XrayConfig

# Configure logging
logger = logging.getLogger("mcp-xray")


class XrayClient:
    """Base client for Xray API interactions."""

    _field_ids_cache: list[dict[str, Any]] | None
    _current_user_account_id: str | None

    config: XrayConfig

    def __init__(self, config: XrayConfig | None = None) -> None:
        """Initialize the Xray client with configuration options.

        Args:
            config: Optional configuration object (will use env vars if not provided)

        Raises:
            ValueError: If configuration is invalid or required credentials are missing
            MCPAtlassianAuthenticationError: If OAuth authentication fails
        """
        # Load configuration from environment variables if not provided
        self.config = config or XrayConfig.from_env()

        # Initialize the Xray client based on auth type
        if self.config.auth_type == "oauth":
            if not self.config.oauth_config or not self.config.oauth_config.cloud_id:
                error_msg = "OAuth authentication requires a valid cloud_id"
                raise ValueError(error_msg)

            # Create a session for OAuth
            session = Session()

            # Configure the session with OAuth authentication
            if not configure_oauth_session(session, self.config.oauth_config):
                error_msg = "Failed to configure OAuth session"
                raise MCPAtlassianAuthenticationError(error_msg)

            # The Xray API URL with OAuth is different
            api_url = (
                f"https://api.atlassian.com/ex/xray/{self.config.oauth_config.cloud_id}"
            )

            # Initialize Xray with the session
            self.xray = Xray(
                url=api_url,
                session=session,
                cloud=self.config.is_cloud,  # Use consistent config value
                verify_ssl=self.config.ssl_verify,
                timeout=self.config.timeout,
            )
        elif self.config.auth_type == "pat":
            logger.debug(
                f"Initializing Xray client with Token (PAT) auth. "
                f"URL: {self.config.url}, "
                f"Token (masked): {mask_sensitive(str(self.config.personal_token))}"
            )
            self.xray = Xray(
                url=self.config.url,
                token=self.config.personal_token,
                cloud=self.config.is_cloud,
                verify_ssl=self.config.ssl_verify,
                timeout=self.config.timeout,
            )
        else:  # basic auth
            logger.debug(
                f"Initializing Xray client with Basic auth. "
                f"URL: {self.config.url}, Username: {self.config.username}, "
                f"API Token present: {bool(self.config.api_token)}, "
                f"Is Cloud: {self.config.is_cloud}"
            )
            self.xray = Xray(
                url=self.config.url,
                username=self.config.username,
                password=self.config.api_token,
                cloud=self.config.is_cloud,
                verify_ssl=self.config.ssl_verify,
                timeout=self.config.timeout,
            )
            logger.debug(
                f"Xray client initialized. Session headers (Authorization masked): "
                f"{get_masked_session_headers(dict(self.xray._session.headers))}"
            )

        # Configure SSL verification using the shared utility
        configure_ssl_verification(
            service_name="Xray",
            url=self.config.url,
            session=self.xray._session,
            ssl_verify=self.config.ssl_verify,
        )

        # Applied after SSL so the retry policy attaches to the adapters
        # that configuration may have mounted.
        configure_retries(
            service_name="Xray",
            session=self.xray._session,
            retries=get_env_retries(),
        )

        # Proxy configuration
        proxies = {}
        if self.config.http_proxy:
            proxies["http"] = self.config.http_proxy
        if self.config.https_proxy:
            proxies["https"] = self.config.https_proxy
        if self.config.socks_proxy:
            proxies["socks"] = self.config.socks_proxy
        if proxies:
            self.xray._session.proxies.update(proxies)
            for k, v in proxies.items():
                log_config_param(
                    logger, "Xray", f"{k.upper()}_PROXY", v, sensitive=True
                )
        if self.config.no_proxy and isinstance(self.config.no_proxy, str):
            os.environ["NO_PROXY"] = self.config.no_proxy
            log_config_param(logger, "Xray", "NO_PROXY", self.config.no_proxy)

        if self.config.custom_headers:
            self.xray._session.headers.update(self.config.custom_headers)
            logger.debug(
                f"Added custom headers: {get_masked_session_headers(self.config.custom_headers)}"
            )

    def get_test_runs_in_context(
        self,
        test_exec_key: str,
        test_key: str | None = None,
        include_test_fields: str | None = None,
        limit: int | None = None,
        page: int | None = None,
    ) -> Any:
        """Retrieve test runs from a Test Execution using Xray REST API v2.

        The contextual endpoint returns the run status and execution metadata and
        can include selected custom fields from the associated Test issue. The
        upstream Xray client defaults to API v1, so this method builds the v2 URL
        explicitly without changing the API version used by other operations.

        Args:
            test_exec_key: Test Execution issue key.
            test_key: Optional Test issue key used to limit the results.
            include_test_fields: Optional comma-separated Test issue fields to
                include in each result.
            limit: Optional maximum number of test runs per page.
            page: Optional page number.

        Returns:
            The response returned by the Xray contextual test-runs endpoint.
        """
        params: dict[str, str | int] = {"testExecKey": test_exec_key}
        if test_key:
            params["testKey"] = test_key
        if include_test_fields:
            params["includeTestFields"] = include_test_fields
        if limit is not None:
            params["limit"] = limit
        if page is not None:
            params["page"] = page

        url = self.xray.resource_url("testruns", api_version="2.0")
        return self.xray.get(url, params=params)

    def update_test_run_step(
        self,
        test_run_id: int,
        step_id: int,
        *,
        status: str | None = None,
        comment: str | None = None,
        actual_result: str | None = None,
    ) -> Any:
        """Update writable fields on a Test Run step using Xray REST API v2.

        Args:
            test_run_id: ID of the Test Run.
            step_id: ID of the step result within that Test Run.
            status: Optional step status (e.g. "PASS", "FAIL").
            comment: Optional step comment.
            actual_result: Optional actual result text.

        Returns:
            The response returned by the Xray step-result endpoint.

        Raises:
            ValueError: If no writable fields are supplied.
        """
        update: dict[str, str] = {}
        if status is not None:
            update["status"] = status
        if comment is not None:
            update["comment"] = comment
        if actual_result is not None:
            update["actualResult"] = actual_result
        if not update:
            raise ValueError("At least one Test Run step field must be provided")

        url = self.xray.resource_url(
            f"testrun/{test_run_id}/step/{step_id}", api_version="2.0"
        )
        return self.xray.put(url, update)
