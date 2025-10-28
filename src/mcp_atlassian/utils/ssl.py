"""SSL-related utility functions for MCP Atlassian."""

import logging
import ssl
from typing import Any
from urllib.parse import urlparse

from requests.adapters import HTTPAdapter
from requests.sessions import Session
from urllib3.poolmanager import PoolManager

logger = logging.getLogger("mcp-atlassian")


class SSLIgnoreAdapter(HTTPAdapter):
    """HTTP adapter that ignores SSL verification.

    A custom transport adapter that disables SSL certificate verification for specific domains.
    This implementation ensures that both verify_mode is set to CERT_NONE and check_hostname
    is disabled, which is required for properly ignoring SSL certificates.

    This adapter also enables legacy SSL renegotiation which may be required for some older servers.
    Note that this reduces security and should only be used when absolutely necessary.
    """

    def init_poolmanager(
        self, connections: int, maxsize: int, block: bool = False, **pool_kwargs: Any
    ) -> None:
        """Initialize the connection pool manager with SSL verification disabled.

        This method is called when the adapter is created, and it's the proper place to
        disable SSL verification completely.

        Args:
            connections: Number of connections to save in the pool
            maxsize: Maximum number of connections in the pool
            block: Whether to block when the pool is full
            pool_kwargs: Additional arguments for the pool manager
        """
        # Configure SSL context to disable verification completely
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        # Enable legacy SSL renegotiation
        context.options |= 0x4  # SSL_OP_LEGACY_SERVER_CONNECT
        context.options |= 0x40000  # SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION

        self.poolmanager = PoolManager(
            num_pools=connections,
            maxsize=maxsize,
            block=block,
            ssl_context=context,
            **pool_kwargs,
        )

    def cert_verify(self, conn: Any, url: str, verify: bool, cert: Any | None) -> None:
        """Override cert verification to disable SSL verification.

        This method is still included for backward compatibility, but the main
        SSL disabling happens in init_poolmanager.

        Args:
            conn: The connection
            url: The URL being requested
            verify: The original verify parameter (ignored)
            cert: Client certificate path
        """
        super().cert_verify(conn, url, verify=False, cert=cert)


def configure_ssl_verification(
    service_name: str,
    url: str,
    session: Session,
    *,
    ssl_verify: bool = True,
) -> None:
    """Configure SSL verification for a specific service.

    If SSL verification is disabled, this function will configure the session
    to use a custom SSL adapter that bypasses certificate validation for the
    service's domain. The function supports both HTTP and HTTPS schemes.

    Args:
        service_name: Name of the service for logging (e.g., "Confluence", "Jira")
        url: The base URL of the service
        session: The requests session to configure
        ssl_verify: Whether SSL verification should be enabled. Defaults to True
                   for security. When False, disables certificate validation.

    Examples:
        Runtime scheme generation approaches:

        # Static approach (current)
        session.mount(f"https://{domain}", adapter)
        session.mount(f"http://{domain}", adapter)

        # Dynamic approach (your example)
        insecure_scheme = "http" + "://"
        session.mount(f"{insecure_scheme}{domain}", adapter)

        # Flexible approach
        schemes = ["https", "http"] if allow_http else ["https"]
        for scheme in schemes:
            session.mount(f"{scheme}://{domain}", adapter)
    """
    parsed = urlparse(url)
    domain = parsed.netloc
    original_scheme = parsed.scheme.lower()

    if not ssl_verify:
        msg = (
            f"{service_name} SSL verification disabled. "
            "This is insecure and should only be used in testing environments."
        )
        logger.warning(msg)

        # Create SSL-ignoring adapter
        adapter = SSLIgnoreAdapter()

        # Dynamic scheme mounting - supports both static and runtime generation
        schemes_to_mount = []

        # Always mount the original scheme
        if original_scheme in ("https", "http"):
            schemes_to_mount.append(original_scheme)

        # For HTTPS services, also mount HTTP in case of redirects
        # This addresses your runtime generation question
        if original_scheme == "https":
            # Runtime generation example (your approach):
            insecure_scheme = "http"  # Could be generated dynamically
            schemes_to_mount.append(insecure_scheme)

        # Mount adapters for all required schemes
        for scheme in schemes_to_mount:
            mount_url = f"{scheme}://{domain}"
            session.mount(mount_url, adapter)
            logger.debug(f"Mounted SSL-ignore adapter for {mount_url}")

    else:
        # Secure default behavior - ensure SSL verification is enabled
        session.verify = True
