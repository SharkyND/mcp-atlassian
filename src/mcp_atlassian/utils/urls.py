"""URL-related utility functions for MCP Atlassian."""

import ipaddress
import os
import re
import socket
from collections.abc import Callable
from typing import Any
from urllib.parse import urljoin, urlparse


def make_ssrf_redirect_hook() -> Callable[..., Any]:
    """Return a requests ``response`` hook that blocks SSRF-unsafe redirects.

    Attach to any session (``session.hooks["response"].append(...)``) so that an
    open redirect cannot steer an outbound request to an internal/metadata host.
    """

    def hook(response: Any, **kwargs: Any) -> Any:
        if response.is_redirect:
            redirect_url = urljoin(response.url, response.headers.get("Location", ""))
            error = validate_url_for_ssrf(redirect_url)
            if error:
                response.close()
                msg = f"Redirect blocked (SSRF): {error}"
                raise ValueError(msg)
        return response

    return hook


def resolve_relative_url(url: str, base_url: str) -> str:
    """Resolve a relative URL against a base URL.

    Only modifies URLs that start with '/'. Absolute URLs are returned as-is.

    Args:
        url: The URL to resolve (may be relative or absolute).
        base_url: The base URL to prepend for relative URLs.

    Returns:
        The resolved absolute URL.
    """
    if url.startswith("/"):
        return base_url.rstrip("/") + url
    return url


def is_atlassian_cloud_url(url: str) -> bool:
    """Determine if a URL belongs to Atlassian Cloud or Server/Data Center.

    Args:
        url: The URL to check

    Returns:
        True if the URL is for an Atlassian Cloud instance, False for Server/Data Center
    """
    if url is None or not url:
        return False

    parsed_url = urlparse(url)
    hostname = parsed_url.hostname or ""

    # Localhost and private IPs are always Server/Data Center
    if (
        hostname == "localhost"
        or re.match(r"^127\.", hostname)
        or re.match(r"^192\.168\.", hostname)
        or re.match(r"^10\.", hostname)
        or re.match(r"^172\.(1[6-9]|2[0-9]|3[0-1])\.", hostname)
    ):
        return False

    # Use endswith() to prevent bypass via substring matching
    # Includes US Government cloud domains (FedRAMP Moderate/High)
    return (
        hostname.endswith(".atlassian.net")
        or hostname.endswith(".jira.com")
        or hostname.endswith(".jira-dev.com")
        or hostname == "api.atlassian.com"
        or hostname.endswith(".atlassian.com")
        or hostname.endswith(".atlassian-us-gov-mod.net")
        or hostname.endswith(".atlassian-us-gov.net")
        or hostname == "bitbucket.org"
        or hostname == "api.bitbucket.org"
    )


def validate_url_for_ssrf(url: str) -> str | None:
    """Validate a URL to prevent SSRF attacks.

    Returns None if the URL is safe, or an error message string if blocked.

    Args:
        url: The URL to validate.

    Returns:
        None if safe, error message string if blocked.
    """
    if not url or not url.strip():
        return "Empty URL"

    try:
        parsed = urlparse(url)
    except Exception:  # noqa: BLE001
        return f"Invalid URL: {url}"

    if parsed.scheme not in ("http", "https"):
        return f"Blocked scheme: {parsed.scheme} (only http/https allowed)"

    # requests treats backslash in authority as path separator — reject parse mismatch
    if "\\" in parsed.netloc:
        return f"Blocked backslash in URL authority: {url}"

    hostname = parsed.hostname
    if not hostname:
        return "No hostname in URL"

    blocked_hostnames = {"localhost", "metadata.google.internal"}
    if hostname.lower() in blocked_hostnames:
        return f"Blocked hostname: {hostname}"

    ip_error = _check_ip_address(hostname)
    if ip_error:
        return ip_error

    allowlist = _get_domain_allowlist()
    if allowlist is not None:
        if not _hostname_matches_allowlist(hostname, allowlist):
            return f"Hostname {hostname} not in allowed domains"
        return None

    dns_error = _check_dns_resolution(hostname)
    if dns_error:
        return dns_error

    return None


def _check_ip_address(hostname: str) -> str | None:
    """Check if hostname is a blocked IP address."""
    try:
        addr = ipaddress.ip_address(hostname)
    except ValueError:
        return None

    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        addr = addr.ipv4_mapped

    if not addr.is_global:
        return f"Blocked IP address: {hostname} (non-global)"

    return None


def _get_domain_allowlist() -> list[str] | None:
    """Get domain allowlist from environment variable."""
    raw = os.environ.get("MCP_ALLOWED_URL_DOMAINS", "").strip()
    if not raw:
        return None
    return [d.strip().lower() for d in raw.split(",") if d.strip()]


def _hostname_matches_allowlist(hostname: str, allowlist: list[str]) -> bool:
    """Check if hostname matches any entry in the allowlist."""
    hostname_lower = hostname.lower()
    for domain in allowlist:
        if hostname_lower == domain or hostname_lower.endswith(f".{domain}"):
            return True
    return False


def _check_dns_resolution(hostname: str) -> str | None:
    """Resolve hostname via DNS and check if any IP is non-global."""
    try:
        results = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        return f"DNS resolution failed for {hostname}"
    except (OSError, UnicodeError):
        return f"DNS resolution error for {hostname}"

    for _family, _type, _proto, _canonname, sockaddr in results:
        ip_str = sockaddr[0]
        try:
            addr = ipaddress.ip_address(ip_str)
            if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
                addr = addr.ipv4_mapped
            if not addr.is_global:
                return f"DNS for {hostname} resolves to non-global IP: {ip_str}"
        except ValueError:
            continue

    return None
