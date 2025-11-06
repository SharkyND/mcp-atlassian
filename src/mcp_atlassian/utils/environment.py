"""Utility functions related to environment checking."""

import logging
import os

from .urls import is_atlassian_cloud_url

logger = logging.getLogger("mcp-atlassian.utils.environment")


def get_available_services(
    headers: dict[str, str] | None = None,
) -> dict[str, bool | None]:
    """Determine which services are available based on environment variables and optional headers."""
    headers = headers or {}

    # Confluence service detection
    confluence_url = os.getenv("CONFLUENCE_URL")
    confluence_is_setup = False
    if confluence_url:
        is_cloud = is_atlassian_cloud_url(confluence_url)

        # OAuth check (highest precedence, applies to Cloud)
        if all(
            [
                os.getenv("ATLASSIAN_OAUTH_CLIENT_ID"),
                os.getenv("ATLASSIAN_OAUTH_CLIENT_SECRET"),
                os.getenv("ATLASSIAN_OAUTH_REDIRECT_URI"),
                os.getenv("ATLASSIAN_OAUTH_SCOPE"),
                os.getenv(
                    "ATLASSIAN_OAUTH_CLOUD_ID"
                ),  # CLOUD_ID is essential for OAuth client init
            ]
        ):
            confluence_is_setup = True
            logger.info(
                "Using Confluence OAuth 2.0 (3LO) authentication (Cloud-only features)"
            )
        elif all(
            [
                os.getenv("ATLASSIAN_OAUTH_ACCESS_TOKEN"),
                os.getenv("ATLASSIAN_OAUTH_CLOUD_ID"),
            ]
        ):
            confluence_is_setup = True
            logger.info(
                "Using Confluence OAuth 2.0 (3LO) authentication (Cloud-only features) "
                "with provided access token"
            )
        elif is_cloud:  # Cloud non-OAuth
            if all(
                [
                    os.getenv("CONFLUENCE_USERNAME"),
                    os.getenv("CONFLUENCE_API_TOKEN"),
                ]
            ):
                confluence_is_setup = True
                logger.info("Using Confluence Cloud Basic Authentication (API Token)")
        else:  # Server/Data Center non-OAuth
            if os.getenv("CONFLUENCE_PERSONAL_TOKEN") or (
                os.getenv("CONFLUENCE_USERNAME") and os.getenv("CONFLUENCE_API_TOKEN")
            ):
                confluence_is_setup = True
                logger.info(
                    "Using Confluence Server/Data Center authentication (PAT or Basic Auth)"
                )
    elif os.getenv("ATLASSIAN_OAUTH_ENABLE", "").lower() in ("true", "1", "yes"):
        confluence_is_setup = True
        logger.info(
            "Using Confluence minimal OAuth configuration - expecting user-provided tokens via headers"
        )

    if not confluence_is_setup:
        confluence_token = headers.get("X-Atlassian-Confluence-Personal-Token")
        confluence_url_header = headers.get("X-Atlassian-Confluence-Url")

        if confluence_token and confluence_url_header:
            confluence_is_setup = True
            logger.info("Using Confluence authentication from header personal token")

    # Jira service detection
    jira_url = os.getenv("JIRA_URL")
    jira_is_setup = False
    if jira_url:
        is_cloud = is_atlassian_cloud_url(jira_url)
        if all(
            [
                os.getenv("ATLASSIAN_OAUTH_CLIENT_ID"),
                os.getenv("ATLASSIAN_OAUTH_CLIENT_SECRET"),
                os.getenv("ATLASSIAN_OAUTH_REDIRECT_URI"),
                os.getenv("ATLASSIAN_OAUTH_SCOPE"),
                os.getenv("ATLASSIAN_OAUTH_CLOUD_ID"),
            ]
        ):
            jira_is_setup = True
            logger.info(
                "Using Jira OAuth 2.0 (3LO) authentication (Cloud-only features)"
            )
        elif all(
            [
                os.getenv("ATLASSIAN_OAUTH_ACCESS_TOKEN"),
                os.getenv("ATLASSIAN_OAUTH_CLOUD_ID"),
            ]
        ):
            jira_is_setup = True
            logger.info(
                "Using Jira OAuth 2.0 (3LO) authentication (Cloud-only features) "
                "with provided access token"
            )
        elif is_cloud:  # Cloud non-OAuth
            if all(
                [
                    os.getenv("JIRA_USERNAME"),
                    os.getenv("JIRA_API_TOKEN"),
                ]
            ):
                jira_is_setup = True
                logger.info("Using Jira Cloud Basic Authentication (API Token)")
        else:  # Server/Data Center non-OAuth
            if os.getenv("JIRA_PERSONAL_TOKEN") or (
                os.getenv("JIRA_USERNAME") and os.getenv("JIRA_API_TOKEN")
            ):
                jira_is_setup = True
                logger.info(
                    "Using Jira Server/Data Center authentication (PAT or Basic Auth)"
                )
    elif os.getenv("ATLASSIAN_OAUTH_ENABLE", "").lower() in ("true", "1", "yes"):
        jira_is_setup = True
        logger.info(
            "Using Jira minimal OAuth configuration - expecting user-provided tokens via headers"
        )

    if not jira_is_setup:
        jira_token = headers.get("X-Atlassian-Jira-Personal-Token")
        jira_url_header = headers.get("X-Atlassian-Jira-Url")

        if jira_token and jira_url_header:
            jira_is_setup = True
            logger.info("Using Jira authentication from header personal token")

    # Bitbucket service detection
    bitbucket_url = os.getenv("BITBUCKET_URL")
    bitbucket_is_setup = False
    if bitbucket_url:
        is_cloud = "bitbucket.org" in bitbucket_url.lower()

        # OAuth check (highest precedence, applies to Cloud)
        if all(
            [
                os.getenv("ATLASSIAN_OAUTH_CLIENT_ID"),
                os.getenv("ATLASSIAN_OAUTH_CLIENT_SECRET"),
                os.getenv("ATLASSIAN_OAUTH_REDIRECT_URI"),
                os.getenv("ATLASSIAN_OAUTH_SCOPE"),
                os.getenv("ATLASSIAN_OAUTH_CLOUD_ID"),
            ]
        ):
            bitbucket_is_setup = True
            logger.info(
                "Using Bitbucket OAuth 2.0 (3LO) authentication (Cloud-only features)"
            )
        elif all(
            [
                os.getenv("ATLASSIAN_OAUTH_ACCESS_TOKEN"),
                os.getenv("ATLASSIAN_OAUTH_CLOUD_ID"),
            ]
        ):
            bitbucket_is_setup = True
            logger.info(
                "Using Bitbucket OAuth 2.0 (3LO) authentication (Cloud-only features) "
                "with provided access token"
            )
        elif is_cloud:  # Cloud non-OAuth
            if all(
                [
                    os.getenv("BITBUCKET_USERNAME"),
                    os.getenv("BITBUCKET_APP_PASSWORD"),
                ]
            ):
                bitbucket_is_setup = True
                logger.info("Using Bitbucket Cloud Basic Authentication (App Password)")
        else:  # Server/Data Center non-OAuth
            if os.getenv("BITBUCKET_PERSONAL_TOKEN") or (
                os.getenv("BITBUCKET_USERNAME") and os.getenv("BITBUCKET_APP_PASSWORD")
            ):
                bitbucket_is_setup = True
                logger.info(
                    "Using Bitbucket Server/Data Center authentication (PAT or Basic Auth)"
                )
    elif os.getenv("ATLASSIAN_OAUTH_ENABLE", "").lower() in ("true", "1", "yes"):
        bitbucket_is_setup = True
        logger.info(
            "Using Bitbucket minimal OAuth configuration - expecting user-provided tokens via headers"
        )

    if not bitbucket_is_setup:
        bitbucket_token = headers.get("X-Atlassian-Bitbucket-Personal-Token")
        bitbucket_url_header = headers.get("X-Atlassian-Bitbucket-Url")

        if bitbucket_token and bitbucket_url_header:
            bitbucket_is_setup = True
            logger.info("Using Bitbucket authentication from header personal token")

    # Xray service detection
    xray_url = os.getenv("XRAY_URL")
    xray_is_setup = False
    if xray_url:
        is_cloud = is_atlassian_cloud_url(xray_url)

        # Xray is not supported in Cloud - force disable if cloud URL is detected
        if is_cloud:
            logger.warning(
                f"Xray is not supported in Atlassian Cloud. "
                f"Disabling Xray tools for cloud URL: {xray_url}"
            )
            xray_is_setup = False
        else:  # Server/Data Center only
            if all(
                [
                    os.getenv("ATLASSIAN_OAUTH_CLIENT_ID"),
                    os.getenv("ATLASSIAN_OAUTH_CLIENT_SECRET"),
                    os.getenv("ATLASSIAN_OAUTH_REDIRECT_URI"),
                    os.getenv("ATLASSIAN_OAUTH_SCOPE"),
                    os.getenv("ATLASSIAN_OAUTH_CLOUD_ID"),
                ]
            ):
                # OAuth is typically for cloud, but keeping this for completeness
                logger.warning(
                    "OAuth configuration detected for Xray, but Xray is only supported on Server/Data Center"
                )
                xray_is_setup = False
            elif all(
                [
                    os.getenv("ATLASSIAN_OAUTH_ACCESS_TOKEN"),
                    os.getenv("ATLASSIAN_OAUTH_CLOUD_ID"),
                ]
            ):
                # OAuth token is typically for cloud, but keeping this for completeness
                logger.warning(
                    "OAuth access token detected for Xray, but Xray is only supported on Server/Data Center"
                )
                xray_is_setup = False
            elif os.getenv("XRAY_PERSONAL_TOKEN") or (
                os.getenv("XRAY_USERNAME") and os.getenv("XRAY_API_TOKEN")
            ):
                xray_is_setup = True
                logger.info(
                    "Using Xray Server/Data Center authentication (PAT or Basic Auth)"
                )
    elif os.getenv("ATLASSIAN_OAUTH_ENABLE", "").lower() in ("true", "1", "yes"):
        # OAuth enable is typically for cloud scenarios, disable Xray
        logger.warning(
            "Minimal OAuth configuration detected, but Xray is only supported on Server/Data Center"
        )
        xray_is_setup = False

    # Check header-based authentication - also validate cloud URLs
    if not xray_is_setup:
        xray_token = headers.get("X-Atlassian-Xray-Personal-Token")
        xray_url_header = headers.get("X-Atlassian-Xray-Url")

        if xray_token and xray_url_header:
            # Check if the header URL is a cloud URL
            if is_atlassian_cloud_url(xray_url_header):
                logger.warning(
                    f"Xray is not supported in Atlassian Cloud. "
                    f"Ignoring header authentication for cloud URL: {xray_url_header}"
                )
                xray_is_setup = False
            else:
                xray_is_setup = True
                logger.info(
                    "Using Xray Server/Data Center authentication from header personal token"
                )

    # Log setup status
    if not confluence_is_setup:
        logger.info(
            "Confluence is not configured or required environment variables are missing."
        )
    if not jira_is_setup:
        logger.info(
            "Jira is not configured or required environment variables are missing."
        )
    if not bitbucket_is_setup:
        logger.info(
            "Bitbucket is not configured or required environment variables are missing."
        )
    if not xray_is_setup:
        logger.info(
            "Xray is not configured or required environment variables are missing."
        )

    return {
        "confluence": confluence_is_setup,
        "jira": jira_is_setup,
        "bitbucket": bitbucket_is_setup,
        "xray": xray_is_setup,
    }
