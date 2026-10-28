"""HTTP retry configuration for Atlassian API sessions.

Atlassian Server/Data Center deployments behind corporate proxies drop
connections and stall intermittently, which surfaces as one-off tool failures
even though a replay would succeed. This module configures urllib3's retry
handling so those blips are absorbed without ever replaying a request that may
already have changed server state.
"""

import logging

from requests.adapters import HTTPAdapter
from requests.sessions import Session
from urllib3.util.retry import Retry

logger = logging.getLogger("mcp-atlassian")

# Methods safe to replay when the request may ALREADY have reached the server.
#
# A read timeout means the request was delivered and Jira may have processed it
# - only the response was lost - so replaying a write can duplicate it (a second
# issue, a second link). PUT and DELETE are excluded despite being idempotent in
# HTTP terms, because Jira's edit-issue endpoint takes "add" operations (e.g.
# `{"update": {"issuelinks": [{"add": ...}]}}`) that accumulate on replay.
_REPLAYABLE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})

# Transient responses worth replaying: rate limiting, and gateway/proxy errors
# that indicate the request was not processed by the application.
_RETRY_STATUS_CODES = frozenset({429, 502, 503, 504})


def configure_retries(
    service_name: str,
    session: Session,
    *,
    retries: int,
    backoff_factor: float = 0.5,
) -> None:
    """Apply transient-failure retries to an Atlassian API session.

    Retries are deliberately asymmetric, because the safety of a replay depends
    on whether the server could already have acted on the request:

    - **Connection errors** are retried for *every* method. The connection was
      never established, so the server never saw the request and a replay
      cannot duplicate anything.
    - **Read timeouts and retryable statuses** are retried only for
      :data:`_REPLAYABLE_METHODS`. For writes the request may already have been
      processed, so replaying risks duplicate issues or links.

    The retry object is attached to the session's existing adapters rather than
    mounted as a new one, so SSL and proxy configuration applied earlier is
    preserved.

    Args:
        service_name: Human-readable service name used in log messages
        session: The requests session used by the Atlassian client
        retries: Maximum retry attempts; ``0`` disables retrying entirely
        backoff_factor: Exponential backoff multiplier between attempts
    """
    if retries <= 0:
        logger.debug(f"{service_name}: HTTP retries disabled")
        return

    retry = Retry(
        total=retries,
        connect=retries,
        read=retries,
        status=retries,
        # Do not replay failures urllib3 cannot classify; they may have applied.
        other=0,
        allowed_methods=_REPLAYABLE_METHODS,
        status_forcelist=_RETRY_STATUS_CODES,
        backoff_factor=backoff_factor,
        # Spread retries out so concurrent callers do not resynchronize.
        backoff_jitter=backoff_factor,
        respect_retry_after_header=True,
        # Surface the final response so existing handlers can read Jira's error
        # body instead of seeing an opaque MaxRetryError.
        raise_on_status=False,
    )

    for adapter in session.adapters.values():
        # Only HTTP adapters carry retry handling; skip any custom transport.
        if isinstance(adapter, HTTPAdapter):
            adapter.max_retries = retry

    logger.debug(
        f"{service_name}: HTTP retries enabled (attempts={retries}, "
        f"backoff_factor={backoff_factor}, replayable={sorted(_REPLAYABLE_METHODS)})"
    )
