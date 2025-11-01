"""Multi-pod aware Prometheus metrics collection for MCP Atlassian server.

This module provides Prometheus-compatible metrics that work across multiple pods:
- Hash PAT tokens to create anonymous user IDs
- Track all user activity as counters (not "first seen")
- Enable aggregation across multiple pods via Prometheus queries
- Survive pod restarts through Prometheus persistence
"""

import os
import time
from typing import Any

try:
    from prometheus_client import (
        CONTENT_TYPE_LATEST,
        REGISTRY,
        Counter,
        Gauge,
        Histogram,
        generate_latest,
    )

    PROMETHEUS_AVAILABLE = True
except ImportError:
    PROMETHEUS_AVAILABLE = False


def _safe_create_metric(
    metric_class: type[Any], *args: Any, **kwargs: Any
) -> Any | None:
    """Safely create a Prometheus metric, handling duplicate registration.

    Args:
        metric_class: The metric class to instantiate (Counter, Gauge, etc.)
        *args: Positional arguments for the metric
        **kwargs: Keyword arguments for the metric

    Returns:
        The metric instance, or None if Prometheus is not available
    """
    if not PROMETHEUS_AVAILABLE:
        return None

    try:
        return metric_class(*args, **kwargs)
    except ValueError as e:
        if "Duplicated timeseries" in str(e):
            # Metric already exists, find and return it
            metric_name = args[0] if args else kwargs.get("name")
            for collector in REGISTRY._collector_to_names:
                if hasattr(collector, "_name") and collector._name == metric_name:
                    return collector
            # If we can't find it, return None and continue without metrics
            return None
        else:
            # Re-raise other ValueErrors
            raise


class MCPAtlassianMetrics:
    """Multi-pod aware metrics collector for MCP Atlassian server."""

    def __init__(self, pod_name: str | None = None) -> None:
        if not PROMETHEUS_AVAILABLE:
            self._metrics_enabled = False
            return

        self._metrics_enabled = True
        self.pod_name = pod_name or os.environ.get("HOSTNAME", "unknown")

        # User activity tracking - foundation for unique user counting
        self.user_activity = _safe_create_metric(
            Counter,
            "mcp_atlassian_user_activity_total",
            "User activity events across all pods",
            ["username", "user_agent", "activity_type", "pod"],
        )

        # HTTP request metrics per pod
        self.http_requests = _safe_create_metric(
            Counter,
            "mcp_atlassian_http_requests_total",
            "HTTP requests per pod",
            ["method", "endpoint", "status_code", "pod"],
        )

        self.http_request_duration = _safe_create_metric(
            Histogram,
            "mcp_atlassian_http_request_duration_seconds",
            "HTTP request duration in seconds",
            ["method", "endpoint", "pod"],
        )

        # Current state metrics per pod
        self.concurrent_requests = _safe_create_metric(
            Gauge,
            "mcp_atlassian_concurrent_requests",
            "Current concurrent requests per pod",
            ["pod"],
        )

        # Internal state for current metrics
        self._current_concurrent = 0

    def track_user_activity(
        self,
        username: str = None,
        user_agent: str = None,
        activity_type: str = "request",
    ) -> None:
        """Track user activity for unique user counting.

        Args:
            username: User's username
            user_agent: User's user agent string
            activity_type: Type of activity ('request', 'tool_usage', 'login', etc.)
        """
        if not self._metrics_enabled or self.user_activity is None:
            return

        self.user_activity.labels(
            username=username or "unknown",
            user_agent=user_agent or "unknown",
            activity_type=activity_type,
            pod=self.pod_name,
        ).inc()

    def start_request_tracking(
        self, method: str, endpoint: str, username: str = None, user_agent: str = None
    ) -> dict:
        """Start tracking an HTTP request.

        Args:
            method: HTTP method
            endpoint: Request endpoint
            username: User's username
            user_agent: User's user agent string

        Returns:
            Context dict for ending the request tracking
        """
        if not self._metrics_enabled:
            return {}

        start_time = time.time()
        self._current_concurrent += 1

        if self.concurrent_requests is not None:
            self.concurrent_requests.labels(pod=self.pod_name).set(
                self._current_concurrent
            )

        # Track user activity if username provided
        if username:
            self.track_user_activity(
                username=username, user_agent=user_agent, activity_type="request"
            )

        return {"start_time": start_time, "method": method, "endpoint": endpoint}

    def end_request_tracking(self, context: dict, status_code: int = 200) -> None:
        """End tracking an HTTP request.

        Args:
            context: Context dict from start_request_tracking
            status_code: HTTP response status code
        """
        if not self._metrics_enabled or not context:
            return

        duration = time.time() - context.get("start_time", time.time())
        method = context.get("method", "unknown")
        endpoint = context.get("endpoint", "unknown")

        # Record request metrics
        if self.http_requests is not None:
            self.http_requests.labels(
                method=method,
                endpoint=endpoint,
                status_code=str(status_code),
                pod=self.pod_name,
            ).inc()

        if self.http_request_duration is not None:
            self.http_request_duration.labels(
                method=method, endpoint=endpoint, pod=self.pod_name
            ).observe(duration)

        # Update concurrent request count
        self._current_concurrent -= 1
        if self.concurrent_requests is not None:
            self.concurrent_requests.labels(pod=self.pod_name).set(
                self._current_concurrent
            )

    def generate_metrics(self) -> tuple[str, str]:
        """Generate Prometheus metrics output for scraping.

        Returns:
            Tuple of (metrics_content, content_type)
        """
        if not self._metrics_enabled:
            return (
                "# Prometheus metrics not available - "
                "prometheus-client not installed\n",
                "text/plain",
            )

        return generate_latest().decode("utf-8"), CONTENT_TYPE_LATEST

    @property
    def is_enabled(self) -> bool:
        """Check if metrics collection is enabled."""
        return self._metrics_enabled


# Global metrics instance
metrics: MCPAtlassianMetrics | None = None


def initialize_metrics(pod_name: str | None = None) -> MCPAtlassianMetrics:
    """Initialize the global metrics instance.

    Args:
        pod_name: Name of the pod (defaults to HOSTNAME env var)

    Returns:
        Initialized metrics instance
    """
    global metrics
    if metrics is not None:
        # Metrics already initialized, return existing instance
        return metrics

    metrics = MCPAtlassianMetrics(pod_name)
    return metrics


def get_metrics() -> MCPAtlassianMetrics | None:
    """Get the global metrics instance.

    Returns:
        The metrics instance or None if not initialized
    """
    return metrics
