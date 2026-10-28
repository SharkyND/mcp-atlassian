"""Tests for transient-failure HTTP retry configuration.

The safety property under test is asymmetry by method. A read timeout means the
request reached the server and may already have been applied, so replaying a
write can duplicate it. A connection error means the request never arrived, so
replaying it is always safe.
"""

import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import pytest
import requests

from mcp_atlassian.utils.retry import (
    _REPLAYABLE_METHODS,
    _RETRY_STATUS_CODES,
    configure_retries,
)


class TestRetryPolicyShape:
    """The policy must not mark state-changing methods replayable."""

    def test_write_methods_are_not_replayable(self):
        for method in ("POST", "PUT", "PATCH", "DELETE"):
            assert method not in _REPLAYABLE_METHODS, (
                f"{method} must not be replayed after a read timeout: Jira may "
                "already have applied it, duplicating issues or links"
            )

    def test_reads_are_replayable(self):
        assert "GET" in _REPLAYABLE_METHODS

    def test_retry_statuses_are_transient_only(self):
        assert _RETRY_STATUS_CODES == frozenset({429, 502, 503, 504})
        # 4xx client errors are deterministic; replaying them cannot help.
        for status in (400, 401, 403, 404, 409):
            assert status not in _RETRY_STATUS_CODES

    def test_zero_retries_leaves_session_untouched(self):
        session = requests.Session()
        before = {k: v.max_retries for k, v in session.adapters.items()}
        configure_retries("Jira", session, retries=0)
        after = {k: v.max_retries for k, v in session.adapters.items()}
        assert before == after

    def test_retries_apply_to_every_mounted_adapter(self):
        session = requests.Session()
        configure_retries("Jira", session, retries=3)
        for adapter in session.adapters.values():
            assert adapter.max_retries.total == 3
            assert adapter.max_retries.connect == 3


class _Handler(BaseHTTPRequestHandler):
    """Counts requests; stalls or fails according to the active scenario."""

    counts: dict[str, int] = {}
    mode = "stall"

    def log_message(self, *args: Any) -> None:  # keep test output clean
        pass

    def _record(self) -> int:
        _Handler.counts[self.command] = _Handler.counts.get(self.command, 0) + 1
        return _Handler.counts[self.command]

    def _respond(self) -> None:
        attempt = self._record()
        if self.command in ("POST", "PUT"):
            length = int(self.headers.get("Content-Length", 0))
            self.rfile.read(length)
        if _Handler.mode == "stall":
            time.sleep(3)  # outlast the client read timeout
            return
        if _Handler.mode == "503-then-ok" and attempt == 1:
            self.send_response(503)
            self.end_headers()
            return
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"{}")

    do_GET = _respond  # noqa: N815 - name fixed by BaseHTTPRequestHandler
    do_POST = _respond  # noqa: N815 - name fixed by BaseHTTPRequestHandler
    do_PUT = _respond  # noqa: N815 - name fixed by BaseHTTPRequestHandler


@pytest.fixture
def server():
    _Handler.counts = {}
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


class TestRetryBehaviourOverHTTP:
    """Drive real requests so the policy is verified end to end."""

    @staticmethod
    def _session(retries: int = 2) -> requests.Session:
        session = requests.Session()
        configure_retries("Jira", session, retries=retries, backoff_factor=0)
        return session

    def test_read_timeout_does_not_replay_a_write(self, server):
        """The regression that matters: no duplicate issue/link creation."""
        _Handler.mode = "stall"
        session = self._session()
        with pytest.raises(requests.exceptions.RequestException):
            session.post(f"{server}/rest/api/2/issue", json={}, timeout=0.5)
        assert _Handler.counts.get("POST", 0) == 1, (
            "POST was replayed after a read timeout; Jira may already have "
            "created the issue, so this would duplicate it"
        )

    def test_read_timeout_replays_a_read(self, server):
        _Handler.mode = "stall"
        session = self._session(retries=2)
        with pytest.raises(requests.exceptions.RequestException):
            session.get(f"{server}/rest/api/2/myself", timeout=0.5)
        assert _Handler.counts.get("GET", 0) > 1, "GET should be retried"

    def test_transient_status_is_retried_for_reads(self, server):
        _Handler.mode = "503-then-ok"
        session = self._session()
        response = session.get(f"{server}/rest/api/2/myself", timeout=5)
        assert response.status_code == 200
        assert _Handler.counts.get("GET", 0) == 2

    def test_transient_status_is_not_retried_for_writes(self, server):
        _Handler.mode = "503-then-ok"
        session = self._session()
        response = session.post(f"{server}/rest/api/2/issue", json={}, timeout=5)
        assert response.status_code == 503
        assert _Handler.counts.get("POST", 0) == 1

    def test_connection_error_replays_even_a_write(self):
        """Nothing reached the server, so replaying cannot duplicate work."""
        session = self._session(retries=2)
        # Port 1 is closed, so every attempt fails during connect.
        with pytest.raises(requests.exceptions.ConnectionError) as exc_info:
            session.post("http://127.0.0.1:1/rest/api/2/issue", json={}, timeout=2)
        assert "max retries exceeded" in str(exc_info.value).lower(), (
            "connection errors should be retried for writes as well"
        )
