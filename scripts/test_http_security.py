"""Real MCP security smoke, restricted to a network-isolated synthetic container.

Run with --network none --add-host synthetic-jira.test:127.0.0.1. The fixture
keeps generated credentials in memory and never contacts a real Atlassian API.
"""

import asyncio
import json
import os
import secrets
import socket
import subprocess
import sys
import tempfile
import threading
from contextlib import asynccontextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.metadata import version
from pathlib import Path
from typing import Any

import httpx
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

HOST = "synthetic-jira.test"
MCP_URL = "http://127.0.0.1:8001/mcp"
TOKENS = {secrets.token_hex(32): user for user in ("synthetic-a", "synthetic-b")}


class Jira(BaseHTTPRequestHandler):
    """Only the synthetic endpoints needed by the Jira issue reader."""

    def log_message(self, format: str, *args: object) -> None:
        """Keep credentials and HTTP bodies out of logs."""

    def do_GET(self) -> None:  # noqa: N802 -- stdlib callback.
        """Answer one read, deriving its owner from the synthetic PAT."""
        token = self.headers.get("Authorization", "").removeprefix("Bearer ")
        user = TOKENS.get(token)
        status = 401
        payload: dict[str, Any] = {"error": "synthetic credential denied"}
        if user:
            status = 200
            who = {
                "name": user,
                "key": user,
                "accountId": user,
                "displayName": user,
                "active": True,
            }
            if self.path.split("?")[0].endswith("/myself"):
                payload = who
            elif "/issue/" in self.path:
                payload = {
                    "id": "1",
                    "key": "SEC-1",
                    "fields": {
                        "summary": "Synthetic issue for " + user,
                        "description": "synthetic",
                        "status": {"name": "Open"},
                        "issuetype": {"name": "Task"},
                        "reporter": who,
                        "assignee": who,
                        "creator": who,
                        "project": {"key": "SEC", "name": "Synthetic"},
                    },
                }
            else:
                payload = {
                    "version": "9.0.0",
                    "versionNumbers": [9, 0, 0],
                    "deploymentType": "Server",
                }
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def headers(token: str) -> dict[str, str]:
    """Create fresh private transport headers, never tool arguments."""
    return {
        "X-Atlassian-Jira-Personal-Token": token,
        "X-Atlassian-Jira-Url": f"http://{HOST}:18081",
    }


@asynccontextmanager
async def session(token: str) -> Any:
    """One private HTTP client and MCP session for one invocation identity."""
    async with httpx.AsyncClient(
        headers=headers(token), timeout=10, trust_env=False, follow_redirects=False
    ) as http:
        async with streamable_http_client(MCP_URL, http_client=http) as (
            read,
            write,
            identifier,
        ):
            async with ClientSession(read, write) as client:
                initialized = await client.initialize()
                if initialized.serverInfo.name != "Atlassian MCP":
                    raise RuntimeError("Unexpected synthetic MCP identity")
                yield client, identifier


def rpc_result(response: httpx.Response) -> dict[str, Any]:
    """Read JSON or the SDK's SSE JSON response without printing raw bodies."""
    if response.headers.get("content-type", "").startswith("application/json"):
        result: dict[str, Any] = response.json()
        return result
    for line in response.text.splitlines():
        if line.startswith("data: "):
            result = json.loads(line[6:])
            if "result" in result or "error" in result:
                return result
    raise RuntimeError("Synthetic MCP response missing")


async def exercise(process: subprocess.Popen[bytes]) -> list[str]:
    """Check the real transport boundary and per-request user ownership."""
    async with httpx.AsyncClient(timeout=5, trust_env=False) as http:
        async with asyncio.timeout(45):
            while process.poll() is None:
                try:
                    response = await http.get("http://127.0.0.1:8001/healthz")
                    if response.status_code == 200:
                        break
                except httpx.HTTPError:
                    pass
                await asyncio.sleep(0.1)
            else:
                raise RuntimeError("Synthetic MCP process exited before readiness")
        no_auth = await http.post(
            MCP_URL, json={"jsonrpc": "2.0", "id": 1, "method": "ping"}
        )
        if no_auth.status_code != 401:
            raise RuntimeError("Unauthenticated MCP request accepted")
        blocked = await http.post(
            MCP_URL,
            json={},
            headers={
                "X-Atlassian-Jira-Personal-Token": "synthetic",
                "X-Atlassian-Jira-Url": "http://169.254.169.254/latest/meta-data",
            },
        )
        if blocked.status_code != 401:
            raise RuntimeError("Private metadata destination accepted")
    values = list(TOKENS)

    async def invoke(token: str) -> str:
        async with session(token) as (client, _):
            result = await client.call_tool(
                "jira_get_issue", {"issue_key": "SEC-1", "update_history": False}
            )
            if result.isError:
                raise RuntimeError("Synthetic authorized Jira call failed")
            return result.model_dump_json()

    first, second = await asyncio.gather(invoke(values[0]), invoke(values[1]))
    for text, mine, other in (
        (first, "synthetic-a", "synthetic-b"),
        (second, "synthetic-b", "synthetic-a"),
    ):
        if (
            "Synthetic issue for " + mine not in text
            or "Synthetic issue for " + other in text
        ):
            raise RuntimeError("Synthetic user results crossed")
    async with session(values[0]) as (client, identifier):
        tools = await client.list_tools()
        if [t.name for t in tools.tools] != ["jira_get_issue"]:
            raise RuntimeError("Tool allowlist was not enforced at discovery")
        denied = await client.call_tool("jira_create_issue", {})
        if not denied.isError:
            raise RuntimeError("Hidden write tool could be invoked by name")
        async with httpx.AsyncClient(timeout=10, trust_env=False) as http:
            switched = await http.post(
                MCP_URL,
                headers={
                    **headers(values[1]),
                    "Accept": "application/json, text/event-stream",
                    "Mcp-Session-Id": str(identifier()),
                },
                json={
                    "jsonrpc": "2.0",
                    "id": 123,
                    "method": "tools/call",
                    "params": {
                        "name": "jira_get_issue",
                        "arguments": {"issue_key": "SEC-1", "update_history": False},
                    },
                },
            )
            if switched.status_code == 200:
                text = json.dumps(rpc_result(switched))
                if (
                    "Synthetic issue for synthetic-a" in text
                    or "Synthetic issue for synthetic-b" not in text
                ):
                    raise RuntimeError(
                        "Reused MCP session retained another user's identity"
                    )
            elif switched.status_code not in (401, 403, 404):
                raise RuntimeError("Unexpected session isolation status")
    async with session("synthetic-invalid") as (client, _):
        denied = await client.call_tool(
            "jira_get_issue", {"issue_key": "SEC-1", "update_history": False}
        )
        if not denied.isError:
            raise RuntimeError("Invalid personal credential used a fallback")
    return [
        "real HTTP startup",
        "unauthenticated MCP denied",
        "private destination denied",
        "concurrent user isolation",
        "filtered discovery",
        "hidden write denied",
        "session identity isolation",
        "invalid credential denied",
    ]


def main() -> int:
    """Refuse external network routes and run only the private local fixture."""
    if not Path("/.dockerenv").exists() or os.geteuid() == 0:
        raise RuntimeError("Run this probe in the non-root built container")
    if any(
        line.split()[1] == "00000000"
        for line in Path("/proc/net/route").read_text().splitlines()[1:]
    ):
        raise RuntimeError("Run this probe with --network none")
    if {
        entry[4][0]
        for entry in socket.getaddrinfo(HOST, 18081, type=socket.SOCK_STREAM)
    } != {"127.0.0.1"}:
        raise RuntimeError("Synthetic Jira alias must resolve only to loopback")
    server = ThreadingHTTPServer(("127.0.0.1", 18081), Jira)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    directory = tempfile.TemporaryDirectory(prefix="mcp-security-")
    env = {
        "PATH": os.environ["PATH"],
        "HOME": directory.name,
        "PYTHONDONTWRITEBYTECODE": "1",
        "ATLASSIAN_OAUTH_ENABLE": "true",
        "READ_ONLY_MODE": "true",
        "ENABLED_TOOLS": "jira_get_issue",
        "MCP_ALLOWED_URL_DOMAINS": HOST,
        "MCP_ATLASSIAN_VALIDATION_CACHE_TTL": "0",
    }
    process = subprocess.Popen(
        [
            sys.executable,
            "-c",
            "from mcp_atlassian import main; main(['--transport','streamable-http','--host','127.0.0.1','--port','8001','--path','/mcp','--read-only'])",
        ],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        checks = asyncio.run(exercise(process))
        print(
            json.dumps(
                {
                    "scope": "isolated-synthetic-atlassian-security",
                    "passed": True,
                    "package": version("mcp-atlassian"),
                    "fastmcp": version("fastmcp"),
                    "external_calls": False,
                    "checks": checks,
                }
            )
        )
        return 0
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        directory.cleanup()


if __name__ == "__main__":
    raise SystemExit(main())
