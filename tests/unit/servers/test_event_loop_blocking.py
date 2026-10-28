"""Regression tests guarding against blocking the asyncio event loop.

Atlassian SDK calls are synchronous. Calling them directly from an ``async``
tool handler blocks the single event loop for the call's full duration, which
starves the ``/healthz`` route and causes Kubernetes to fail liveness probes
and restart the pod. Every tool handler must therefore hand blocking work to a
worker thread via ``asyncio.to_thread``.
"""

import ast
import re
from pathlib import Path

import pytest

SERVERS_DIR = Path(__file__).resolve().parents[3] / "src" / "mcp_atlassian" / "servers"

# Request-scoped Atlassian clients resolved inside tool handlers. Any direct
# call on these blocks the event loop.
BLOCKING_CLIENTS = ("jira", "confluence_fetcher", "bitbucket", "xray")

CALL_PATTERN = re.compile(
    r"\b(" + "|".join(BLOCKING_CLIENTS) + r")\.([A-Za-z_][\w.]*)\s*\("
)

SERVER_MODULES = ["jira.py", "confluence.py", "bitbucket.py", "xray.py"]


def _async_line_ranges(source: str) -> list[tuple[int, int]]:
    """Return 1-based inclusive line ranges covering every async function."""
    return [
        (node.lineno, node.end_lineno)
        for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.AsyncFunctionDef) and node.end_lineno is not None
    ]


def _unwrapped_calls(source: str) -> list[tuple[int, str]]:
    """Find blocking client calls inside async functions that lack to_thread."""
    ranges = _async_line_ranges(source)
    offenders: list[tuple[int, str]] = []
    for match in CALL_PATTERN.finditer(source):
        line_no = source.count("\n", 0, match.start()) + 1
        if not any(start <= line_no <= end for start, end in ranges):
            continue
        preceding = source[max(0, match.start() - 80) : match.start()]
        if "to_thread(" in preceding:
            continue
        offenders.append((line_no, f"{match.group(1)}.{match.group(2)}"))
    return offenders


@pytest.mark.parametrize("module_name", SERVER_MODULES)
def test_no_blocking_client_calls_in_async_handlers(module_name: str) -> None:
    source = (SERVERS_DIR / module_name).read_text(encoding="utf-8")
    offenders = _unwrapped_calls(source)
    assert not offenders, (
        f"{module_name} calls blocking Atlassian clients directly inside async "
        "handlers, which stalls the event loop and trips liveness probes. Wrap "
        "them with `await asyncio.to_thread(...)`. Offending calls: "
        + ", ".join(f"line {line}: {call}" for line, call in offenders)
    )


@pytest.mark.anyio
async def test_to_thread_keeps_event_loop_responsive() -> None:
    """A blocking call offloaded to a thread must not stall other coroutines."""
    import asyncio
    import time

    ticks = 0

    async def heartbeat() -> None:
        nonlocal ticks
        while True:
            ticks += 1
            await asyncio.sleep(0.01)

    beat = asyncio.create_task(heartbeat())
    try:
        await asyncio.to_thread(time.sleep, 0.3)
    finally:
        beat.cancel()

    # With the blocking call on the loop this stays at 1; offloaded it keeps ticking.
    assert ticks > 5, f"event loop appeared blocked (only {ticks} heartbeats)"
