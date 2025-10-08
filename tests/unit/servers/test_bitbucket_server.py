import json
from types import SimpleNamespace

import pytest

from mcp_atlassian.exceptions import MCPAtlassianAuthenticationError
from mcp_atlassian.servers import bitbucket as bitbucket_server

pytestmark = pytest.mark.anyio


class DummyModel:
    """Simple stand-in for models with a model_dump method."""

    def __init__(self, data: dict) -> None:
        self._data = data

    def model_dump(self, *args, **kwargs) -> dict:  # noqa: D401, ANN002, ANN003
        """Return stored data ignoring serialization kwargs."""
        return self._data


def make_ctx(read_only: bool = False) -> SimpleNamespace:
    """Create a minimal FastMCP context substitute."""
    app_ctx = SimpleNamespace(read_only=read_only)
    lifespan_context = {"app_lifespan_context": app_ctx}
    request_context = SimpleNamespace(lifespan_context=lifespan_context)
    return SimpleNamespace(request_context=request_context)


def tool_fn(name: str):
    """Return the underlying coroutine for a tool name."""
    return getattr(bitbucket_server, name).fn


success_cases = [
    {
        "func": "list_workspaces_or_projects",
        "method": "get_all_workspaces",
        "return_value": [DummyModel({"slug": "sample"})],
        "kwargs": {},
        "expected": [{"slug": "sample"}],
    },
    {
        "func": "list_repositories",
        "method": "get_repositories",
        "return_value": [DummyModel({"name": "repo"})],
        "kwargs": {"workspace": "ws"},
        "expected": [{"name": "repo"}],
    },
    {
        "func": "get_repository_info",
        "method": "get_repository_info",
        "return_value": DummyModel({"key": "rep"}),
        "kwargs": {"workspace": "ws", "repository": "rep"},
        "expected": {"key": "rep"},
    },
    {
        "func": "list_branches",
        "method": "get_branches",
        "return_value": [DummyModel({"displayId": "main"})],
        "kwargs": {"workspace": "ws", "repository": "rep"},
        "expected": [{"displayId": "main"}],
    },
    {
        "func": "get_default_branch",
        "method": "get_default_branch",
        "return_value": DummyModel({"displayId": "main"}),
        "kwargs": {"workspace": "ws", "repository": "rep"},
        "expected": {"displayId": "main"},
    },
    {
        "func": "get_file_content",
        "method": "get_file_content",
        "return_value": b"hello world",
        "kwargs": {
            "workspace": "ws",
            "repository": "rep",
            "file_path": "README.md",
            "branch": "main",
        },
        "expected": {
            "workspace": "ws",
            "repository": "rep",
            "file_path": "README.md",
            "branch": "main",
            "content": "hello world",
        },
    },
    {
        "func": "list_directory",
        "method": "get_directory_content",
        "return_value": [{"path": "src"}],
        "kwargs": {
            "workspace": "ws",
            "repository": "rep",
            "path": "",
            "branch": "main",
        },
        "expected": [{"path": "src"}],
    },
    {
        "func": "list_pull_requests",
        "method": "get_pull_requests",
        "return_value": [{"id": 1}],
        "kwargs": {"workspace": "ws", "repository": "rep", "state": "OPEN"},
        "expected": [{"id": 1}],
    },
    {
        "func": "pull_request_activities",
        "method": "get_pull_request_activities",
        "return_value": [{"action": "comment"}],
        "kwargs": {"workspace": "ws", "repository": "rep", "pull_request_id": 4},
        "expected": [{"action": "comment"}],
    },
    {
        "func": "get_pull_request",
        "method": "get_pull_request",
        "return_value": DummyModel({"id": 7}),
        "kwargs": {"workspace": "ws", "repository": "rep", "pull_request_id": 7},
        "expected": {"id": 7},
    },
    {
        "func": "get_commit_changes",
        "method": "get_commit_changes",
        "return_value": DummyModel({"changes": ["file"]}),
        "kwargs": {
            "workspace": "ws",
            "repository": "rep",
            "commit_id": "abc",
            "merges": "include",
            "hash_newest": None,
        },
        "expected": {"changes": ["file"]},
    },
    {
        "func": "get_commits",
        "method": "get_commits",
        "return_value": [DummyModel({"hash": "abc"})],
        "kwargs": {
            "workspace": "ws",
            "repository": "rep",
            "limit": 25,
            "until": None,
            "since": None,
        },
        "expected": [{"hash": "abc"}],
    },
]

create_pr_capture: dict = {}
create_branch_capture: dict = {}

success_cases.extend(
    [
        {
            "func": "create_pull_request",
            "method": "create_pull_request",
            "method_impl": lambda workspace,
            repository,
            pr_data,
            *,
            capture=create_pr_capture: (
                capture.update({"payload": pr_data}) or {"id": 42}
            ),
            "kwargs": {
                "workspace": "ws",
                "repository": "rep",
                "title": "Add feature",
                "source_branch": "feature",
                "destination_branch": "main",
                "description": "desc",
            },
            "expected": {"success": True, "pull_request": {"id": 42}},
            "expected_payload": {
                "title": "Add feature",
                "description": "desc",
                "state": "OPEN",
                "open": True,
                "closed": False,
                "fromRef": {
                    "id": "refs/heads/feature",
                    "repository": {
                        "slug": "rep",
                        "name": None,
                        "project": {"key": "ws"},
                    },
                },
                "toRef": {
                    "id": "refs/heads/main",
                    "repository": {
                        "slug": "rep",
                        "name": None,
                        "project": {"key": "ws"},
                    },
                },
                "locked": False,
                "reviewers": [],
            },
            "capture": create_pr_capture,
        },
        {
            "func": "create_branch",
            "method": "create_branch",
            "method_impl": lambda workspace,
            repository,
            branch_data,
            *,
            capture=create_branch_capture: (
                capture.update({"payload": branch_data}) or {"name": "feature"}
            ),
            "kwargs": {
                "workspace": "ws",
                "repository": "rep",
                "branch_name": "feature",
                "source_branch": "develop",
            },
            "expected": {
                "success": True,
                "branch": {"name": "feature"},
                "source_branch": "develop",
            },
            "expected_payload": {
                "name": "feature",
                "target": {"branch": {"name": "develop"}},
            },
            "capture": create_branch_capture,
        },
        {
            "func": "add_pull_request_blocker_comment",
            "method": "add_pull_request_blocker_comment",
            "return_value": {"text": "ok"},
            "kwargs": {
                "workspace": "ws",
                "repository": "rep",
                "pull_request_id": 3,
                "comment": "blocking comment",
                "severity": "BLOCKER",
            },
            "expected": {
                "success": True,
                "comment": {"text": "ok"},
                "pull_request_id": 3,
            },
        },
        {
            "func": "add_pull_request_comment",
            "method": "add_pull_request_comment",
            "return_value": {"text": "ok"},
            "kwargs": {
                "workspace": "ws",
                "repository": "rep",
                "pull_request_id": 5,
                "comment": "regular",
            },
            "expected": {
                "success": True,
                "comment": {"text": "ok"},
                "pull_request_id": 5,
            },
        },
    ]
)


@pytest.mark.parametrize(
    "case", success_cases, ids=[case["func"] for case in success_cases]
)
async def test_bitbucket_tools_success(
    monkeypatch: pytest.MonkeyPatch, case: dict
) -> None:
    capture = case.get("capture")
    if capture is not None:
        capture.clear()

    fetcher = SimpleNamespace()

    if method_impl := case.get("method_impl"):
        setattr(fetcher, case["method"], method_impl)
    else:
        return_value = case["return_value"]

        def _method(*_args, _ret=return_value, **_kwargs):  # noqa: ANN002, ANN003
            return _ret

        setattr(fetcher, case["method"], _method)

    async def fake_fetcher(_ctx):  # noqa: ANN001
        return fetcher

    monkeypatch.setattr(bitbucket_server, "get_bitbucket_fetcher", fake_fetcher)

    ctx = make_ctx()
    result = await tool_fn(case["func"])(ctx, **case["kwargs"])
    parsed = json.loads(result)

    assert parsed == case["expected"]

    if capture is not None:
        assert capture["payload"] == case["expected_payload"]


error_cases = [
    {
        "func": case["func"],
        "kwargs": case["kwargs"],
    }
    for case in success_cases
]


@pytest.mark.parametrize(
    "case", error_cases, ids=[case["func"] for case in error_cases]
)
async def test_bitbucket_tools_configuration_error(
    monkeypatch: pytest.MonkeyPatch, case: dict
) -> None:
    async def fake_fetcher(_ctx):  # noqa: ANN001
        raise ValueError("missing config")

    monkeypatch.setattr(bitbucket_server, "get_bitbucket_fetcher", fake_fetcher)

    ctx = make_ctx()
    result = await tool_fn(case["func"])(ctx, **case["kwargs"])
    parsed = json.loads(result)

    assert parsed["success"] is False
    assert "Configuration Error" in parsed["error"]


async def test_get_default_branch_no_default(monkeypatch: pytest.MonkeyPatch) -> None:
    fetcher = SimpleNamespace(get_default_branch=lambda *args, **kwargs: None)

    async def fake_fetcher(_ctx):  # noqa: ANN001
        return fetcher

    monkeypatch.setattr(bitbucket_server, "get_bitbucket_fetcher", fake_fetcher)

    ctx = make_ctx()
    result = await tool_fn("get_default_branch")(ctx, "ws", "rep")
    parsed = json.loads(result)

    assert parsed == {"error": "No default branch found"}


async def test_create_branch_read_only(monkeypatch: pytest.MonkeyPatch) -> None:
    ctx = make_ctx(read_only=True)

    async def fake_fetcher(_ctx):  # noqa: ANN001
        AssertionError("Fetcher should not be called when read-only")

    monkeypatch.setattr(bitbucket_server, "get_bitbucket_fetcher", fake_fetcher)

    with pytest.raises(ValueError) as exc:
        await tool_fn("create_branch")(
            ctx, "ws", "rep", branch_name="feature", source_branch="main"
        )

    assert "read-only" in str(exc.value)


async def test_list_workspaces_auth_error(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_fetcher(_ctx):  # noqa: ANN001
        raise MCPAtlassianAuthenticationError("bad token")

    monkeypatch.setattr(bitbucket_server, "get_bitbucket_fetcher", fake_fetcher)

    result = await tool_fn("list_workspaces_or_projects")(make_ctx())
    parsed = json.loads(result)

    assert parsed["error"].startswith("Authentication/Permission Error")


async def test_list_repositories_network_error(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_fetcher(_ctx):  # noqa: ANN001
        raise OSError("network down")

    monkeypatch.setattr(bitbucket_server, "get_bitbucket_fetcher", fake_fetcher)

    result = await tool_fn("list_repositories")(make_ctx(), workspace="ws")
    parsed = json.loads(result)

    assert parsed["error"].startswith("Network or API Error")


async def test_get_pull_request_unexpected_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def fake_fetcher(_ctx):  # noqa: ANN001
        raise RuntimeError("boom")

    monkeypatch.setattr(bitbucket_server, "get_bitbucket_fetcher", fake_fetcher)

    result = await tool_fn("get_pull_request")(
        make_ctx(), "ws", "rep", pull_request_id=1
    )
    parsed = json.loads(result)

    assert parsed["error"].startswith("An unexpected error occurred")
