"""Tests for the main MCP server implementation."""

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from starlette.requests import Request
from starlette.responses import JSONResponse

from mcp_atlassian.servers.main import UserTokenMiddleware, main_mcp


@pytest.mark.anyio
async def test_run_server_stdio():
    """Test that main_mcp.run_async is called with stdio transport."""
    with patch.object(main_mcp, "run_async") as mock_run_async:
        mock_run_async.return_value = None
        await main_mcp.run_async(transport="stdio")
        mock_run_async.assert_called_once_with(transport="stdio")


@pytest.mark.anyio
async def test_run_server_sse():
    """Test that main_mcp.run_async is called with sse transport and correct port."""
    with patch.object(main_mcp, "run_async") as mock_run_async:
        mock_run_async.return_value = None
        test_port = 9000
        await main_mcp.run_async(transport="sse", port=test_port)
        mock_run_async.assert_called_once_with(transport="sse", port=test_port)


@pytest.mark.anyio
async def test_run_server_streamable_http():
    """Test that main_mcp.run_async is called with streamable-http transport and correct parameters."""
    with patch.object(main_mcp, "run_async") as mock_run_async:
        mock_run_async.return_value = None
        test_port = 9001
        test_host = "127.0.0.1"
        test_path = "/custom_mcp"
        await main_mcp.run_async(
            transport="streamable-http", port=test_port, host=test_host, path=test_path
        )
        mock_run_async.assert_called_once_with(
            transport="streamable-http", port=test_port, host=test_host, path=test_path
        )


@pytest.mark.anyio
async def test_run_server_invalid_transport():
    """Test that run_server raises ValueError for invalid transport."""
    # We don't need to patch run_async here as the error occurs before it's called
    with pytest.raises(ValueError) as excinfo:
        await main_mcp.run_async(transport="invalid")  # type: ignore

    assert "Unknown transport" in str(excinfo.value)
    assert "invalid" in str(excinfo.value)


@pytest.mark.anyio
async def test_health_check_endpoint():
    """Test the health check endpoint returns 200 and correct JSON response."""
    app = main_mcp.http_app()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/healthz")

        assert response.status_code == 200
        assert response.json() == {"status": "ok"}


@pytest.mark.anyio
async def test_sse_app_health_check_endpoint():
    """Test the /healthz endpoint on the SSE app returns 200 and correct JSON response."""
    # Use http_app with sse transport instead of deprecated sse_app()
    app = main_mcp.http_app(transport="sse")
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/healthz")
        assert response.status_code == 200
        assert response.json() == {"status": "ok"}


@pytest.mark.anyio
async def test_streamable_http_app_health_check_endpoint():
    """Test the /healthz endpoint on the Streamable HTTP app returns 200 and correct JSON response."""
    # Use http_app with default streamable-http transport instead of deprecated streamable_http_app()
    app = main_mcp.http_app(transport="streamable-http")
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/healthz")
        assert response.status_code == 200
        assert response.json() == {"status": "ok"}


class TestUserTokenMiddleware:
    """Tests for the UserTokenMiddleware class."""

    @pytest.fixture
    def middleware(self):
        """Create a UserTokenMiddleware instance for testing."""
        mock_app = AsyncMock()
        # Create a mock MCP server to avoid warnings
        mock_mcp_server = MagicMock()
        mock_mcp_server.settings.streamable_http_path = "/mcp"
        return UserTokenMiddleware(mock_app, mcp_server_ref=mock_mcp_server)

    @pytest.fixture
    def mock_request(self):
        """Create a mock request for testing."""
        request = MagicMock(spec=Request)
        request.url.path = "/mcp"
        request.method = "POST"
        request.headers = {}
        # Create a real state object that can be modified
        from types import SimpleNamespace

        request.state = SimpleNamespace()
        return request

    @pytest.fixture
    def mock_call_next(self):
        """Create a mock call_next function."""
        mock_response = JSONResponse({"test": "response"})
        call_next = AsyncMock(return_value=mock_response)
        return call_next

    @pytest.mark.anyio
    async def test_cloud_id_header_extraction_success(
        self, middleware, mock_request, mock_call_next, monkeypatch
    ):
        """Test successful cloud ID header extraction."""
        # Ensure REQUIRE_USERNAME is not set for this test
        monkeypatch.delenv("REQUIRE_USERNAME", raising=False)

        # Create a mock ASGI scope for the new ASGI middleware
        scope = {
            "type": "http",
            "path": "/mcp",
            "method": "POST",
            "headers": [
                (b"authorization", b"Bearer test-token"),
                (b"x-atlassian-cloud-id", b"test-cloud-id-123"),
            ],
            "state": {},
        }

        # Mock receive and send functions for ASGI
        async def mock_receive():
            return {"type": "http.request", "body": b"", "more_body": False}

        async def mock_send(message):
            pass

        # Mock the app to verify it gets called with modified scope
        middleware.app = AsyncMock()

        # Call the ASGI middleware
        await middleware(scope, mock_receive, mock_send)

        # Verify cloud ID was extracted and stored in scope state
        assert "user_atlassian_cloud_id" in scope["state"]
        assert scope["state"]["user_atlassian_cloud_id"] == "test-cloud-id-123"

        # Verify the app was called with the modified scope
        middleware.app.assert_called_once()

    @pytest.mark.anyio
    async def test_username_requirement_disabled_by_default(
        self, middleware, monkeypatch
    ):
        """Test that username requirement is disabled by default."""
        # Ensure REQUIRE_USERNAME is not set for this test
        monkeypatch.delenv("REQUIRE_USERNAME", raising=False)

        scope = {
            "type": "http",
            "path": "/mcp",
            "method": "POST",
            "headers": [
                (b"authorization", b"Bearer test-token"),
            ],
            "state": {},
        }

        async def mock_receive():
            return {"type": "http.request", "body": b"", "more_body": False}

        async def mock_send(message):
            pass

        middleware.app = AsyncMock()
        await middleware(scope, mock_receive, mock_send)

        # Should proceed normally without username requirement
        middleware.app.assert_called_once()

    @pytest.mark.anyio
    async def test_username_requirement_enabled_with_username(
        self, middleware, monkeypatch
    ):
        """Test username requirement succeeds when username header is present."""
        monkeypatch.setenv("REQUIRE_USERNAME", "true")

        scope = {
            "type": "http",
            "path": "/mcp",
            "method": "POST",
            "headers": [
                (b"authorization", b"Bearer test-token"),
                (b"x-atlassian-username", b"test-user"),
            ],
            "state": {},
        }

        async def mock_receive():
            return {"type": "http.request", "body": b"", "more_body": False}

        async def mock_send(message):
            pass

        middleware.app = AsyncMock()
        await middleware(scope, mock_receive, mock_send)

        # Should proceed normally with username present
        middleware.app.assert_called_once()

    @pytest.mark.anyio
    async def test_username_requirement_enabled_without_username(
        self, middleware, monkeypatch
    ):
        """Test username requirement fails when username header is missing."""
        monkeypatch.setenv("REQUIRE_USERNAME", "true")

        scope = {
            "type": "http",
            "path": "/mcp",
            "method": "POST",
            "headers": [
                (b"authorization", b"Bearer test-token"),
            ],
            "state": {},
        }

        async def mock_receive():
            return {"type": "http.request", "body": b"", "more_body": False}

        sent_messages = []

        async def mock_send(message):
            sent_messages.append(message)

        middleware.app = AsyncMock()
        await middleware(scope, mock_receive, mock_send)

        # Should not call the app
        middleware.app.assert_not_called()

        # Should send 400 error response
        assert len(sent_messages) >= 2
        response_start = sent_messages[0]
        assert response_start["type"] == "http.response.start"
        assert response_start["status"] == 400

        response_body = sent_messages[1]
        assert response_body["type"] == "http.response.body"
        assert b"Username required" in response_body["body"]
        assert b"X-Atlassian-Username" in response_body["body"]

    @pytest.mark.anyio
    async def test_username_requirement_with_confluence_username(
        self, middleware, monkeypatch
    ):
        """Test username requirement accepts username header (any service)."""
        monkeypatch.setenv("REQUIRE_USERNAME", "true")

        scope = {
            "type": "http",
            "path": "/mcp",
            "method": "POST",
            "headers": [
                (b"authorization", b"Bearer test-token"),
                (b"x-atlassian-username", b"confluence-user"),
            ],
            "state": {},
        }

        async def mock_receive():
            return {"type": "http.request", "body": b"", "more_body": False}

        async def mock_send(message):
            pass

        middleware.app = AsyncMock()
        await middleware(scope, mock_receive, mock_send)

        # Should proceed normally with Confluence username present
        middleware.app.assert_called_once()

    @pytest.mark.anyio
    async def test_username_requirement_with_bitbucket_username(
        self, middleware, monkeypatch
    ):
        """Test username requirement accepts username header (any service)."""
        monkeypatch.setenv("REQUIRE_USERNAME", "true")

        scope = {
            "type": "http",
            "path": "/mcp",
            "method": "POST",
            "headers": [
                (b"authorization", b"Bearer test-token"),
                (b"x-atlassian-username", b"bitbucket-user"),
            ],
            "state": {},
        }

        async def mock_receive():
            return {"type": "http.request", "body": b"", "more_body": False}

        async def mock_send(message):
            pass

        middleware.app = AsyncMock()
        await middleware(scope, mock_receive, mock_send)

        # Should proceed normally with Bitbucket username present
        middleware.app.assert_called_once()
