"""Unit tests for the Confluence FastMCP server."""

import json
import logging
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastmcp import FastMCP
from starlette.requests import Request

from src.mcp_atlassian.confluence import ConfluenceFetcher
from src.mcp_atlassian.confluence.config import ConfluenceConfig
from src.mcp_atlassian.models.confluence.common import ConfluenceUser
from src.mcp_atlassian.models.confluence.page import ConfluencePage
from src.mcp_atlassian.servers.context import MainAppContext
from src.mcp_atlassian.servers.main import AtlassianMCP
from src.mcp_atlassian.utils.oauth import OAuthConfig

logger = logging.getLogger(__name__)


@pytest.fixture
def mock_confluence_fetcher():
    """Create a mocked ConfluenceFetcher instance for testing."""
    mock_fetcher = MagicMock(spec=ConfluenceFetcher)

    # Mock page for various methods
    mock_page = MagicMock(spec=ConfluencePage)
    mock_page.to_simplified_dict.return_value = {
        "id": "123456",
        "title": "Test Page Mock Title",
        "url": "https://example.atlassian.net/wiki/spaces/TEST/pages/123456/Test+Page",
        "content": {
            "value": "This is a test page content in Markdown",
            "format": "markdown",
        },
    }
    mock_page.content = "This is a test page content in Markdown"

    # Set up mock responses for each method
    mock_fetcher.search.return_value = [mock_page]
    mock_fetcher.get_page_content.return_value = mock_page
    mock_fetcher.get_page_children.return_value = [mock_page]
    mock_fetcher.create_page.return_value = mock_page
    mock_fetcher.update_page.return_value = mock_page
    mock_fetcher.delete_page.return_value = True

    # Mock comment
    mock_comment = MagicMock()
    mock_comment.to_simplified_dict.return_value = {
        "id": "789",
        "author": "Test User",
        "created": "2023-08-01T12:00:00.000Z",
        "body": "This is a test comment",
    }
    mock_fetcher.get_page_comments.return_value = [mock_comment]

    # Mock label
    mock_label = MagicMock()
    mock_label.to_simplified_dict.return_value = {"id": "lbl1", "name": "test-label"}
    mock_fetcher.get_page_labels.return_value = [mock_label]
    mock_fetcher.add_page_label.return_value = [mock_label]

    # Mock add_comment method
    mock_comment = MagicMock()
    mock_comment.to_simplified_dict.return_value = {
        "id": "987",
        "author": "Test User",
        "created": "2023-08-01T13:00:00.000Z",
        "body": "This is a test comment added via API",
    }
    mock_fetcher.add_comment.return_value = mock_comment

    # Mock search_user method
    mock_user_search_result = MagicMock()
    mock_user_search_result.to_simplified_dict.return_value = {
        "entity_type": "user",
        "title": "First Last",
        "score": 0.0,
        "user": {
            "account_id": "a031248587011jasoidf9832jd8j1",
            "display_name": "First Last",
            "email": "first.last@foo.com",
            "profile_picture": "/wiki/aa-avatar/a031248587011jasoidf9832jd8j1",
            "is_active": True,
        },
        "url": "/people/a031248587011jasoidf9832jd8j1",
        "last_modified": "2025-06-02T13:35:59.680Z",
        "excerpt": "",
    }
    mock_fetcher.search_user.return_value = [mock_user_search_result]

    return mock_fetcher


@pytest.fixture
def mock_base_confluence_config():
    """Create a mock base ConfluenceConfig for MainAppContext using OAuth for multi-user scenario."""
    mock_oauth_config = OAuthConfig(
        client_id="server_client_id",
        client_secret="server_client_secret",
        redirect_uri="http://localhost",
        scope="read:confluence",
        cloud_id="mock_cloud_id",
    )
    return ConfluenceConfig(
        url="https://mock.atlassian.net/wiki",
        auth_type="oauth",
        oauth_config=mock_oauth_config,
    )


@pytest.fixture
def test_confluence_mcp(mock_confluence_fetcher, mock_base_confluence_config):
    """Create a test FastMCP instance with standard configuration."""

    @asynccontextmanager
    async def test_lifespan(app: FastMCP) -> AsyncGenerator[MainAppContext, None]:
        try:
            yield MainAppContext(
                full_confluence_config=mock_base_confluence_config, read_only=False
            )
        finally:
            pass

    test_mcp = AtlassianMCP(
        name="TestConfluence",
        lifespan=test_lifespan,
    )

    # Mount the actual confluence MCP instance
    from mcp_atlassian.servers.confluence import confluence_mcp

    test_mcp.mount(confluence_mcp, "confluence")

    return test_mcp


@pytest.fixture
def no_fetcher_test_confluence_mcp(mock_base_confluence_config):
    """Create a test FastMCP instance that simulates missing Confluence fetcher."""

    @asynccontextmanager
    async def no_fetcher_test_lifespan(
        app: FastMCP,
    ) -> AsyncGenerator[MainAppContext, None]:
        try:
            yield MainAppContext(
                full_confluence_config=mock_base_confluence_config, read_only=False
            )
        finally:
            pass

    test_mcp = AtlassianMCP(
        name="NoFetcherTestConfluence",
        lifespan=no_fetcher_test_lifespan,
    )

    # Mount the actual confluence MCP instance
    from mcp_atlassian.servers.confluence import confluence_mcp

    test_mcp.mount(confluence_mcp, "confluence")

    return test_mcp


# Removed unused mock_request fixture


# Removed unused DirectToolCaller class


@pytest.fixture
async def client(mock_confluence_fetcher):
    """Create a client that calls the confluence tools directly with mocked dependencies."""
    from fastmcp.server.context import Context

    # Import the actual tool functions
    from src.mcp_atlassian.servers.confluence import (
        add_comment,
        add_label,
        create_page,
        delete_page,
        get_comments,
        get_labels,
        get_page,
        get_page_children,
        get_user_details,
        search,
        search_user,
        update_page,
    )

    # Create a class to wrap the tools
    class ConfluenceToolClient:
        def __init__(self, mock_fetcher):
            self.mock_fetcher = mock_fetcher

        async def call_tool(self, tool_name: str, parameters: dict):
            # Create mock context
            mock_context = MagicMock(spec=Context)
            mock_request = MagicMock(spec=Request)
            mock_request.state = MagicMock()
            mock_context.session = {"request": mock_request}

            # Convert parent_id to string if present (to match BeforeValidator behavior)
            if "parent_id" in parameters and parameters["parent_id"] is not None:
                parameters["parent_id"] = str(parameters["parent_id"])

            # Mock response format
            class MockContent:
                def __init__(self, text):
                    self.text = text
                    self.type = "text"

            class MockResponse:
                def __init__(self, text):
                    self.content = [MockContent(text)]

            # Map tool names to actual function calls
            with patch(
                "src.mcp_atlassian.servers.confluence.get_confluence_fetcher",
                AsyncMock(return_value=self.mock_fetcher),
            ):
                if tool_name == "confluence_search":
                    result = await search.fn(mock_context, **parameters)
                elif tool_name == "confluence_get_page":
                    result = await get_page.fn(mock_context, **parameters)
                elif tool_name == "confluence_get_page_children":
                    result = await get_page_children.fn(mock_context, **parameters)
                elif tool_name == "confluence_create_page":
                    result = await create_page.fn(mock_context, **parameters)
                elif tool_name == "confluence_update_page":
                    result = await update_page.fn(mock_context, **parameters)
                elif tool_name == "confluence_delete_page":
                    result = await delete_page.fn(mock_context, **parameters)
                elif tool_name == "confluence_add_comment":
                    result = await add_comment.fn(mock_context, **parameters)
                elif tool_name == "confluence_get_comments":
                    result = await get_comments.fn(mock_context, **parameters)
                elif tool_name == "confluence_add_label":
                    result = await add_label.fn(mock_context, **parameters)
                elif tool_name == "confluence_get_labels":
                    result = await get_labels.fn(mock_context, **parameters)
                elif tool_name == "confluence_search_user":
                    result = await search_user.fn(mock_context, **parameters)
                elif tool_name == "confluence_get_user_details":
                    result = await get_user_details.fn(mock_context, **parameters)
                else:
                    raise ValueError(f"Unknown tool: {tool_name}")

                return MockResponse(result)

    yield ConfluenceToolClient(mock_confluence_fetcher)


@pytest.fixture
async def no_fetcher_client_fixture(no_fetcher_test_confluence_mcp):
    """Create a client that simulates missing Confluence fetcher configuration."""

    # Create a simple client for testing no-fetcher scenarios
    class NoFetcherClient:
        async def call_tool(self, tool_name: str, parameters: dict):
            raise Exception("No confluence fetcher configured")

    yield NoFetcherClient()


@pytest.mark.anyio
async def test_search(client, mock_confluence_fetcher):
    """Test the search tool with basic query."""
    response = await client.call_tool("confluence_search", {"query": "test search"})

    mock_confluence_fetcher.search.assert_called_once()
    args, kwargs = mock_confluence_fetcher.search.call_args
    assert 'siteSearch ~ "test search"' in args[0]
    assert kwargs.get("limit") == 10
    assert kwargs.get("spaces_filter") is None

    result_data = json.loads(response.content[0].text)
    assert isinstance(result_data, list)
    assert len(result_data) > 0
    assert result_data[0]["title"] == "Test Page Mock Title"


@pytest.mark.anyio
async def test_search_site_search_fallbacks_to_text(client, mock_confluence_fetcher):
    """Ensure siteSearch failure falls back to text search."""
    mock_page = mock_confluence_fetcher.search.return_value[0]
    mock_confluence_fetcher.search.side_effect = [Exception("boom"), [mock_page]]

    response = await client.call_tool(
        "confluence_search", {"query": "incident reports"}
    )

    # Two calls: first siteSearch, second text fallback
    assert mock_confluence_fetcher.search.call_count == 2
    first_query = mock_confluence_fetcher.search.call_args_list[0].args[0]
    second_query = mock_confluence_fetcher.search.call_args_list[1].args[0]
    assert "siteSearch" in first_query
    assert "text" in second_query

    result_data = json.loads(response.content[0].text)
    assert isinstance(result_data, list)
    assert result_data[0]["title"] == "Test Page Mock Title"


@pytest.mark.anyio
async def test_search_cql_query_passthrough(client, mock_confluence_fetcher):
    """Ensure CQL queries skip conversion logic."""
    await client.call_tool(
        "confluence_search", {"query": 'type=page AND space="DOC"', "limit": 5}
    )

    mock_confluence_fetcher.search.assert_called_once()
    called_query = mock_confluence_fetcher.search.call_args.args[0]
    assert called_query == 'type=page AND space="DOC"'


@pytest.mark.anyio
async def test_get_page(client, mock_confluence_fetcher):
    """Test the get_page tool with default parameters."""
    response = await client.call_tool("confluence_get_page", {"page_id": "123456"})

    mock_confluence_fetcher.get_page_content.assert_called_once_with(
        "123456", convert_to_markdown=True, top_n=-1
    )

    result_data = json.loads(response.content[0].text)
    assert "metadata" in result_data
    assert result_data["metadata"]["title"] == "Test Page Mock Title"
    assert "content" in result_data["metadata"]
    assert "value" in result_data["metadata"]["content"]
    assert "This is a test page content" in result_data["metadata"]["content"]["value"]


@pytest.mark.anyio
async def test_get_page_no_metadata(client, mock_confluence_fetcher):
    """Test get_page with metadata disabled."""
    response = await client.call_tool(
        "confluence_get_page", {"page_id": "123456", "include_metadata": False}
    )

    mock_confluence_fetcher.get_page_content.assert_called_once_with(
        "123456", convert_to_markdown=True, top_n=-1
    )

    result_data = json.loads(response.content[0].text)
    assert "metadata" not in result_data
    assert "content" in result_data
    assert "This is a test page content" in result_data["content"]["value"]


@pytest.mark.anyio
async def test_get_page_no_markdown(client, mock_confluence_fetcher):
    """Test get_page with HTML content format."""
    mock_page_html = MagicMock(spec=ConfluencePage)
    mock_page_html.to_simplified_dict.return_value = {
        "id": "123456",
        "title": "Test Page HTML",
        "url": "https://example.com/html",
        "content": "<p>HTML Content</p>",
        "content_format": "storage",
    }
    mock_page_html.content = "<p>HTML Content</p>"
    mock_page_html.content_format = "storage"

    mock_confluence_fetcher.get_page_content.return_value = mock_page_html

    response = await client.call_tool(
        "confluence_get_page", {"page_id": "123456", "convert_to_markdown": False}
    )

    mock_confluence_fetcher.get_page_content.assert_called_once_with(
        "123456", convert_to_markdown=False, top_n=-1
    )

    result_data = json.loads(response.content[0].text)
    assert "metadata" in result_data
    assert result_data["metadata"]["title"] == "Test Page HTML"
    assert result_data["metadata"]["content"] == "<p>HTML Content</p>"
    assert result_data["metadata"]["content_format"] == "storage"


@pytest.mark.anyio
async def test_get_page_with_page_id_and_title(client, mock_confluence_fetcher):
    """Providing page_id together with title should ignore title."""
    await client.call_tool(
        "confluence_get_page",
        {"page_id": "123456", "title": "Ignored", "space_key": "DOC"},
    )

    mock_confluence_fetcher.get_page_content.assert_called_once_with(
        "123456", convert_to_markdown=True, top_n=-1
    )


@pytest.mark.anyio
async def test_get_page_by_title_not_found(client, mock_confluence_fetcher):
    """Return error when page by title is missing."""
    mock_confluence_fetcher.get_page_by_title.return_value = None

    response = await client.call_tool(
        "confluence_get_page", {"title": "Missing", "space_key": "DOC"}
    )

    payload = json.loads(response.content[0].text)
    assert "error" in payload
    assert "Page with title" in payload["error"]


@pytest.mark.anyio
async def test_get_page_requires_identifier(client):
    """Calling get_page without identifiers raises ValueError."""
    with pytest.raises(ValueError):
        await client.call_tool("confluence_get_page", {})


@pytest.mark.anyio
async def test_get_page_not_found_after_fetch(client, mock_confluence_fetcher):
    """Return error when fetcher returns None."""
    mock_confluence_fetcher.get_page_content.return_value = None

    response = await client.call_tool(
        "confluence_get_page", {"page_id": "missing-page"}
    )

    payload = json.loads(response.content[0].text)
    assert payload["error"].startswith("Page not found")


@pytest.mark.anyio
async def test_get_page_with_sample_truncation(client, mock_confluence_fetcher):
    """Sample parameter should trim content."""
    mock_page = MagicMock(spec=ConfluencePage)
    mock_page.content = "line1\nline2\nline3"
    mock_confluence_fetcher.get_page_content.return_value = mock_page

    response = await client.call_tool(
        "confluence_get_page",
        {"page_id": "123456", "include_metadata": False, "sample": 1},
    )
    payload = json.loads(response.content[0].text)
    assert payload["content"]["value"] == "line1"


@pytest.mark.anyio
async def test_get_page_content_error_returns_json(client, mock_confluence_fetcher):
    """Errors from fetcher should be converted to JSON payload."""
    mock_confluence_fetcher.get_page_content.side_effect = Exception("boom")

    response = await client.call_tool("confluence_get_page", {"page_id": "broken"})
    payload = json.loads(response.content[0].text)
    assert payload["error"].startswith("Failed to retrieve page by ID 'broken'")


@pytest.mark.anyio
async def test_get_page_children(client, mock_confluence_fetcher):
    """Test the get_page_children tool."""
    response = await client.call_tool(
        "confluence_get_page_children", {"parent_id": "123456"}
    )

    mock_confluence_fetcher.get_page_children.assert_called_once()
    call_kwargs = mock_confluence_fetcher.get_page_children.call_args.kwargs
    assert call_kwargs["page_id"] == "123456"
    assert call_kwargs.get("start") == 0
    assert call_kwargs.get("limit") == 25
    assert call_kwargs.get("expand") == "version"

    result_data = json.loads(response.content[0].text)
    assert "parent_id" in result_data
    assert "results" in result_data
    assert len(result_data["results"]) > 0
    assert result_data["results"][0]["title"] == "Test Page Mock Title"


@pytest.mark.anyio
async def test_get_page_children_include_content(client, mock_confluence_fetcher):
    """include_content should inject body.storage expansion."""
    await client.call_tool(
        "confluence_get_page_children",
        {"parent_id": "123456", "include_content": True, "expand": "version"},
    )
    expand_arg = mock_confluence_fetcher.get_page_children.call_args.kwargs["expand"]
    assert "body.storage" in expand_arg


@pytest.mark.anyio
async def test_get_page_children_handles_exception(client, mock_confluence_fetcher):
    """Errors should be surfaced in response."""
    mock_confluence_fetcher.get_page_children.side_effect = Exception("failure")

    response = await client.call_tool(
        "confluence_get_page_children", {"parent_id": "123456"}
    )
    payload = json.loads(response.content[0].text)
    assert payload["error"].startswith("Failed to get child pages")


@pytest.mark.anyio
async def test_get_comments(client, mock_confluence_fetcher):
    """Test retrieving page comments."""
    response = await client.call_tool("confluence_get_comments", {"page_id": "123456"})

    mock_confluence_fetcher.get_page_comments.assert_called_once_with("123456")

    result_data = json.loads(response.content[0].text)
    assert isinstance(result_data, list)
    assert len(result_data) > 0
    assert result_data[0]["author"] == "Test User"


@pytest.mark.anyio
async def test_add_comment(client, mock_confluence_fetcher):
    """Test adding a comment to a Confluence page."""
    response = await client.call_tool(
        "confluence_add_comment",
        {"page_id": "123456", "content": "Test comment content"},
    )

    mock_confluence_fetcher.add_comment.assert_called_once_with(
        page_id="123456", content="Test comment content"
    )

    result_data = json.loads(response.content[0].text)
    assert isinstance(result_data, dict)
    assert result_data["success"] is True
    assert "comment" in result_data
    assert result_data["comment"]["id"] == "987"
    assert result_data["comment"]["author"] == "Test User"
    assert result_data["comment"]["body"] == "This is a test comment added via API"
    assert result_data["comment"]["created"] == "2023-08-01T13:00:00.000Z"


@pytest.mark.anyio
async def test_get_labels(client, mock_confluence_fetcher):
    """Test retrieving page labels."""
    response = await client.call_tool("confluence_get_labels", {"page_id": "123456"})
    mock_confluence_fetcher.get_page_labels.assert_called_once_with("123456")
    result_data = json.loads(response.content[0].text)
    assert isinstance(result_data, list)
    assert result_data[0]["name"] == "test-label"


@pytest.mark.anyio
async def test_add_label(client, mock_confluence_fetcher):
    """Test adding a label to a page."""
    response = await client.call_tool(
        "confluence_add_label", {"page_id": "123456", "name": "new-label"}
    )
    mock_confluence_fetcher.add_page_label.assert_called_once_with(
        "123456", "new-label"
    )
    result_data = json.loads(response.content[0].text)
    assert isinstance(result_data, list)
    assert result_data[0]["name"] == "test-label"


@pytest.mark.anyio
async def test_add_label_read_only_enforced(client, mock_confluence_fetcher):
    """Ensure add_label still works when allowed (already covered)."""
    # This test intentionally left simple to keep fixture warm.
    response = await client.call_tool(
        "confluence_add_label", {"page_id": "123456", "name": "another"}
    )
    payload = json.loads(response.content[0].text)
    assert isinstance(payload, list)


@pytest.mark.anyio
async def test_search_user(client, mock_confluence_fetcher):
    """Test the search_user tool with CQL query."""
    response = await client.call_tool(
        "confluence_search_user", {"query": 'user.fullname ~ "First Last"', "limit": 10}
    )

    mock_confluence_fetcher.search_user.assert_called_once_with(
        'user.fullname ~ "First Last"', limit=10
    )

    result_data = json.loads(response.content[0].text)
    assert isinstance(result_data, list)
    assert len(result_data) == 1
    assert result_data[0]["entity_type"] == "user"
    assert result_data[0]["title"] == "First Last"
    assert result_data[0]["user"]["account_id"] == "a031248587011jasoidf9832jd8j1"
    assert result_data[0]["user"]["display_name"] == "First Last"


@pytest.mark.anyio
async def test_search_user_simple_term_conversion(client, mock_confluence_fetcher):
    """Simple user names should be converted to fullname search."""
    await client.call_tool(
        "confluence_search_user", {"query": "First Last", "limit": 5}
    )
    mock_confluence_fetcher.search_user.assert_called_once_with(
        'user.fullname ~ "First Last"', limit=5
    )


@pytest.mark.anyio
async def test_search_user_auth_error(client, mock_confluence_fetcher):
    """Authentication errors should be handled gracefully."""
    mock_confluence_fetcher.search_user.side_effect = MCPAtlassianAuthenticationError(
        "bad auth"
    )

    response = await client.call_tool(
        "confluence_search_user", {"query": "First Last", "limit": 2}
    )
    payload = json.loads(response.content[0].text)
    assert payload["error"].startswith("Authentication failed")


@pytest.mark.anyio
async def test_search_user_generic_error(client, mock_confluence_fetcher):
    """Unexpected exceptions should produce generic error message."""
    mock_confluence_fetcher.search_user.side_effect = Exception("network down")

    response = await client.call_tool(
        "confluence_search_user", {"query": 'user.fullname ~ "Test"', "limit": 2}
    )
    payload = json.loads(response.content[0].text)
    assert payload["error"].startswith("An unexpected error occurred")


@pytest.mark.anyio
async def test_create_page_with_numeric_parent_id(client, mock_confluence_fetcher):
    """Test creating a page with numeric parent_id (integer) - should convert to string."""
    response = await client.call_tool(
        "confluence_create_page",
        {
            "space_key": "TEST",
            "title": "Test Page",
            "content": "Test content",
            "parent_id": 123456789,  # Numeric ID as integer
        },
    )

    # Verify the parent_id was converted to string when calling the underlying method
    mock_confluence_fetcher.create_page.assert_called_once()
    call_kwargs = mock_confluence_fetcher.create_page.call_args.kwargs
    assert call_kwargs["parent_id"] == "123456789"  # Should be string
    assert call_kwargs["space_key"] == "TEST"
    assert call_kwargs["title"] == "Test Page"

    result_data = json.loads(response.content[0].text)
    assert result_data["message"] == "Page created successfully"
    assert result_data["page"]["title"] == "Test Page Mock Title"


@pytest.mark.anyio
async def test_create_page_with_string_parent_id(client, mock_confluence_fetcher):
    """Test creating a page with string parent_id - should remain unchanged."""
    response = await client.call_tool(
        "confluence_create_page",
        {
            "space_key": "TEST",
            "title": "Test Page",
            "content": "Test content",
            "parent_id": "123456789",  # String ID
        },
    )

    mock_confluence_fetcher.create_page.assert_called_once()
    call_kwargs = mock_confluence_fetcher.create_page.call_args.kwargs
    assert call_kwargs["parent_id"] == "123456789"  # Should remain string
    assert call_kwargs["space_key"] == "TEST"
    assert call_kwargs["title"] == "Test Page"

    result_data = json.loads(response.content[0].text)
    assert result_data["message"] == "Page created successfully"
    assert result_data["page"]["title"] == "Test Page Mock Title"


@pytest.mark.anyio
async def test_create_page_invalid_content_format(client):
    """Invalid content_format should raise ValueError."""
    with pytest.raises(ValueError):
        await client.call_tool(
            "confluence_create_page",
            {
                "space_key": "TEST",
                "title": "Invalid Format",
                "content": "text",
                "content_format": "pdf",
            },
        )


@pytest.mark.anyio
async def test_create_page_wiki_format(client, mock_confluence_fetcher):
    """Non-markdown formats should set content_representation."""
    await client.call_tool(
        "confluence_create_page",
        {
            "space_key": "TEST",
            "title": "Wiki Page",
            "content": "h1. Title",
            "content_format": "wiki",
        },
    )
    call_kwargs = mock_confluence_fetcher.create_page.call_args.kwargs
    assert call_kwargs["is_markdown"] is False
    assert call_kwargs["content_representation"] == "wiki"


@pytest.mark.anyio
async def test_update_page_with_numeric_parent_id(client, mock_confluence_fetcher):
    """Test updating a page with numeric parent_id (integer) - should convert to string."""
    response = await client.call_tool(
        "confluence_update_page",
        {
            "page_id": "999999",
            "title": "Updated Page",
            "content": "Updated content",
            "parent_id": 123456789,  # Numeric ID as integer
        },
    )

    mock_confluence_fetcher.update_page.assert_called_once()
    call_kwargs = mock_confluence_fetcher.update_page.call_args.kwargs
    assert call_kwargs["parent_id"] == "123456789"  # Should be string
    assert call_kwargs["page_id"] == "999999"
    assert call_kwargs["title"] == "Updated Page"

    result_data = json.loads(response.content[0].text)
    assert result_data["message"] == "Page updated successfully"
    assert result_data["page"]["title"] == "Test Page Mock Title"


@pytest.mark.anyio
async def test_get_user_details_by_userkey(client, mock_confluence_fetcher):
    """Test the confluence_get_user_details tool with userkey."""
    mock_user_details = {"displayName": "Test User", "userKey": "testuser-key-12345"}
    mock_confluence_fetcher.get_user_details.return_value = (
        ConfluenceUser.from_api_response(mock_user_details)
    )

    response = await client.call_tool(
        "confluence_get_user_details",
        {"identifier": "testuser-key-12345", "identifier_type": "userKey"},
    )

    result_data = json.loads(response.content[0].text)
    assert result_data["display_name"] == "Test User"


@pytest.mark.anyio
async def test_get_user_details_invalid_userkey(client, mock_confluence_fetcher):
    """Test the get_user_details tool with an invalid userkey."""
    mock_confluence_fetcher.get_user_details.return_value = None

    response = await client.call_tool(
        "confluence_get_user_details",
        {"identifier": "invalid-userkey", "identifier_type": "userKey"},
    )

    result_data = json.loads(response.content[0].text)
    assert result_data["success"] is False
    assert "User not found" in result_data["message"]


@pytest.mark.anyio
async def test_get_user_details_by_account_id(client, mock_confluence_fetcher):
    """Test the confluence_get_user_details tool with accountId."""
    mock_user_details = {"displayName": "Test User", "accountId": "12345"}
    mock_confluence_fetcher.get_user_details.return_value = (
        ConfluenceUser.from_api_response(mock_user_details)
    )

    response = await client.call_tool(
        "confluence_get_user_details",
        {"identifier": "12345", "identifier_type": "accountId"},
    )

    result_data = json.loads(response.content[0].text)
    assert result_data["display_name"] == "Test User"


@pytest.mark.anyio
async def test_get_user_details_by_username(client, mock_confluence_fetcher):
    """Test the confluence_get_user_details tool with username."""
    mock_user_details = {"displayName": "Test User", "name": "testuser"}
    mock_confluence_fetcher.get_user_details.return_value = (
        ConfluenceUser.from_api_response(mock_user_details)
    )

    response = await client.call_tool(
        "confluence_get_user_details",
        {"identifier": "testuser", "identifier_type": "username"},
    )

    result_data = json.loads(response.content[0].text)
    assert result_data["display_name"] == "Test User"


@pytest.mark.anyio
async def test_update_page_with_string_parent_id(client, mock_confluence_fetcher):
    """Test updating a page with string parent_id - should remain unchanged."""
    response = await client.call_tool(
        "confluence_update_page",
        {
            "page_id": "999999",
            "title": "Updated Page",
            "content": "Updated content",
            "parent_id": "123456789",  # String ID
        },
    )

    mock_confluence_fetcher.update_page.assert_called_once()
    call_kwargs = mock_confluence_fetcher.update_page.call_args.kwargs
    assert call_kwargs["parent_id"] == "123456789"  # Should remain string
    assert call_kwargs["page_id"] == "999999"
    assert call_kwargs["title"] == "Updated Page"

    result_data = json.loads(response.content[0].text)
    assert result_data["message"] == "Page updated successfully"
    assert result_data["page"]["title"] == "Test Page Mock Title"
