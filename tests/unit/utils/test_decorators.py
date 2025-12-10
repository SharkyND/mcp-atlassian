from unittest.mock import MagicMock

import pytest

from mcp_atlassian.utils.decorators import check_write_access


class DummyContext:
    def __init__(
        self,
        read_only: bool,
        cli_read_only: bool | None = None,
        env_read_only: bool | None = None,
        header: str | None = None,
    ):
        cli_value = read_only if cli_read_only is None else cli_read_only
        self.request_context = MagicMock()
        self.request_context.lifespan_context = {
            "app_lifespan_context": MagicMock(
                read_only=read_only,
                cli_read_only=cli_value,
                env_read_only=env_read_only,
            )
        }
        self.request_context.request = MagicMock()
        self.request_context.request.state = MagicMock()
        self.request_context.request.state.read_only_mode_header = header


@pytest.mark.asyncio
async def test_check_write_access_blocks_in_read_only():
    @check_write_access
    async def dummy_tool(ctx, x):
        return x * 2

    ctx = DummyContext(read_only=True)
    with pytest.raises(ValueError) as exc:
        await dummy_tool(ctx, 3)
    assert "read-only mode" in str(exc.value)


@pytest.mark.asyncio
async def test_check_write_access_allows_in_writable():
    @check_write_access
    async def dummy_tool(ctx, x):
        return x * 2

    ctx = DummyContext(read_only=False)
    result = await dummy_tool(ctx, 4)
    assert result == 8


@pytest.mark.asyncio
async def test_check_write_access_header_true_blocks():
    @check_write_access
    async def dummy_tool(ctx, x):
        return x * 2

    ctx = DummyContext(read_only=False, cli_read_only=False, header="true")
    with pytest.raises(ValueError):
        await dummy_tool(ctx, 4)


@pytest.mark.asyncio
async def test_check_write_access_header_false_allows_write():
    @check_write_access
    async def dummy_tool(ctx, x):
        return x * 2

    ctx = DummyContext(read_only=True, cli_read_only=True, header="false")
    result = await dummy_tool(ctx, 6)
    assert result == 12
