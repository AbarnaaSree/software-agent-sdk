from unittest.mock import AsyncMock, MagicMock

import mcp.types
import pytest

from openhands.sdk.mcp.config import MCPServer
from openhands.sdk.mcp.definition import MCPToolAction
from openhands.sdk.mcp.exceptions import ToolTrustError
from openhands.sdk.mcp.tool import (
    MCPToolDefinition,
    MCPToolExecutor,
    _get_mcp_server_config,
)
from openhands.sdk.mcp.trust import TrustVerificationResult


class FakeTrustVerifier:
    """Test verifier with a configurable result."""

    def __init__(self, decision: str = "PERMIT") -> None:
        self.verify = AsyncMock(return_value=TrustVerificationResult(decision=decision))


@pytest.fixture
def client() -> MagicMock:
    """Create a mock MCP client."""
    client = MagicMock()
    client.is_connected.return_value = True
    client.call_tool_mcp = AsyncMock(
        return_value=mcp.types.CallToolResult(
            content=[
                mcp.types.TextContent(
                    type="text",
                    text="success",
                )
            ],
            isError=False,
        )
    )
    return client


@pytest.mark.asyncio
async def test_trust_verification_disabled_allows_tool_call(
    client: MagicMock,
) -> None:
    """Tool execution is unchanged when trust verification is disabled."""
    verifier = FakeTrustVerifier("DENY")

    executor = MCPToolExecutor(
        tool_name="test_tool",
        client=client,
        trust_verifier=verifier,
        trust_credential="test-credential",
        trust_verification=False,
    )

    result = await executor.call_tool(MCPToolAction(data={"value": "test"}))

    assert result.is_error is False
    verifier.verify.assert_not_awaited()
    client.call_tool_mcp.assert_awaited_once()


@pytest.mark.asyncio
async def test_permit_allows_tool_call(
    client: MagicMock,
) -> None:
    """A PERMIT decision allows the MCP tool to execute."""
    verifier = FakeTrustVerifier("PERMIT")

    executor = MCPToolExecutor(
        tool_name="test_tool",
        client=client,
        trust_verifier=verifier,
        trust_credential="test-credential",
        trust_verification=True,
    )

    result = await executor.call_tool(MCPToolAction(data={"value": "test"}))

    assert result.is_error is False
    verifier.verify.assert_awaited_once_with("test-credential")
    client.call_tool_mcp.assert_awaited_once()


@pytest.mark.asyncio
async def test_deny_blocks_tool_call(
    client: MagicMock,
) -> None:
    """A DENY decision prevents the MCP tool from executing."""
    verifier = FakeTrustVerifier("DENY")

    executor = MCPToolExecutor(
        tool_name="test_tool",
        client=client,
        trust_verifier=verifier,
        trust_credential="test-credential",
        trust_verification=True,
    )

    with pytest.raises(ToolTrustError, match="denied"):
        await executor.call_tool(MCPToolAction(data={"value": "test"}))

    verifier.verify.assert_awaited_once_with("test-credential")
    client.call_tool_mcp.assert_not_awaited()


@pytest.mark.asyncio
async def test_verification_failure_blocks_tool_call(
    client: MagicMock,
) -> None:
    """A verifier failure prevents the MCP tool from executing."""
    verifier = FakeTrustVerifier()
    verifier.verify.side_effect = RuntimeError("verification service unavailable")

    executor = MCPToolExecutor(
        tool_name="test_tool",
        client=client,
        trust_verifier=verifier,
        trust_credential="test-credential",
        trust_verification=True,
    )

    with pytest.raises(
        ToolTrustError,
        match="Trust verification failed",
    ):
        await executor.call_tool(MCPToolAction(data={"value": "test"}))

    verifier.verify.assert_awaited_once_with("test-credential")
    client.call_tool_mcp.assert_not_awaited()


@pytest.mark.asyncio
async def test_missing_credential_blocks_tool_call(
    client: MagicMock,
) -> None:
    """Missing credentials prevent verification and tool execution."""
    verifier = FakeTrustVerifier("PERMIT")

    executor = MCPToolExecutor(
        tool_name="test_tool",
        client=client,
        trust_verifier=verifier,
        trust_credential=None,
        trust_verification=True,
    )

    with pytest.raises(
        ToolTrustError,
        match="no trust credential",
    ):
        await executor.call_tool(MCPToolAction(data={"value": "test"}))

    verifier.verify.assert_not_awaited()
    client.call_tool_mcp.assert_not_awaited()


@pytest.mark.asyncio
async def test_missing_verifier_blocks_when_verification_enabled(
    client: MagicMock,
) -> None:
    """Missing verifier prevents execution when verification is enabled."""
    executor = MCPToolExecutor(
        tool_name="test_tool",
        client=client,
        trust_verifier=None,
        trust_credential="test-credential",
        trust_verification=True,
    )

    with pytest.raises(
        ToolTrustError,
        match="no trust verifier",
    ):
        await executor.call_tool(MCPToolAction(data={"value": "test"}))

    client.call_tool_mcp.assert_not_awaited()


def test_single_mcp_server_config_is_used_for_unprefixed_tool() -> None:
    server_config = MCPServer(
        url="http://localhost:8000",
        trust_verification=True,
        trust_credential="test-credential",
    )

    result = _get_mcp_server_config(
        "search",
        {"github": server_config},
    )

    assert result is server_config


def test_mcp_tool_definition_wires_trust_verifier() -> None:
    """MCP tool definitions inherit trust verification from their server."""
    server_config = MCPServer(
        url="http://localhost:8000",
        trust_verification=True,
        trust_credential="test-credential",
    )

    client = MagicMock()
    client._server_configs = {"github": server_config}

    mcp_tool = mcp.types.Tool(
        name="search",
        description="Search GitHub",
        inputSchema={
            "type": "object",
            "properties": {},
        },
    )

    definitions = MCPToolDefinition.create(
        mcp_tool,
        client,
    )

    assert len(definitions) == 1

    executor = definitions[0].executor
    assert isinstance(executor, MCPToolExecutor)
    assert executor.trust_verification is True
    assert executor.trust_credential == "test-credential"
