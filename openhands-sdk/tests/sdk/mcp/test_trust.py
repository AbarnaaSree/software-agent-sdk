import httpx
import pytest

from openhands.sdk.mcp.config import MCPServer
from openhands.sdk.mcp.trust import (
    HTTPTrustVerifier,
    TrustVerificationResult,
)


def test_permit_result_is_permitted() -> None:
    result = TrustVerificationResult(
        decision="PERMIT",
        detected_format="trust-card",
        issuer="example-issuer",
    )

    assert result.permitted is True


def test_deny_result_is_not_permitted() -> None:
    result = TrustVerificationResult(
        decision="DENY",
        detected_format="trust-card",
        issuer="example-issuer",
    )

    assert result.permitted is False


def test_decision_is_case_insensitive() -> None:
    result = TrustVerificationResult(decision="permit")

    assert result.permitted is True


@pytest.mark.asyncio
async def test_http_verifier_parses_permit_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class MockAsyncClient:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

        async def post(self, url, json):
            assert json == {"payload": "test-credential"}

            return httpx.Response(
                200,
                request=httpx.Request("POST", url),
                json={
                    "decision": "PERMIT",
                    "detected_format": "trust-card",
                    "issuer": "example-issuer",
                },
            )

    monkeypatch.setattr(
        "openhands.sdk.mcp.trust.httpx.AsyncClient",
        MockAsyncClient,
    )

    verifier = HTTPTrustVerifier(endpoint="https://example.com/verify")

    result = await verifier.verify("test-credential")

    assert result.decision == "PERMIT"
    assert result.detected_format == "trust-card"
    assert result.issuer == "example-issuer"
    assert result.permitted is True


def test_mcp_server_accepts_trust_credential() -> None:
    server = MCPServer(
        url="https://example.com/mcp",
        transport="streamable-http",
        trust_credential="test-trust-card",
    )

    assert server.trust_credential == "test-trust-card"


def test_mcp_server_accepts_custom_trust_verifier_endpoint() -> None:
    server = MCPServer(
        url="https://example.com/mcp",
        trust_verification=True,
        trust_credential="test-trust-card",
        trust_verifier_endpoint="https://custom.example.com/verify",
    )

    assert server.trust_verifier_endpoint == "https://custom.example.com/verify"
