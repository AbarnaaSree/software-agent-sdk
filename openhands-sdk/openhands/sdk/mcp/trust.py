"""Trust verification for MCP tools."""

from dataclasses import dataclass
from typing import Protocol

import httpx


DEFAULT_TRUST_VERIFIER_ENDPOINT = "https://www.marketnow.site/api/trust?action=verify"


@dataclass(frozen=True)
class TrustVerificationResult:
    """Result returned by a trust verifier."""

    decision: str
    detected_format: str | None = None
    issuer: str | None = None

    @property
    def permitted(self) -> bool:
        """Whether the credential is explicitly trusted."""
        return self.decision.upper() == "PERMIT"


class TrustVerifier(Protocol):
    """Interface for MCP trust verification."""

    async def verify(self, credential: str) -> TrustVerificationResult:
        """Verify an MCP server trust credential."""
        ...


class HTTPTrustVerifier:
    """Verify trust credentials using the UTA HTTP API."""

    def __init__(
        self,
        endpoint: str = DEFAULT_TRUST_VERIFIER_ENDPOINT,
        timeout: float = 10.0,
    ) -> None:
        self.endpoint = endpoint
        self.timeout = timeout

    async def verify(self, credential: str) -> TrustVerificationResult:
        """Verify a credential using the configured HTTP endpoint."""
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.post(
                self.endpoint,
                json={"payload": credential},
            )
            response.raise_for_status()

            data = response.json()

        decision = str(data.get("decision", "ERROR")).upper()

        return TrustVerificationResult(
            decision=decision,
            detected_format=data.get("detected_format"),
            issuer=data.get("issuer"),
        )
