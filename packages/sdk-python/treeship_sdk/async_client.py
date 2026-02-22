"""
Treeship async client — async interface for attestation.
"""
from __future__ import annotations

import hashlib
import json
import os
from typing import Any, Dict, Optional

import httpx

from .client import AttestResult, _get_api_url


class AsyncTreeship:
    """
    Async Treeship client for creating cryptographic attestations.
    
    Example:
        >>> from treeship_sdk import AsyncTreeship
        >>> async with AsyncTreeship() as ts:
        ...     result = await ts.attest(
        ...         action="Async task completed",
        ...         inputs_hash=ts.hash({"task_id": "t-789"})
        ...     )
        ...     print(result.url)
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        agent: Optional[str] = None,
        api_url: Optional[str] = None,
    ):
        """
        Initialize the async Treeship client.
        
        Args:
            api_key: API key for authentication. Defaults to TREESHIP_API_KEY env var.
            agent: Default agent slug. Defaults to TREESHIP_AGENT env var.
            api_url: API base URL. Defaults to TREESHIP_API_URL env var or https://api.treeship.dev.
        """
        self.api_key = api_key or os.environ.get("TREESHIP_API_KEY", "")
        self.agent = agent or os.getenv("TREESHIP_AGENT", "")
        self._api_url = api_url or _get_api_url()
        self._client = httpx.AsyncClient(
            base_url=self._api_url,
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "User-Agent": "treeship-sdk/0.2.0",
            },
            timeout=30.0,
        )

    @staticmethod
    def hash(data: Any) -> str:
        """Create a SHA256 hash of data for use as inputs_hash."""
        if isinstance(data, (dict, list)):
            data = json.dumps(data, sort_keys=True, separators=(",", ":"))
        if isinstance(data, str):
            data = data.encode()
        return hashlib.sha256(data).hexdigest()

    async def attest(
        self,
        action: str,
        inputs_hash: Optional[str] = None,
        agent: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AttestResult:
        """
        Create a cryptographic attestation asynchronously.
        
        Args:
            action: Human-readable description of the action.
            inputs_hash: SHA256 hash of inputs. If not provided, hashes the action string.
            agent: Agent slug. Uses default agent if not provided.
            metadata: Optional key-value metadata.
            
        Returns:
            AttestResult with attestation details and verification URL.
        """
        slug = agent or self.agent
        if not slug:
            raise ValueError(
                "Agent slug required: pass agent= or set TREESHIP_AGENT environment variable"
            )

        if not self.api_key:
            raise ValueError(
                "API key required: pass api_key= or set TREESHIP_API_KEY environment variable"
            )

        response = await self._client.post(
            "/v1/attest",
            json={
                "agent_slug": slug,
                "action": action,
                "inputs_hash": inputs_hash or self.hash(action),
                "metadata": metadata or {},
            },
        )
        response.raise_for_status()
        return AttestResult.from_dict(response.json())

    async def verify(self, attestation_id: str) -> Dict[str, Any]:
        """Verify an attestation by ID."""
        response = await self._client.get(f"/v1/verify/{attestation_id}")
        response.raise_for_status()
        return response.json()

    async def get_agent(self, slug: Optional[str] = None) -> Dict[str, Any]:
        """Get agent feed with recent attestations."""
        agent_slug = slug or self.agent
        if not agent_slug:
            raise ValueError("Agent slug required")
        response = await self._client.get(f"/v1/agent/{agent_slug}")
        response.raise_for_status()
        return response.json()

    async def get_pubkey(self) -> Dict[str, Any]:
        """Get the public signing key for independent verification."""
        response = await self._client.get("/v1/pubkey")
        response.raise_for_status()
        return response.json()

    async def close(self) -> None:
        """Close the HTTP client."""
        await self._client.aclose()

    async def __aenter__(self) -> AsyncTreeship:
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.close()
