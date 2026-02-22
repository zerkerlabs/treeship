"""
Treeship client — sync interface for attestation.

Matches the published treeship-sdk 0.1.0 API with additions for v0.2.0.

Privacy contract:
- Inputs are hashed locally using SHA-256
- Only action + hash are sent to Treeship
- Raw content never leaves your server
"""
from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from typing import Any, Dict, Optional

import httpx


def _get_api_url() -> str:
    return os.getenv("TREESHIP_API_URL", "https://api.treeship.dev")


@dataclass
class AttestResult:
    """Result of creating an attestation."""
    
    attestation_id: str
    signature: str
    payload_hash: str
    key_id: str
    timestamp: str
    url: str
    verify_command: str
    agent_slug: str
    action: str
    inputs_hash: str

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> AttestResult:
        return cls(
            attestation_id=d["attestation_id"],
            signature=d["signature"],
            payload_hash=d["payload_hash"],
            key_id=d["key_id"],
            timestamp=d["timestamp"],
            url=d["public_url"],
            verify_command=d["verify_command"],
            agent_slug=d["agent_slug"],
            action=d["action"],
            inputs_hash=d["inputs_hash"],
        )


class Treeship:
    """
    Treeship client for creating cryptographic attestations.
    
    Example:
        >>> from treeship_sdk import Treeship
        >>> ts = Treeship()
        >>> result = ts.attest(
        ...     action="Approved loan application #12345",
        ...     inputs_hash=ts.hash({"customer_id": "cust_123"})
        ... )
        >>> print(result.url)
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        agent: Optional[str] = None,
        api_url: Optional[str] = None,
    ):
        """
        Initialize the Treeship client.
        
        Args:
            api_key: API key for authentication. Defaults to TREESHIP_API_KEY env var.
            agent: Default agent slug. Defaults to TREESHIP_AGENT env var.
            api_url: API base URL. Defaults to TREESHIP_API_URL env var or https://api.treeship.dev.
        """
        self.api_key = api_key or os.environ.get("TREESHIP_API_KEY", "")
        self.agent = agent or os.getenv("TREESHIP_AGENT", "")
        self._api_url = api_url or _get_api_url()
        self._client = httpx.Client(
            base_url=self._api_url,
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "User-Agent": "treeship-sdk/0.2.0",
            },
            timeout=30.0,
        )

    @staticmethod
    def hash(data: Any) -> str:
        """
        Create a SHA256 hash of data for use as inputs_hash.
        
        Args:
            data: Any JSON-serializable data, string, or bytes.
            
        Returns:
            Hex-encoded SHA256 hash.
        """
        if isinstance(data, (dict, list)):
            data = json.dumps(data, sort_keys=True, separators=(",", ":"))
        if isinstance(data, str):
            data = data.encode()
        return hashlib.sha256(data).hexdigest()

    def attest(
        self,
        action: str,
        inputs_hash: Optional[str] = None,
        agent: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AttestResult:
        """
        Create a cryptographic attestation.
        
        Args:
            action: Human-readable description of the action.
            inputs_hash: SHA256 hash of inputs. If not provided, hashes the action string.
            agent: Agent slug. Uses default agent if not provided.
            metadata: Optional key-value metadata.
            
        Returns:
            AttestResult with attestation details and verification URL.
            
        Raises:
            ValueError: If no agent slug is available.
            httpx.HTTPStatusError: If the API request fails.
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

        response = self._client.post(
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

    def verify(self, attestation_id: str) -> Dict[str, Any]:
        """
        Verify an attestation by ID.
        
        Args:
            attestation_id: The attestation UUID.
            
        Returns:
            Dict with verification result including 'valid' boolean.
            
        Raises:
            httpx.HTTPStatusError: If the attestation is not found or request fails.
        """
        response = self._client.get(f"/v1/verify/{attestation_id}")
        response.raise_for_status()
        return response.json()

    def get_agent(self, slug: Optional[str] = None) -> Dict[str, Any]:
        """
        Get agent feed with recent attestations.
        
        Args:
            slug: Agent slug. Uses default agent if not provided.
            
        Returns:
            Dict with agent info and attestations list.
        """
        agent_slug = slug or self.agent
        if not agent_slug:
            raise ValueError("Agent slug required")
        response = self._client.get(f"/v1/agent/{agent_slug}")
        response.raise_for_status()
        return response.json()

    def get_pubkey(self) -> Dict[str, Any]:
        """
        Get the public signing key for independent verification.
        
        Returns:
            Dict with key_id, algorithm, and public_key_pem.
        """
        response = self._client.get("/v1/pubkey")
        response.raise_for_status()
        return response.json()

    def close(self) -> None:
        """Close the HTTP client."""
        self._client.close()

    def __enter__(self) -> Treeship:
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()


# Backwards compatibility alias
TreshipClient = Treeship
