"""
Treeship client — sync and async interfaces for attestation.

Privacy contract:
- Inputs are hashed locally using SHA-256
- Only action + hash are sent to Treeship
- Raw content never leaves your server

Reliability contract:
- All methods have reasonable timeouts
- Failures return result objects with attested=False
- NEVER raises exceptions for attestation failures
"""
import hashlib
import json
import os
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Optional

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


@dataclass
class AttestResult:
    """Result of an attestation request."""
    attested: bool
    id: Optional[str] = None
    url: Optional[str] = None
    timestamp: Optional[datetime] = None
    signature: Optional[str] = None
    error: Optional[str] = None


@dataclass
class VerifyResult:
    """Result of a verification request."""
    valid: bool
    signature_valid: bool = False
    key_matches: bool = False
    attestation: Optional[dict] = None
    error: Optional[str] = None


class TreshipClient:
    """
    Treeship client for creating and verifying attestations.
    
    Args:
        api_key: API key (default: TREESHIP_API_KEY env var)
        api_url: API URL (default: https://api.treeship.dev)
        agent: Default agent slug (default: TREESHIP_AGENT env var)
        timeout: Request timeout in seconds (default: 10)
        hash_only: If True, only send hashes (default: True)
    
    Example:
        client = TreshipClient()
        result = client.attest(
            action="Document processed",
            inputs={"doc_id": "123", "content": "sensitive data"}
        )
        print(result.url)  # https://treeship.dev/verify/ts_abc123
    """
    
    def __init__(
        self,
        api_key: Optional[str] = None,
        api_url: Optional[str] = None,
        agent: Optional[str] = None,
        timeout: float = 10.0,
        hash_only: bool = True,
    ):
        self.api_key = api_key or os.getenv("TREESHIP_API_KEY", "")
        self.api_url = (api_url or os.getenv("TREESHIP_API_URL", "https://api.treeship.dev")).rstrip("/")
        self.agent = agent or os.getenv("TREESHIP_AGENT", "python-agent")
        self.timeout = timeout
        self.hash_only = hash_only
        
        self._client = httpx.Client(
            timeout=self.timeout,
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
                "User-Agent": "treeship-sdk-python/1.0.0",
            },
        )
        
        self._async_client: Optional[httpx.AsyncClient] = None
    
    def _hash_inputs(self, inputs: Optional[dict]) -> str:
        """Hash inputs using SHA-256. Content never leaves this function."""
        if inputs is None:
            inputs = {}
        canonical = json.dumps(inputs, sort_keys=True, separators=(",", ":"), default=str)
        return hashlib.sha256(canonical.encode()).hexdigest()
    
    def attest(
        self,
        action: str,
        inputs: Optional[dict] = None,
        agent: Optional[str] = None,
        metadata: Optional[dict] = None,
    ) -> AttestResult:
        """
        Create a new attestation.
        
        Args:
            action: Human-readable description of the action (max 500 chars)
            inputs: Optional dict of inputs (hashed locally, never sent)
            agent: Agent slug (default: client default)
            metadata: Optional additional metadata
        
        Returns:
            AttestResult with verification URL on success
        
        Note:
            This method NEVER raises. Check result.attested for success.
        """
        try:
            inputs_hash = self._hash_inputs(inputs)
            
            payload = {
                "agent_slug": agent or self.agent,
                "action": action[:500],
                "inputs_hash": inputs_hash,
            }
            if metadata:
                payload["metadata"] = metadata
            
            response = self._client.post(f"{self.api_url}/v1/attest", json=payload)
            
            if response.status_code == 201:
                data = response.json()
                return AttestResult(
                    attested=True,
                    id=data.get("attestation_id"),
                    url=data.get("public_url"),
                    timestamp=datetime.fromisoformat(data["timestamp"].replace("Z", "+00:00")) if data.get("timestamp") else None,
                    signature=data.get("signature"),
                )
            else:
                return AttestResult(attested=False, error=f"API error: {response.status_code}")
                
        except httpx.TimeoutException:
            return AttestResult(attested=False, error="Timeout")
        except Exception as e:
            return AttestResult(attested=False, error=str(e)[:100])
    
    def verify(self, attestation_id: str) -> VerifyResult:
        """
        Verify an attestation.
        
        Args:
            attestation_id: The attestation ID (e.g., "ts_abc123")
        
        Returns:
            VerifyResult with verification details
        """
        try:
            # Fetch attestation
            response = self._client.get(f"{self.api_url}/v1/verify/{attestation_id}")
            if response.status_code != 200:
                return VerifyResult(valid=False, error=f"Not found: {attestation_id}")
            
            data = response.json()
            attestation = data.get("attestation", data)
            
            # Fetch public key
            pubkey_response = self._client.get(f"{self.api_url}/v1/pubkey")
            pubkey_data = pubkey_response.json()
            expected_key = pubkey_data.get("public_key")
            
            # Verify signature locally
            signature_valid, key_matches = self._verify_signature(attestation, expected_key)
            
            return VerifyResult(
                valid=signature_valid and key_matches,
                signature_valid=signature_valid,
                key_matches=key_matches,
                attestation=attestation,
            )
            
        except Exception as e:
            return VerifyResult(valid=False, error=str(e)[:100])
    
    def _verify_signature(self, attestation: dict, expected_key: Optional[str]) -> tuple[bool, bool]:
        """Verify Ed25519 signature locally."""
        try:
            import base64
            
            # Reconstruct canonical payload
            canonical = json.dumps({
                "action": attestation["action"],
                "agent": attestation.get("agent_slug") or attestation.get("agent"),
                "id": attestation["id"],
                "inputs_hash": attestation["inputs_hash"],
                "timestamp": attestation["timestamp"],
                "version": "1.0",
            }, separators=(",", ":"), sort_keys=True)
            
            payload = canonical.encode("utf-8")
            
            # Decode signature and public key (base64url)
            sig_b64 = attestation["signature"]
            key_b64 = attestation["public_key"]
            
            # Add padding if needed
            sig_b64 += "=" * (4 - len(sig_b64) % 4) if len(sig_b64) % 4 else ""
            key_b64 += "=" * (4 - len(key_b64) % 4) if len(key_b64) % 4 else ""
            
            signature = base64.urlsafe_b64decode(sig_b64)
            public_key_bytes = base64.urlsafe_b64decode(key_b64)
            
            # Verify
            public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
            public_key.verify(signature, payload)
            
            # Check if key matches expected
            key_matches = expected_key is None or key_b64.rstrip("=") == expected_key.rstrip("=")
            
            return True, key_matches
            
        except Exception:
            return False, False
    
    async def attest_async(
        self,
        action: str,
        inputs: Optional[dict] = None,
        agent: Optional[str] = None,
        metadata: Optional[dict] = None,
    ) -> AttestResult:
        """Async version of attest()."""
        if self._async_client is None:
            self._async_client = httpx.AsyncClient(
                timeout=self.timeout,
                headers=self._client.headers,
            )
        
        try:
            inputs_hash = self._hash_inputs(inputs)
            
            payload = {
                "agent_slug": agent or self.agent,
                "action": action[:500],
                "inputs_hash": inputs_hash,
            }
            if metadata:
                payload["metadata"] = metadata
            
            response = await self._async_client.post(f"{self.api_url}/v1/attest", json=payload)
            
            if response.status_code == 201:
                data = response.json()
                return AttestResult(
                    attested=True,
                    id=data.get("attestation_id"),
                    url=data.get("public_url"),
                    timestamp=datetime.fromisoformat(data["timestamp"].replace("Z", "+00:00")) if data.get("timestamp") else None,
                    signature=data.get("signature"),
                )
            else:
                return AttestResult(attested=False, error=f"API error: {response.status_code}")
                
        except httpx.TimeoutException:
            return AttestResult(attested=False, error="Timeout")
        except Exception as e:
            return AttestResult(attested=False, error=str(e)[:100])
    
    def close(self):
        """Close HTTP clients."""
        self._client.close()
        if self._async_client:
            # Note: async client should be closed with await in async context
            pass
    
    def __enter__(self):
        return self
    
    def __exit__(self, *args):
        self.close()
