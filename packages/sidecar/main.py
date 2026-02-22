"""
Treeship Sidecar — universal verification bridge for any agent framework.
Port 2019. Two interfaces: REST and MCP.

Privacy contract:
  Receives: action (string) + inputs (dict, optional)
  Computes: sha256(inputs) locally
  Sends to Treeship: action + hash ONLY. NEVER raw content.
  Returns: public verification URL

Reliability contract:
  NEVER raises to caller. Swallows all exceptions.
  Returns {"attested": false} gracefully on any failure.
  Agent work is NEVER blocked by attestation failure.
"""
import hashlib
import json
import os
import httpx
from datetime import datetime, timezone
from typing import Optional

from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(
    title="Treeship Sidecar",
    version="1.0.0",
    description="Universal verification bridge for AI agents"
)

# Configuration from environment
API_URL = os.getenv("TREESHIP_API_URL", "https://api.treeship.dev")
API_KEY = os.getenv("TREESHIP_API_KEY", "")
AGENT = os.getenv("TREESHIP_AGENT", "unknown-agent")
HASH_ONLY = os.getenv("TREESHIP_HASH_ONLY", "true").lower() == "true"
TIMEOUT = float(os.getenv("TREESHIP_TIMEOUT", "10"))


class AttestRequest(BaseModel):
    action: str
    inputs: Optional[dict] = None


class AttestResponse(BaseModel):
    attested: bool
    url: Optional[str] = None
    id: Optional[str] = None
    agent: str
    timestamp: Optional[str] = None
    error: Optional[str] = None


def _hash_inputs(inputs: Optional[dict]) -> str:
    """Hash inputs using SHA-256. Content never leaves this function."""
    if inputs is None:
        inputs = {}
    canonical = json.dumps(inputs, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode()).hexdigest()


async def _attest_to_api(action: str, inputs_hash: str) -> AttestResponse:
    """Send attestation to Treeship API. Never raises."""
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            response = await client.post(
                f"{API_URL}/v1/attest",
                headers={
                    "Authorization": f"Bearer {API_KEY}",
                    "Content-Type": "application/json",
                    "User-Agent": "treeship-sidecar/1.0.0"
                },
                json={
                    "agent_slug": AGENT,
                    "action": action[:500],  # Truncate to 500 chars
                    "inputs_hash": inputs_hash
                }
            )
            
            if response.status_code == 201:
                data = response.json()
                return AttestResponse(
                    attested=True,
                    url=data.get("public_url"),
                    id=data.get("attestation_id"),
                    agent=AGENT,
                    timestamp=data.get("timestamp")
                )
            else:
                return AttestResponse(
                    attested=False,
                    agent=AGENT,
                    error=f"API returned {response.status_code}"
                )
    except httpx.TimeoutException:
        return AttestResponse(attested=False, agent=AGENT, error="Timeout")
    except Exception as e:
        return AttestResponse(attested=False, agent=AGENT, error=str(e)[:100])


@app.post("/attest", response_model=AttestResponse)
async def attest(req: AttestRequest) -> AttestResponse:
    """
    Create a tamper-proof attestation for an agent action.
    
    - action: Human-readable description (max 500 chars)
    - inputs: Optional dict of inputs (hashed locally, never sent)
    
    Returns verification URL on success, {"attested": false} on failure.
    NEVER blocks or raises — agent work always continues.
    """
    inputs_hash = _hash_inputs(req.inputs)
    return await _attest_to_api(req.action, inputs_hash)


@app.get("/health")
async def health():
    """Health check for Docker/Kubernetes."""
    return {
        "status": "ok",
        "agent": AGENT,
        "api_url": API_URL,
        "hash_only": HASH_ONLY,
        "version": "1.0.0"
    }


@app.get("/")
async def root():
    """Root endpoint with usage info."""
    return {
        "name": "Treeship Sidecar",
        "version": "1.0.0",
        "docs": "/docs",
        "endpoints": {
            "POST /attest": "Create attestation",
            "GET /health": "Health check"
        }
    }


# MCP support (optional, when fastmcp is available)
try:
    from fastmcp import FastMCP
    
    mcp = FastMCP("Treeship")
    
    @mcp.tool()
    async def treeship_attest(action: str, inputs: Optional[dict] = None) -> str:
        """
        Create a tamper-proof, independently verifiable record of this agent decision.
        
        Call at: data reads, consequential decisions, external tool calls, final outputs.
        Never blocks on failure — always returns quickly.
        
        Args:
            action: Human-readable description of what happened
            inputs: Optional dict of inputs (hashed locally, content never sent)
        
        Returns:
            Verification URL on success, status message on failure
        """
        inputs_hash = _hash_inputs(inputs)
        result = await _attest_to_api(action, inputs_hash)
        
        if result.attested:
            return f"Verified. Audit trail: {result.url}"
        return "Verification unavailable — continuing."
    
    app.mount("/mcp", mcp.get_asgi_app())
    MCP_ENABLED = True
except ImportError:
    MCP_ENABLED = False


if __name__ == "__main__":
    import uvicorn
    
    port = int(os.getenv("PORT", "2019"))
    log_level = os.getenv("TREESHIP_LOG_LEVEL", "warning")
    
    print(f"Treeship Sidecar starting on port {port}")
    print(f"  Agent: {AGENT}")
    print(f"  API: {API_URL}")
    print(f"  Hash-only mode: {HASH_ONLY}")
    print(f"  MCP enabled: {MCP_ENABLED}")
    
    uvicorn.run(app, host="0.0.0.0", port=port, log_level=log_level)
