"""
Treeship Python SDK — cryptographic verification for AI agents.

Quick start:
    from treeship import TreshipClient, attest_reasoning

    # Client-based usage
    client = TreshipClient()
    result = client.attest(action="Document processed", inputs={"doc_id": "123"})
    print(result.url)

    # Decorator-based usage
    @attest_reasoning
    def make_decision(context):
        return {"decision": "approved", "reasoning": "meets all criteria"}
"""
from .client import TreshipClient, AttestResult, VerifyResult
from .decorators import attest_memory, attest_reasoning, attest_performance

__version__ = "1.0.0"
__all__ = [
    "TreshipClient",
    "AttestResult", 
    "VerifyResult",
    "attest_memory",
    "attest_reasoning",
    "attest_performance",
]
