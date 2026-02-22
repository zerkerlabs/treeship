"""
Treeship Python SDK — cryptographic verification for AI agents.

Quick start:
    from treeship_sdk import Treeship

    # Client-based usage
    ts = Treeship()
    result = ts.attest(action="Document processed", inputs_hash=ts.hash({"doc_id": "123"}))
    print(result.url)

    # Decorator-based usage (v0.2.0+)
    from treeship_sdk import attest_reasoning

    @attest_reasoning
    def make_decision(context):
        return {"decision": "approved", "reasoning": "meets all criteria"}
"""
from .client import Treeship, AttestResult
from .async_client import AsyncTreeship
from .decorators import attest_memory, attest_reasoning, attest_performance

__version__ = "0.2.0"
__all__ = [
    "Treeship",
    "AsyncTreeship",
    "AttestResult",
    "attest_memory",
    "attest_reasoning",
    "attest_performance",
]
