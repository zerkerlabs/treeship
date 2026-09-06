"""Treeship receipts for anthropics/commerce-agents.

One shared executor runs every tool call on all three commerce-agents
runtimes (Messages API, Agent SDK, Managed Agents). Wrapping it once gives
every call a signed intent receipt before it runs and a signed result
receipt after, chained from the session's root. See ``receipts.py``.
"""

from .receipts import (
    TreeshipExecutorMixin,
    TreeshipReceipts,
    args_digest,
    attach,
    receipted,
    text_digest,
)

__all__ = [
    "TreeshipExecutorMixin",
    "TreeshipReceipts",
    "args_digest",
    "attach",
    "receipted",
    "text_digest",
]
__version__ = "0.27.0"
