"""Treeship receipts for anthropics/commerce-agents.

One shared executor runs every tool call on all three commerce-agents
runtimes (Messages API, Agent SDK, Managed Agents). Wrapping it once gives
every call a signed intent receipt before it runs and a signed result
receipt after, chained from the session's root. See ``receipts.py``.
"""

from .approvals import (
    Grant,
    MerchantApprovals,
    TreeshipApprovalMixin,
    approved,
    change_subject,
)
from .checkout import ReceiptedBackend, cart_digest, order_placed, receipted_backend
from .host import approving
from .receipts import (
    TreeshipExecutorMixin,
    TreeshipReceipts,
    args_digest,
    attach,
    receipted,
    text_digest,
)

__all__ = [
    "attest_at_handoff",
    "vi_check",
    "vi_verify",
    "Grant",
    "MerchantApprovals",
    "ReceiptedBackend",
    "TreeshipApprovalMixin",
    "TreeshipExecutorMixin",
    "TreeshipReceipts",
    "approved",
    "approving",
    "args_digest",
    "attach",
    "cart_digest",
    "change_subject",
    "order_placed",
    "receipted",
    "receipted_backend",
    "text_digest",
]
__version__ = "0.31.0"
from .vi import attest_at_handoff, vi_check, vi_verify  # noqa: E402
