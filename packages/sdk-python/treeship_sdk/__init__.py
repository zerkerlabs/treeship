"""
Treeship SDK for Python.

Portable trust receipts for agent workflows.
Wraps the treeship CLI binary for signing and verification.

Usage:
    from treeship_sdk import Treeship

    ts = Treeship()
    result = ts.attest_action(actor="agent://my-agent", action="tool.call")
    print(result.artifact_id)

Requires the treeship CLI: curl -fsSL treeship.dev/install | sh
"""

from treeship_sdk.client import (
    SessionReportResult,
    Treeship,
    TreeshipError,
)

__all__ = [
    "SessionReportResult",
    "Treeship",
    "TreeshipError",
]
__version__ = "0.9.2"
