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

from treeship_sdk.bootstrap import (
    BootstrapResult,
    TreeshipBootstrapError,
    ensure_cli,
)
from treeship_sdk.client import (
    SessionReportResult,
    Treeship,
    TreeshipError,
)

__all__ = [
    "BootstrapResult",
    "SessionReportResult",
    "Treeship",
    "TreeshipBootstrapError",
    "TreeshipError",
    "ensure_cli",
]


def _resolve_version() -> str:
    # Single source of truth: the package metadata. Hardcoding the
    # string here forced two parallel version sites (this file and
    # pyproject.toml) and the version-bump script regularly missed one
    # of them, producing the v0.10 dogfood smoke where pip installed
    # 0.10.0 but reported 0.9.x. importlib.metadata.version reads
    # whichever metadata the active install came with.
    try:
        from importlib.metadata import PackageNotFoundError, version
    except ImportError:  # Python < 3.8 -- not supported, but defensive.
        return "0.0.0+unknown"
    try:
        return version("treeship-sdk")
    except PackageNotFoundError:
        # Source checkout without an installed dist (`pip install -e .`
        # not run yet, or a sys.path tweak). Returning a sentinel beats
        # raising on import.
        return "0.0.0+unknown"


__version__ = _resolve_version()
