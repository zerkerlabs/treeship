"""Drop-in for the reference's approval surface.

The Agent SDK runtime's ``MerchantToolset`` *is* the host's approval surface:
its console asks y/N per staged change and calls ``host_approve(change_id)``
on yes, then ``host_clear(change_id)`` when the apply turn returns. That is
the one place a human's decision enters the process, so it is the one place
to sign it.

:func:`approving` wraps those two methods on an existing toolset so the
console's loop needs no edits::

    toolset = approving(
        MerchantToolset(backend=..., executor_class=Executor),
        approvals,
    )
    # unchanged from the reference's main.py:
    toolset.host_approve(change.change_id)     # now also mints the signed grant
    ...
    toolset.host_clear(change.change_id)       # now also drops the grant handle

``host_approve`` still sets the reference's mark first, so the gate behaves
exactly as before even if minting fails (it warns; see
:meth:`MerchantApprovals.grant`). ``host_clear`` forgets the grant handle so a
later turn cannot offer a nonce the operator's click did not cover -- the
journal, not the handle, is what makes a use single; forgetting is hygiene.

The other two runtimes have no in-process approval surface. The Messages API
orchestrator leaves ``state.approved_change_ids`` to the host, so the host
calls :meth:`MerchantApprovals.grant` alongside its own mark. The Managed
Agents MCP server runs with ``require_host_approval=False`` because the
platform's ``always_ask`` prompt is the approval surface; that click happens
outside the process, so nothing here can sign it -- an apply there records
no approval evidence rather than inventing some, and ``enforce=True`` would
hold every apply, which is the honest reading of "no signed approval".
"""

from __future__ import annotations

from typing import Any, TypeVar

from .approvals import MerchantApprovals

T = TypeVar("T")


def approving(toolset: T, approvals: MerchantApprovals) -> T:
    """Bind ``approvals`` to a toolset's ``host_approve`` / ``host_clear``.

    The toolset must expose both methods, as the reference's ``MerchantToolset``
    does. Returns the same object, so ``build_merchant_sdk_tools(toolset)`` and
    everything else that holds it keep working. The summary the grant is minted
    with is the staged change's own ``summary`` when the toolset can look it
    up, so the operator's signed record reads the same as the card they
    approved.
    """
    for name in ("host_approve", "host_clear"):
        if not callable(getattr(toolset, name, None)):
            raise TypeError(
                f"{type(toolset).__name__} has no {name}(); approving() wraps the "
                "reference's MerchantToolset approval surface, and this is not one."
            )
    original_approve = toolset.host_approve
    original_clear = toolset.host_clear

    def host_approve(change_id: str) -> None:
        # The reference's mark first: the gate must behave exactly as before
        # even when the grant cannot be signed.
        original_approve(change_id)
        approvals.grant(change_id, summary=_summary_of(toolset, change_id))

    def host_clear(change_id: str) -> None:
        original_clear(change_id)
        approvals.forget(change_id)

    toolset.host_approve = host_approve  # type: ignore[attr-defined]
    toolset.host_clear = host_clear  # type: ignore[attr-defined]
    toolset.treeship_approvals = approvals  # type: ignore[attr-defined]
    return toolset


def _summary_of(toolset: Any, change_id: str) -> str:
    state = getattr(toolset, "state", None)
    seen = getattr(state, "seen_changes", None) or {}
    change = seen.get(change_id)
    return str(getattr(change, "summary", "") or "")
