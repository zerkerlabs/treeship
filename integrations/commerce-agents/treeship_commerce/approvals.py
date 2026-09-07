"""The operator's yes, signed once and spendable once.

The gap this closes
-------------------
On the merchant side the reference already gates the one tool that mutates a
merchant's system of record. ``check_apply_change`` refuses unless the change
was staged in this session, passes the configured guardrails, and -- when
``require_host_approval`` is on -- appears in ``state.approved_change_ids``.
The console's y/N puts it there through ``toolset.host_approve(change_id)``
and takes it out again with ``host_clear`` once the apply turn returns.

That set is an in-process boolean. It is correct while the process lives and
it is gone afterwards, so it cannot answer the two questions an operator is
actually asked later:

* *Did a human approve this change, and when?* The set left no record.
* *Was that approval spent more than once?* The set cannot say; ``host_approve``
  is idempotent and a second apply inside the same window passes the same check.

:class:`MerchantApprovals` answers both. The moment the operator says yes it
mints a **signed Approval Grant** scoped to one actor, one action, and one
change, with ``max_uses=1``. When the apply runs, its intent receipt is signed
*with that grant's nonce*, which makes the CLI reserve a use in the local
Approval Use Journal before it will sign. A second apply of the same change
finds the grant spent and gets no receipt. A grant minted for one change
cannot be spent on another: the action names ``change://<change_id>`` as its
subject, and the grant's scope names the same URI.

What this does not do
---------------------
It does not replace the reference's gate, and it is not a second gate by
default. Recording stays off the critical path: if a grant is missing or
already spent, the intent receipt is written *without* approval evidence and
says so (``approval: "unproven"`` with a reason), and the tool still runs into
the reference's own ``check_apply_change``, which is what holds it. Pass
``enforce=True`` to :func:`approved` when you want the missing evidence to
hold the call itself -- a deployment that has decided the receipt is the
authority, not a record of it.

Wiring it
---------
The host that asks the human is the host that mints::

    approvals = MerchantApprovals(ts, approver="human://operator")
    Executor = approved(receipted(MerchantToolExecutor, recorder=...), approvals)

    # in the console's y/N loop, replacing the bare host_approve:
    approvals.grant(change.change_id, summary=change.summary)
    toolset.host_approve(change.change_id)

``grant`` returns the :class:`Grant`; ``toolset.host_approve`` still runs the
reference's own gate. The two together mean the change is both allowed to
apply and provably approved.
"""

from __future__ import annotations

import asyncio
import logging
import os
from dataclasses import dataclass
from typing import Any, Callable, Mapping

from treeship_sdk import Treeship

from .receipts import TreeshipExecutorMixin, sdk_supports_subject

logger = logging.getLogger("treeship_commerce")

# The action label the apply's intent receipt carries, and the one a grant is
# scoped to. Kept in one place because the scope match is exact: a grant that
# names a different label refuses every action.
APPLY_INTENT_ACTION = "commerce.tool.apply_change.intent"

# The subject URI scheme for a staged change. The action carries it as
# subject.uri and the grant's allowed_subjects names the same string, so a
# grant for one change cannot be spent on another.
SUBJECT_SCHEME = "change"


def change_subject(change_id: str) -> str:
    """``chg_7f2`` -> ``change://chg_7f2``, the URI both sides match on."""
    return f"{SUBJECT_SCHEME}://{change_id}"


@dataclass(frozen=True)
class PendingApproval:
    """What the recorder signs the next intent with.

    ``subject`` is the subject of the *call about to happen*, derived from its
    own arguments -- never copied from the grant. Taking it from the grant
    would make the scope check compare the grant against itself and pass for
    every change, which is the whole property gone.
    """

    nonce: str
    grant_id: str
    subject: str
    change_id: str


@dataclass(frozen=True)
class Grant:
    """A signed, single-use approval for one staged change."""

    change_id: str
    artifact_id: str
    nonce: str
    subject: str

    def __repr__(self) -> str:  # nonce is a capability; keep it out of logs
        return (
            f"Grant(change_id={self.change_id!r}, artifact_id={self.artifact_id!r}, "
            f"nonce=<{len(self.nonce)} chars>)"
        )


class MerchantApprovals:
    """Mints one single-use grant per approved change and hands out its nonce.

    ``client`` is a configured :class:`treeship_sdk.Treeship`. ``approver`` is
    the human the grant names -- a URI, not a display name, since it is signed.
    ``actor`` must equal the actor the receipts are written under, or the
    grant's scope will refuse the action it was minted for.
    """

    def __init__(
        self,
        client: Treeship,
        *,
        approver: str = "human://operator",
        actor: str = "agent://merchant",
        action: str = APPLY_INTENT_ACTION,
        expires_at: str | None = None,
    ) -> None:
        self.client = client
        self.approver = approver
        self.actor = actor
        self.action = action
        self.expires_at = expires_at
        self._grants: dict[str, Grant] = {}
        self.minted: list[str] = []
        """Artifact ids of the grants minted, in order."""

    @property
    def disabled(self) -> bool:
        return os.environ.get("TREESHIP_DISABLE") == "1"

    def grant(self, change_id: str, *, summary: str = "") -> Grant | None:
        """Sign that the operator approved ``change_id``. Once.

        Returns the :class:`Grant`, or ``None`` when recording is disabled or
        the grant could not be signed -- this is a recorder, so a failure here
        warns and leaves the reference's own approval gate to do its work.
        """
        if self.disabled:
            return None
        if not sdk_supports_subject():
            self._warn_old_sdk()
            return None
        description = f"apply change {change_id}"
        if summary:
            description = f"{description}: {summary}"
        try:
            result = self.client.attest_approval(
                self.approver,
                description,
                allowed_actions=[self.action],
                allowed_actors=[self.actor],
                allowed_subjects=[change_subject(change_id)],
                max_uses=1,
                expires_at=self.expires_at,
            )
        except Exception as err:  # noqa: BLE001 -- minting must not break the console
            logger.warning(
                "treeship approval grant not written for %s: %s. The change is still "
                "gated by the reference's own approval check; it just is not provable.",
                change_id,
                err,
            )
            return None
        grant = Grant(
            change_id=change_id,
            artifact_id=result.artifact_id,
            nonce=result.nonce,
            subject=change_subject(change_id),
        )
        self._grants[change_id] = grant
        self.minted.append(result.artifact_id)
        return grant

    def nonce_for(self, change_id: str) -> str | None:
        grant = self._grants.get(change_id)
        return grant.nonce if grant else None

    def get(self, change_id: str) -> Grant | None:
        return self._grants.get(change_id)

    def _warn_old_sdk(self) -> None:
        if getattr(self, "_old_sdk_warned", False):
            return
        self._old_sdk_warned = True
        logger.warning(
            "treeship-sdk cannot name an action's subject, so a single-use approval "
            "grant would be refused by its own scope on every apply. No grant minted; "
            "apply_change stays gated by the reference's own approval check. Upgrade "
            "treeship-sdk to mint provable approvals."
        )

    def forget(self, change_id: str) -> None:
        """Drop the local handle on a grant. The signed grant and any use of it
        stay on disk; this only stops this object from offering the nonce
        again. The journal, not this dict, is what makes a use single."""
        self._grants.pop(change_id, None)


def change_id_of(tool_input: Mapping[str, Any] | None) -> str | None:
    """The change a tool call targets, or ``None``. The reference names the
    argument ``change_id`` on both ``apply_change`` and ``discard_change``."""
    if not tool_input:
        return None
    value = tool_input.get("change_id")
    return str(value) if value else None


class TreeshipApprovalMixin:
    """Binds :class:`MerchantApprovals` to the apply tool's intent receipt.

    Sits between :class:`~treeship_commerce.receipts.TreeshipExecutorMixin` and
    the reference executor. It does not sign anything itself; it tells the
    recorder which nonce and subject to sign the next intent with, so the CLI
    reserves the use before the receipt exists.
    """

    treeship_approvals: MerchantApprovals | None = None
    treeship_approvals_factory: Callable[[Any], MerchantApprovals] | None = None
    treeship_apply_tool: str = "apply_change"
    treeship_enforce_approval: bool = False
    #: What the most recent apply's intent receipt says about its grant:
    #: ``"proven"``, ``"unproven"`` (the grant would not spend: already used,
    #: expired, or scoped to another change), or ``None`` when no grant was
    #: offered. Set after every apply so a host can print or log the verdict
    #: next to the tool's own outcome.
    treeship_last_approval: str | None = None
    _treeship_apply_lock: asyncio.Lock | None = None

    def _treeship_approvals(self) -> MerchantApprovals | None:
        if self.treeship_approvals is None and self.treeship_approvals_factory is not None:
            self.treeship_approvals = self.treeship_approvals_factory(self)
        return self.treeship_approvals

    def _treeship_is_apply(self, name: str) -> bool:
        # Runtimes prefix tool names (``mcp__merchant__apply_change``), so the
        # reference matches on the suffix and so do we.
        return name.endswith(self.treeship_apply_tool)

    def _treeship_hold(self, name: str, tool_input: dict[str, Any] | None) -> Any | None:
        """Under ``enforce``, hold an apply whose approval is not proven. Runs
        after the intent receipt, so the receipt already says *why*: no grant
        was offered, or the grant would not spend (already used, expired, or
        scoped to another change)."""
        if not self.treeship_enforce_approval or not self._treeship_is_apply(name):
            return None
        approvals = self._treeship_approvals()
        if approvals is None:
            return None
        change_id = change_id_of(tool_input)
        receipts = self._treeship_recorder()
        verdict = receipts.approval_outcome if receipts is not None else None
        if verdict == "proven":
            return None
        if verdict == "unproven":
            return _held_unapproved(change_id, spent=True)
        # No grant was offered at all (or nothing records, so nothing was tried).
        if change_id is None or approvals.get(change_id) is None:
            return _held_unapproved(change_id, spent=False)
        return None

    async def execute(self, name: str, tool_input: dict[str, Any] | None) -> Any:
        approvals = self._treeship_approvals()
        if approvals is None or not self._treeship_is_apply(name):
            return await super().execute(name, tool_input)  # type: ignore[misc]

        # The pending approval rides on the recorder, which one executor shares
        # across its calls. Applies are serialised per executor so two
        # concurrent applies cannot read each other's grant; every other tool
        # runs unserialised as before.
        if self._treeship_apply_lock is None:
            self._treeship_apply_lock = asyncio.Lock()
        async with self._treeship_apply_lock:
            change_id = change_id_of(tool_input)
            grant = approvals.get(change_id) if change_id else None
            receipts = self._treeship_recorder()

            if receipts is not None and grant is not None and change_id is not None:
                receipts.pending_approval = PendingApproval(
                    nonce=grant.nonce,
                    grant_id=grant.artifact_id,
                    # From the call, not the grant.
                    subject=change_subject(change_id),
                    change_id=change_id,
                )
            try:
                # TreeshipExecutorMixin signs the intent (consuming the grant),
                # asks _treeship_hold, runs or holds, and signs the result.
                return await super().execute(name, tool_input)  # type: ignore[misc]
            finally:
                if receipts is not None:
                    receipts.pending_approval = None
                    spent = receipts.take_approval_outcome()
                    self.treeship_last_approval = spent
                    if spent is not None and grant is not None:
                        # A grant is spendable once; drop the handle either
                        # way, so a second apply cannot even offer the nonce.
                        approvals.forget(grant.change_id)


def _held_unapproved(change_id: str | None, *, spent: bool) -> Any:
    """The reference's own held outcome, so an enforced refusal looks to the
    model exactly like the gate it already knows how to talk about."""
    from commerce_common.streaming import ToolOutcome

    why = (
        "its signed approval would not spend: it was already used, has expired, "
        "or was minted for a different change"
        if spent
        else "it has no signed approval grant; the operator has not approved it"
    )
    return ToolOutcome.held(
        "approval",
        f"change {change_id} cannot be applied: {why}. Ask the operator to approve "
        "it on their approval surface.",
    )


def approved(
    executor_cls: type,
    approvals: MerchantApprovals | Callable[[Any], MerchantApprovals],
    *,
    apply_tool: str = "apply_change",
    enforce: bool = False,
) -> type:
    """``receipted(MerchantToolExecutor)`` in, approval-bound executor out.

    Compose it around a receipted class -- the approval evidence rides on the
    intent receipt, so there must be a recorder for it to ride on::

        Executor = approved(
            receipted(MerchantToolExecutor, recorder=make_recorder),
            approvals,
        )

    ``enforce=True`` turns a missing or spent grant into a held outcome instead
    of an unproven receipt. Leave it off to keep recording strictly off the
    critical path, with the reference's ``check_apply_change`` doing the gating.
    """
    if not issubclass(executor_cls, TreeshipExecutorMixin):
        raise TypeError(
            f"{executor_cls.__name__} does not record receipts, so there is nothing for "
            f"the approval to ride on. Wrap it first: "
            f"approved(receipted({executor_cls.__name__}, recorder=...), approvals)."
        )
    body: dict[str, Any] = {
        "treeship_apply_tool": apply_tool,
        "treeship_enforce_approval": enforce,
    }
    if callable(approvals) and not isinstance(approvals, MerchantApprovals):
        body["treeship_approvals_factory"] = staticmethod(approvals)
    else:
        body["treeship_approvals"] = approvals
    return type(
        f"Approved{executor_cls.__name__.removeprefix('Approved')}",
        (TreeshipApprovalMixin, executor_cls),
        body,
    )
