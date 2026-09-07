"""A receipted merchant session where the operator's approval is signed once.

    python -m treeship_commerce.demo_merchant   # from a clone of commerce-agents, venv active

Drives the reference's ``MerchantToolExecutor`` over ``examples/retail``'s mock
merchant with no model and no API key: a listing search, a staged price update,
then three attempts to apply it.

    1. before approval       -- the reference's own gate holds it
    2. after approval        -- the signed grant is consumed, the apply lands
    3. the same again        -- the grant is spent; the journal refuses a second use

The third is the one that matters. The reference's approval *gate* lets it
through, because the host's in-process mark is still set for the rest of the
turn; the mock backend then happens to refuse it as already applied, which is
backend state, not evidence. The Approval Use Journal refuses it regardless of
what the backend knows, before anything is signed, and the receipt says so:
the row reads ``error, approval unproven`` in the default run (the tool ran
and the backend refused it; the receipt carries no approval) and
``blocked:approval`` under ``--enforce`` (the wrapper held the tool itself).
Every id printed is real; verify them with the commands printed at the end.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import os
import sys
import uuid

from treeship_sdk import Treeship

from . import MerchantApprovals, TreeshipReceipts, approved, attach, receipted
from .lifecycle import _run_json, close_session, session_status, start_session
from .receipts import sdk_supports_subject

ACTOR = "agent://merchant"
APPROVER = "human://operator"


def _build_executor(session_id: str, approvals: MerchantApprovals, *, enforce: bool):
    try:
        from commerce_common.memory import InMemoryMemoryStore
        from commerce_common.skills import SkillRegistry
        from merchant_agent import (
            MerchantAgentConfig,
            MerchantSessionContext,
            MerchantSessionState,
        )
        from merchant_agent.executor import MerchantToolExecutor, build_memory
        from merchant_agent_sdk import load_mock_backend
    except ImportError as err:  # pragma: no cover - environment, not logic
        sys.exit(
            f"commerce-agents packages are not installed ({err}). From a clone of "
            "anthropics/commerce-agents: pip install -r requirements.txt"
        )
    config = MerchantAgentConfig()
    cls = approved(receipted(MerchantToolExecutor), approvals, enforce=enforce)
    return cls(
        backend=load_mock_backend(),
        config=config,
        skills=SkillRegistry([]),
        session=MerchantSessionContext(
            session_id=session_id, merchant_id="m-acme", operator=APPROVER
        ),
        state=MerchantSessionState(),
        memory=build_memory(config, InMemoryMemoryStore()),
    )


async def run(*, enforce: bool) -> int:
    if not sdk_supports_subject():
        sys.exit(
            "the installed treeship-sdk cannot name an action's subject, so a "
            "single-use grant would be refused by its own scope. Upgrade treeship-sdk."
        )
    ts = Treeship()
    commerce_session = f"demo-{uuid.uuid4().hex}"  # the reference treats this as a credential
    root = start_session(ts, name="commerce:merchant-demo", actor=ACTOR)
    approvals = MerchantApprovals(ts, approver=APPROVER, actor=ACTOR)
    executor = attach(
        _build_executor(commerce_session, approvals, enforce=enforce),
        TreeshipReceipts(
            ts, actor=ACTOR, session_id=commerce_session, role="merchant", parent_id=root
        ),
    )
    receipts: TreeshipReceipts = executor.treeship_receipts

    async def call(label: str, name: str, tool_input: dict):
        before = len(receipts.recorded)
        outcome = await executor.execute(name, tool_input)
        status = (
            "blocked:" + outcome.blocked
            if outcome.blocked
            else ("error" if outcome.is_error else "ok")
        )
        # What the receipt says about the grant, next to what the tool did.
        # ``unproven`` is the replay in the default run: the journal refused
        # a second use before anything was signed, the wrapper recorded the
        # call without approval evidence, and the mock backend then refused
        # it as already applied. ``error`` alone would let the backend take
        # the credit for a refusal the journal made.
        approval = getattr(executor, "treeship_last_approval", None)
        if approval:
            status = f"{status}, approval {approval}"
        new = receipts.recorded[before:]
        print(f"  {label:<26} {status:<26} {' '.join(new) or '(no receipt written)'}")
        return outcome

    tag = hashlib.sha256(commerce_session.encode()).hexdigest()[:12]
    print(f"session root      {root}")
    print(f"commerce session  sha256:{tag}  (tag; the id itself is never written)")
    print("steps                      outcome                    receipt ids")

    await call("search_listings", "search_listings", {"query": ""})
    listings = [
        (lid, item) for lid, item in executor._state.seen_listings.items() if not item.has_options
    ]
    if not listings:
        print("the merchant mock returned no simple listings; stopping")
        return 1
    listing_id, listing = listings[0]
    await call(
        "stage_price_update",
        "stage_price_update",
        {
            "items": [{"listing_id": listing_id, "new_price": round(listing.price * 0.97, 2)}],
            "note": "3% clearance",
        },
    )
    staged = list(executor._state.seen_changes)
    if not staged:
        print("nothing staged; stopping")
        return 1
    change_id = staged[0]

    # 1. Unapproved. The reference's own gate holds it.
    await call("apply (not yet approved)", "apply_change", {"change_id": change_id})

    # 2. The operator says yes. A host does both: the signed grant, which is the
    #    evidence, and the reference's mark, which is what lets the apply run.
    grant = approvals.grant(change_id, summary=f"3% clearance on {listing_id}")
    executor._state.approved_change_ids.add(change_id)
    print(f"  operator approves          grant signed               {grant.artifact_id}")
    await call("apply (approved)", "apply_change", {"change_id": change_id})

    # 3. The replay. The reference's mark is still set, so its gate allows this;
    #    only the mock backend's "already applied" state stops it. The grant is
    #    spent, so the receipt cannot claim approval whatever the backend says.
    approvals._grants[change_id] = grant
    await call("apply again (replay)", "apply_change", {"change_id": change_id})

    uses = _run_json(ts, ["approval", "uses", grant.artifact_id])
    print(f"\napproval          grant {grant.artifact_id}")
    print(f"                  journal records {len(uses.get('uses', []))} use of it, max 1")

    status = session_status(ts)
    print(
        f"session           receipts={status['receipts']} events={status['events']} "
        f"root_verified={status['root_verified']}"
    )
    if receipts.dropped:
        print(f"WARNING           {receipts.dropped} receipt(s) not written; the chain has gaps")
    sealed = close_session(
        ts,
        summary=(
            "Merchant demo: one price change staged, held unapproved, applied once under a "
            "signed single-use approval, and refused on replay. Mock merchant, no live prices."
        ),
        headline="Receipted merchant session with a single-use operator approval",
    )
    print(f"package           {sealed.get('package')}")
    print(f"verify            treeship verify {receipts.head}")
    print(f"                  treeship approval uses {grant.artifact_id}")
    print(f"                  treeship package verify {sealed.get('package')}")
    return 0 if receipts.dropped == 0 else 2


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--enforce",
        action="store_true",
        help="hold an apply that has no signed grant, instead of recording it as unproven",
    )
    args = parser.parse_args()
    if os.environ.get("TREESHIP_DISABLE") == "1":
        sys.exit("TREESHIP_DISABLE=1 is set; this demo exists to write receipts")
    sys.exit(asyncio.run(run(enforce=args.enforce)))


if __name__ == "__main__":
    main()
