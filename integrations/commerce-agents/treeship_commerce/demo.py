"""A receipted shopping session over the retail mock, no model and no API key.

    python -m treeship_commerce.demo            # from a clone of commerce-agents, venv active
    python -m treeship_commerce.demo --report   # also publish, if a hub is attached

Drives the reference's ``ShoppingToolExecutor`` over ``examples/retail``'s
mock backend exactly the way the reference's own tests do, with receipts on:
a search, a product read, an add to the cart, an add the provenance gate
holds, and a checkout hand-off. Then it seals the Treeship session and prints
where the package is and how to verify it. Every receipt id printed is real.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import os
import sys
import uuid

from treeship_sdk import Treeship

from . import TreeshipReceipts, attach, order_placed, receipted, receipted_backend
from .lifecycle import close_session, session_status, start_session

ACTOR = "agent://shopping"


def _build_executor(session_id: str):
    try:
        from commerce_common.memory import InMemoryMemoryStore
        from commerce_common.skills import SkillRegistry
        from shopping_agent import ShoppingAgentConfig, ShoppingSessionContext, ShoppingSessionState
        from shopping_agent.executor import ShoppingToolExecutor, build_memory
        from shopping_agent_sdk import load_mock_backend
    except ImportError as err:  # pragma: no cover - environment, not logic
        sys.exit(
            f"commerce-agents packages are not installed ({err}). From a clone of "
            "anthropics/commerce-agents: pip install -r requirements.txt"
        )
    from shopping_agent.types import CheckoutHandoff

    base = load_mock_backend()

    class HostedCheckout(type(base)):
        """The retail mock plus what a platform backend has: a hosted
        checkout URL for this cart. The model never sees it; the receipt
        carries only its digest."""

        async def checkout_handoff(self, session, cart):
            return [CheckoutHandoff(url=f"https://pay.acme.example/c/{session.session_id}")]

    config = ShoppingAgentConfig(brand_name="ACME", assistant_name="Scout")
    cls = receipted(ShoppingToolExecutor)
    return cls(
        backend=receipted_backend(HostedCheckout()),
        config=config,
        skills=SkillRegistry([]),
        session=ShoppingSessionContext(session_id=session_id, user_id="demo-user"),
        state=ShoppingSessionState(),
        memory=build_memory(config, InMemoryMemoryStore()),
        inline_context=True,
    )


async def run(report: bool) -> int:
    ts = Treeship()
    commerce_session = f"demo-{uuid.uuid4().hex}"  # the reference treats this as a credential
    root = start_session(ts, name="commerce:retail-demo", actor=ACTOR)
    executor = attach(
        _build_executor(commerce_session),
        TreeshipReceipts(ts, actor=ACTOR, session_id=commerce_session, parent_id=root),
    )
    receipts: TreeshipReceipts = executor.treeship_receipts

    async def call(name: str, tool_input: dict) -> None:
        before = len(receipts.recorded)
        outcome = await executor.execute(name, tool_input)
        status = (
            "blocked:" + outcome.blocked
            if outcome.blocked
            else ("error" if outcome.is_error else "ok")
        )
        new = receipts.recorded[before:]
        ids = " ".join(new) if new else "(no receipt written)"
        print(f"  {name:<22} {status:<20} {ids}")

    tag = hashlib.sha256(commerce_session.encode()).hexdigest()[:12]
    print(f"session root      {root}")
    print(f"commerce session  sha256:{tag}  (tag; the id itself is never written)")
    print("tool calls        intent-id result-id")
    await call("search_products", {"query": "tent"})
    seen = list(executor._state.seen_products)
    if not seen:
        print("the retail mock returned nothing for 'tent'; stopping")
        return 1
    await call("get_product_details", {"product_id": seen[0]})
    await call("add_to_cart", {"product_id": seen[0], "quantity": 1})
    await call("add_to_cart", {"product_id": "p-not-from-this-session", "quantity": 1})
    await call("checkout", {"note": "Ready when you are."})
    handoff = executor._backend.handoffs[-1] if executor._backend.handoffs else None
    print(f"  {'checkout hand-off':<22} {'cart signed':<20} {handoff or '(not written)'}")
    # The host, out of the agent's sight, places the order on its checkout
    # page and chains it onto the hand-off. Mock order; no card charged.
    order = await order_placed(receipts, order_ref="ord_demo_0001", amount=None, currency="USD")
    print(f"  {'order placed':<22} {'chained':<20} {order or '(not written)'}")

    status = session_status(ts)
    print(
        f"\nsession           receipts={status['receipts']} events={status['events']} "
        f"root_verified={status['root_verified']}"
    )
    if receipts.dropped:
        print(f"WARNING           {receipts.dropped} receipt(s) not written; the chain has gaps")
    sealed = close_session(
        ts,
        summary=(
            f"Retail demo: {len(receipts.recorded) // 2} tool calls signed, one add held by the "
            "provenance gate, the cart signed at checkout hand-off, a mock order chained onto "
            "it. No card charged."
        ),
        headline="Receipted shopping session over the ACME retail mock",
    )
    print(f"package           {sealed.get('package')}")
    print(f"verify            treeship verify {receipts.head}")
    print(f"                  treeship package verify {sealed.get('package')}")
    if report:
        result = ts.session_report()
        print(f"report            {result.receipt_url}")
    return 0 if receipts.dropped == 0 else 2


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--report", action="store_true", help="publish the session report to the attached hub"
    )
    args = parser.parse_args()
    if os.environ.get("TREESHIP_DISABLE") == "1":
        sys.exit("TREESHIP_DISABLE=1 is set; this demo exists to write receipts")
    sys.exit(asyncio.run(run(report=args.report)))


if __name__ == "__main__":
    main()
