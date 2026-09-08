# The customer's receipt. Each test names the property it exists for; the
# hand-off is driven through the reference's own checkout tool and its own
# presentation layer, which is where backend.checkout_handoff is called.

from __future__ import annotations

import json

from treeship_commerce import (
    TreeshipReceipts,
    attach,
    cart_digest,
    order_placed,
    receipted,
    receipted_backend,
)
from treeship_commerce.checkout import HANDOFF_ACTION, ORDER_ACTION, ReceiptedBackend
from treeship_commerce.receipts import text_digest

from .conftest import COMMERCE_SESSION_ID, Ship, needs_cli

pytestmark = needs_cli

HOSTED = "https://pay.example.test/checkout/s3cr3t-token-9f2a"


def _hosted_backend():
    """The retail mock, plus a hosted checkout URL -- the shape a platform
    backend has. The URL is a capability and must never reach a receipt."""
    from shopping_agent.types import CheckoutHandoff
    from shopping_agent_sdk import load_mock_backend

    base = load_mock_backend()

    class Hosted(type(base)):
        async def checkout_handoff(self, session, cart):
            return [CheckoutHandoff(url=HOSTED, label="Pay at ACME")]

    return Hosted()


def _shopping_executor(ship: Ship, backend):
    from commerce_common.memory import InMemoryMemoryStore
    from commerce_common.skills import SkillRegistry
    from shopping_agent import ShoppingAgentConfig, ShoppingSessionContext, ShoppingSessionState
    from shopping_agent.executor import ShoppingToolExecutor, build_memory

    config = ShoppingAgentConfig(brand_name="ACME")
    ex = receipted(ShoppingToolExecutor)(
        backend=backend,
        config=config,
        skills=SkillRegistry([]),
        session=ShoppingSessionContext(session_id=COMMERCE_SESSION_ID, user_id="u-1"),
        state=ShoppingSessionState(),
        memory=build_memory(config, InMemoryMemoryStore()),
        inline_context=True,
    )
    return attach(
        ex,
        TreeshipReceipts(
            ship.client,
            actor="agent://shopping",
            session_id=COMMERCE_SESSION_ID,
            parent_id=ship.session_root,
        ),
    )


async def _fill_cart(executor) -> None:
    outcome = await executor.execute("search_products", {"query": "tent"})
    assert not outcome.refused, outcome.result_text
    product = next(iter(executor._state.seen_products))
    outcome = await executor.execute("add_to_cart", {"product_id": product, "quantity": 2})
    assert not outcome.refused, outcome.result_text


def test_cart_digest_is_canonical_and_covers_what_is_charged():
    from shopping_agent.types import Cart, CartItem

    a = CartItem(product_id="p1", title="Tent", price=99.5, quantity=2)
    b = CartItem(product_id="p2", title="Stove", price=30.0, quantity=1, option_values={"c": "red"})
    same = cart_digest(Cart(items=[a, b]))
    assert same == cart_digest(Cart(items=[b, a])), "line order does not matter"
    assert same != cart_digest(Cart(items=[a, b], currency="EUR")), "currency does"
    assert same != cart_digest(Cart(items=[a.model_copy(update={"quantity": 3}), b]))
    assert same != cart_digest(Cart(items=[a.model_copy(update={"price": 98.0}), b]))
    # A title change is not a different purchase; the digest does not move.
    assert same == cart_digest(Cart(items=[a.model_copy(update={"title": "TENT"}), b]))
    # A dict-shaped cart (a host's own JSON) digests the same as the model.
    as_dict = {"currency": "USD", "items": [a.model_dump(), b.model_dump()]}
    assert cart_digest(as_dict) == same


async def test_checkout_hands_off_a_signed_cart_and_never_the_url(ship: Ship):
    """Through the reference's own checkout tool: the hand-off receipt names
    the cart by digest, the amount, and the URL by digest only."""
    from shopping_agent.types import Cart

    backend = receipted_backend(_hosted_backend())
    executor = _shopping_executor(ship, backend)
    await _fill_cart(executor)
    outcome = await executor.execute("checkout", {"note": "Ready when you are."})
    assert not outcome.refused, outcome.result_text

    assert len(backend.handoffs) == 1
    handoff = ship.artifacts()[backend.handoffs[0]]
    meta = handoff["statement"]["meta"]
    assert handoff["statement"]["action"] == HANDOFF_ACTION

    cart: Cart = await backend.wrapped.get_cart(executor._session)
    assert meta["cart_digest"] == cart_digest(cart), "a holder of the cart can recompute it"
    assert meta["item_count"] == cart.item_count == 2
    assert meta["subtotal"] == cart.subtotal
    assert meta["currency"] == cart.currency
    assert meta["handoffs"] == [{"url_digest": text_digest(HOSTED)}]
    assert HOSTED not in handoff["raw"]
    assert "s3cr3t" not in handoff["raw"]
    assert COMMERCE_SESSION_ID not in handoff["raw"]

    # It sits on the session chain after the checkout intent that caused it,
    # and the checkout result comes after it, so the chain reads: intent,
    # hand-off, result.
    receipts: TreeshipReceipts = executor.treeship_receipts
    chain = ship.chain(receipts.head)
    actions = [c["statement"]["action"] for c in chain][-3:]
    assert actions == [
        "commerce.tool.checkout.intent",
        HANDOFF_ACTION,
        "commerce.tool.checkout.result",
    ]
    assert receipts.last_handoff == backend.handoffs[0]
    assert ship.cli_json("verify", receipts.head)["outcome"] == "pass"


async def test_the_hosts_order_chains_from_the_handoff(ship: Ship):
    """The other half: the host places the order out of the agent's sight
    and chains a signed order receipt onto the hand-off. The order reference
    is digested, never written."""
    backend = receipted_backend(_hosted_backend())
    executor = _shopping_executor(ship, backend)
    await _fill_cart(executor)
    await executor.execute("checkout", {})
    receipts: TreeshipReceipts = executor.treeship_receipts

    head_before = receipts.head  # the checkout result, which follows the hand-off
    order_id = await order_placed(receipts, order_ref="ord_77accf", amount=199.0, currency="USD")
    assert order_id is not None
    order = ship.artifacts()[order_id]
    assert order["statement"]["action"] == ORDER_ACTION
    # Onto the head, never onto the hand-off: signing onto the hand-off
    # forks the chain and the checkout result drops out of the package
    # (QA TS-002 on 0.31.0). The hand-off is named in meta instead.
    assert order["statement"]["parentId"] == head_before
    meta = order["statement"]["meta"]
    assert meta["handoff"] == backend.handoffs[0]
    # Every receipt this recorder wrote is on the one chain the session seals.
    on_chain = {c["record"]["artifact_id"] for c in ship.chain(receipts.head)}
    assert set(receipts.recorded) <= on_chain, set(receipts.recorded) - on_chain
    assert meta["order_ref_digest"] == text_digest("ord_77accf")
    assert "ord_77accf" not in order["raw"]
    assert meta["amount"] == 199.0 and meta["currency"] == "USD"
    assert meta["handoff_recorded"] is True

    verdict = ship.cli_json("verify", order_id)
    assert verdict["outcome"] == "pass" and verdict["chain_linkage_ok"] is True


async def test_a_backend_with_no_hosted_url_still_signs_the_cart(ship: Ship):
    """The reference's default checkout_handoff returns nothing (the host's
    own checkout page). The cart that went to checkout is still signed; the
    receipt just lists no hand-off URLs."""
    from shopping_agent_sdk import load_mock_backend

    backend = receipted_backend(load_mock_backend())
    executor = _shopping_executor(ship, backend)
    await _fill_cart(executor)
    await executor.execute("checkout", {})
    (handoff_id,) = backend.handoffs
    meta = ship.artifacts()[handoff_id]["statement"]["meta"]
    assert meta["handoffs"] == []
    assert meta["item_count"] == 2


async def test_an_order_without_a_handoff_says_so(ship: Ship):
    """A host that never wrapped its backend still gets an order receipt on
    the session chain, and the receipt says the hand-off is missing rather
    than pointing at something invented."""
    from shopping_agent_sdk import load_mock_backend

    executor = _shopping_executor(ship, load_mock_backend())  # not wrapped
    await _fill_cart(executor)
    await executor.execute("checkout", {})
    receipts: TreeshipReceipts = executor.treeship_receipts
    head_before = receipts.head
    order_id = await order_placed(receipts, order_ref="ord_1", amount=1.0, currency="USD")
    order = ship.artifacts()[order_id]["statement"]
    assert order["meta"]["handoff_recorded"] is False
    assert order["parentId"] == head_before


def test_receipted_backend_is_transparent_and_idempotent():
    from shopping_agent_sdk import load_mock_backend

    base = load_mock_backend()
    wrapped = receipted_backend(base)
    assert isinstance(wrapped, ReceiptedBackend)
    assert receipted_backend(wrapped) is wrapped
    assert wrapped.wrapped is base
    # Attribute access and assignment go through to the real backend.
    assert wrapped.get_cart is not None
    wrapped.some_setting = 3
    assert base.some_setting == 3


async def test_the_handoff_receipt_is_recomputable_from_the_card_payload(ship: Ship):
    """What a customer holds is the checkout card's cart payload. Its lines
    are enough to recompute the digest on the receipt -- the receipt does not
    depend on anything the customer cannot see."""
    backend = receipted_backend(_hosted_backend())
    executor = _shopping_executor(ship, backend)
    await _fill_cart(executor)
    outcome = await executor.execute("checkout", {})
    card = next(e for e in outcome.events if getattr(e, "type", "") == "ui")
    payload = card.data["payload"] if hasattr(card, "data") else card.payload
    cart_on_card = {"currency": payload["cart"]["currency"], "items": payload["cart"]["items"]}
    meta = ship.artifacts()[backend.handoffs[0]]["statement"]["meta"]
    assert cart_digest(cart_on_card) == meta["cart_digest"], json.dumps(payload["cart"])[:300]
