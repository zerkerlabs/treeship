"""The customer's receipt: exactly the cart that went to checkout.

Where the seam is
-----------------
The reference's ``checkout`` tool does not take the cart as an argument and
never shows the model a payment URL. When the model calls ``checkout``, the
executor's presentation layer reads the cart from the backend, then asks
``backend.checkout_handoff(session, cart)`` where that cart is paid for: the
platform's hosted checkout URL, or one URL per seller on a marketplace. The
URL goes on the card the host renders and nowhere else.

That call is the one moment where "this cart" and "this checkout" meet, and
it happens inside the backend the deployment owns. :func:`receipted_backend`
wraps a backend so that call also signs a **hand-off receipt**: a digest of
the cart's lines, the item count, subtotal and currency, and a digest of each
URL handed off, with the seller when there is one. Chained to the session's
receipts, so it sits after the ``checkout`` intent that caused it.

Then the host places the order, on its own checkout page, out of the agent's
sight. :func:`order_placed` lets the host chain a signed **order receipt**
after the hand-off, naming it: a digest of the order reference, the amount and currency.
A customer, a merchant, or an auditor holding the cart can recompute the cart
digest and check that the order chains from a hand-off for exactly that cart.

What the receipts never carry
-----------------------------
The URL (it is a capability; a digest lets a holder check it and tells a
reader nothing), the product titles or prices per line (the cart digest covers
them; a holder of the cart can recompute it), the customer, the session id.
The subtotal, currency and item count are on the receipt because a receipt
for a purchase that does not say the amount is not a receipt.

Wiring
------
Wrap the backend once, where the runtime is built::

    backend = receipted_backend(MyStorefront(), recorder=lambda session: ...)

or let it find the recorder by the commerce session: every
:class:`~treeship_commerce.receipts.TreeshipReceipts` registers itself under
its session tag, and the wrapped backend looks the session up the same way.
That is the default, and it is what the ``receipted(...)`` executor classes
on all three runtimes already give you.

When the host's order comes back::

    order_placed(receipts, order_ref=order.order_id, amount=order.total,
                 currency=order.currency)
"""

from __future__ import annotations

import hashlib
import json
import logging
from typing import Any, Callable, Sequence

from .receipts import TreeshipReceipts, _jsonable, _session_tag, text_digest

logger = logging.getLogger("treeship_commerce")

HANDOFF_ACTION = "commerce.checkout.handoff"
ORDER_ACTION = "commerce.order.placed"


def cart_digest(cart: Any) -> str:
    """``sha256:<hex>`` over the cart's lines, in a canonical form.

    Covers what a customer is charged for: each line's product id, variant,
    option values, unit price and quantity, plus the cart's currency. Sorted
    by product id so two carts with the same lines in a different order are
    the same cart. Anyone holding the cart can recompute it; the receipt
    holder learns only that *a* cart of this digest went to checkout.
    """
    lines = []
    for item in _get(cart, "items") or []:
        lines.append(
            {
                "product_id": _get(item, "product_id"),
                "variant_of": _get(item, "variant_of"),
                "option_values": dict(_get(item, "option_values") or {}),
                "price": _get(item, "price"),
                "quantity": _get(item, "quantity"),
            }
        )
    lines.sort(key=lambda line: json.dumps(line, sort_keys=True, default=_jsonable))
    canonical = json.dumps(
        {"currency": _get(cart, "currency"), "lines": lines},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=_jsonable,
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


def _get(obj: Any, name: str) -> Any:
    if isinstance(obj, dict):
        return obj.get(name)
    return getattr(obj, name, None)


class ReceiptedBackend:
    """A proxy over a ``StorefrontBackend`` whose ``checkout_handoff`` also
    signs the hand-off. Every other attribute goes straight through, so the
    executor, the enrichment hooks and the runtime see the backend they were
    given. ``isinstance`` checks against the reference's protocol still pass
    because the protocol is structural.
    """

    def __init__(
        self,
        backend: Any,
        *,
        recorder: Callable[[Any], TreeshipReceipts | None] | None = None,
    ) -> None:
        object.__setattr__(self, "_treeship_backend", backend)
        object.__setattr__(self, "_treeship_recorder", recorder)
        object.__setattr__(self, "handoffs", [])

    def __getattr__(self, name: str) -> Any:
        return getattr(object.__getattribute__(self, "_treeship_backend"), name)

    def __setattr__(self, name: str, value: Any) -> None:
        setattr(object.__getattribute__(self, "_treeship_backend"), name, value)

    @property
    def wrapped(self) -> Any:
        return object.__getattribute__(self, "_treeship_backend")

    async def checkout_handoff(self, session: Any, cart: Any) -> Any:
        backend = object.__getattribute__(self, "_treeship_backend")
        result = await backend.checkout_handoff(session, cart)
        try:
            receipts = self._receipts_for(session)
            if receipts is not None:
                artifact_id = await sign_handoff(receipts, cart, result)
                if artifact_id is not None:
                    object.__getattribute__(self, "handoffs").append(artifact_id)
        except Exception as err:  # noqa: BLE001 -- the hand-off must reach the customer
            logger.warning("treeship checkout hand-off not receipted: %s", err)
        return result

    def _receipts_for(self, session: Any) -> TreeshipReceipts | None:
        recorder = object.__getattribute__(self, "_treeship_recorder")
        if recorder is not None:
            return recorder(session)
        return TreeshipReceipts.for_session(_get(session, "session_id"))


def receipted_backend(
    backend: Any,
    *,
    recorder: Callable[[Any], TreeshipReceipts | None] | None = None,
) -> ReceiptedBackend:
    """Wrap ``backend`` so ``checkout_handoff`` signs the hand-off. Idempotent."""
    if isinstance(backend, ReceiptedBackend):
        return backend
    return ReceiptedBackend(backend, recorder=recorder)


async def sign_handoff(receipts: TreeshipReceipts, cart: Any, handoffs: Sequence[Any] | None) -> str | None:
    """Sign the hand-off receipt on ``receipts``' chain. Returns its id, or
    ``None`` when recording is off or the write failed (counted in
    ``receipts.dropped``, like any other receipt)."""
    meta: dict[str, Any] = {
        "cart_digest": cart_digest(cart),
        "item_count": int(_get(cart, "item_count") or 0),
        "subtotal": _get(cart, "subtotal"),
        "currency": _get(cart, "currency"),
        "handoffs": [
            {
                "url_digest": text_digest(str(_get(h, "url") or "")),
                **({"seller": _get(h, "seller")} if _get(h, "seller") else {}),
            }
            for h in (handoffs or [])
        ],
        "session_tag": receipts.session_tag,
    }
    return await receipts.attest(HANDOFF_ACTION, meta)


async def order_placed(
    receipts: TreeshipReceipts,
    *,
    order_ref: str,
    amount: float | None,
    currency: str | None,
    handoff_id: str | None = None,
) -> str | None:
    """The host's side of the seam: the placed order, chained onto the chain
    after the hand-off and naming it.

    The order is signed onto the recorder's current head, which sits after
    the hand-off receipt (the checkout result follows the hand-off on the
    same chain). It is *not* signed onto the hand-off itself: that would
    fork the chain, and the checkout result would branch off the path the
    session seals, so it would be missing from the package (QA finding
    TS-002 on 0.31.0). ``meta.handoff`` names the hand-off receipt
    explicitly, so a holder of the cart still finds the order that followed
    it in one step. ``handoff_id`` defaults to the most recent hand-off
    this recorder wrote; pass it when the host places orders asynchronously.
    The order reference is digested, never written: it is the customer's
    lookup key on the host, and the receipt only needs to let a holder of
    it check.
    """
    handoff = handoff_id or receipts.last_handoff
    if handoff is None:
        logger.warning(
            "treeship order receipt has no hand-off to name; writing it on the "
            "session chain without one. Wrap the backend with receipted_backend() so the "
            "cart that went to checkout is signed first."
        )
    meta: dict[str, Any] = {
        "order_ref_digest": text_digest(str(order_ref)),
        "amount": amount,
        "currency": currency,
        "handoff_recorded": handoff is not None,
        "session_tag": receipts.session_tag,
    }
    if handoff is not None:
        meta["handoff"] = handoff
    # Chain onto the head (never fork), unless the caller names a hand-off
    # that is not on this recorder's chain at all (an asynchronous host
    # with its own recorder), in which case it is the only link we have.
    parent = receipts.head if receipts.head is not None else handoff
    return await receipts.attest(ORDER_ACTION, meta, parent=parent)


def session_tag_of(session: Any) -> str:
    """The tag a wrapped backend looks a session's recorder up by."""
    return _session_tag(_get(session, "session_id"))
