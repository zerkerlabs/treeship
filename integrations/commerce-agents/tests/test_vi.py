"""Verifiable Intent at hand-off: the Layer 3 pair names the hand-off receipt
as its chain head, the host's order chains onto the attestation, and a cart
outside the mandate is refused with nothing written.

The Layer 1 / Layer 2 fixture was issued by the reference SDK's deterministic
demo keys (see packages/core/tests/fixtures/vi/); the agent key it delegates
to is imported into the test ship.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from treeship_sdk import TreeshipError

from treeship_commerce import TreeshipReceipts, attest_at_handoff, order_placed, receipted_backend, vi_check, vi_verify

from .conftest import Ship, needs_cli
from .test_checkout import _fill_cart, _hosted_backend, _shopping_executor

pytestmark = needs_cli

FIXTURE = json.loads((Path(__file__).parent / "fixtures" / "vi-reference-v0.1.json").read_text())
PURCHASE = dict(merchant="merchant-uuid-1", items=[("BAB86345", 1)], amount_minor=27999, currency="USD")
AUD = dict(aud_network="https://www.mastercard.com", aud_merchant="https://tennis-warehouse.com")


def _import_agent_key(ship: Ship) -> None:
    jwk = ship.root / "agent.jwk"
    jwk.write_text(json.dumps(FIXTURE["agent_private_jwk"]))
    out = ship.cli_json("vi", "keys", "import", "--jwk", str(jwk))
    assert out["kid"] == "agent-key-1"


async def _handed_off(ship: Ship):
    backend = receipted_backend(_hosted_backend())
    executor = _shopping_executor(ship, backend)
    await _fill_cart(executor)
    outcome = await executor.execute("checkout", {"note": "Ready when you are."})
    assert not outcome.refused, outcome.result_text
    receipts: TreeshipReceipts = executor.treeship_receipts
    assert receipts.last_handoff == backend.handoffs[0]
    return executor, receipts


async def test_the_credential_names_the_handoff_and_the_order_chains_onto_it(ship: Ship):
    _import_agent_key(ship)
    _, receipts = await _handed_off(ship)
    handoff = receipts.last_handoff

    summary = attest_at_handoff(
        ship.client, receipts, mandate=FIXTURE["l2"], checkout_jwt=FIXTURE["checkout_jwt"],
        **PURCHASE, **AUD, iss="https://agent.example.com", out=ship.root / "vi-out", workdir=ship.root, env=ship.env,
    )
    att = summary["attestation"]
    assert att["chain_head"] == handoff, "the credential names the hand-off receipt"
    assert att["recorded"] is True
    assert att["reaches_session_root"] is True
    assert att["checkpoint"].startswith("mroot_")
    for name in ("l3a.sdjwt", "l3b.sdjwt", "l2-payment.sdjwt", "l2-checkout.sdjwt", "attestation.json"):
        assert (ship.root / "vi-out" / name).exists(), name

    # The attestation is a receipt on the chain, chained onto the hand-off,
    # and the recorder adopted it as its head.
    assert receipts.head == att["artifact_id"]
    statement = ship.artifacts()[att["artifact_id"]]["statement"]
    assert statement["action"] == "vi.l3.attested"
    assert statement["parentId"] == handoff
    assert statement["meta"]["transaction_id"] == summary["checkout_hash"]

    # The host's order chains onto the attestation, so the sealed session
    # reads: hand-off, credential, order.
    order = await order_placed(receipts, order_ref="ord_1", amount=279.99, currency="USD", handoff_id=att["artifact_id"])
    assert ship.artifacts()[order]["statement"]["parentId"] == att["artifact_id"]
    assert ship.cli_json("verify", order)["outcome"] == "pass"

    report = vi_verify(ship.client, mandate=FIXTURE["l2"], out=ship.root / "vi-out", l1=FIXTURE["l1"], issuer_jwk=FIXTURE["issuer_public_jwk"], workdir=ship.root, env=ship.env)
    assert report["outcome"] == "pass", [c for c in report["checks"] if not c["pass"]]
    assert report["attestation"]["chain_head"] == handoff


async def test_a_cart_outside_the_mandate_is_refused_with_nothing_written(ship: Ship):
    _import_agent_key(ship)
    _, receipts = await _handed_off(ship)
    head_before = receipts.head
    n_before = len(ship.artifacts())
    with pytest.raises(TreeshipError, match="refused"):
        attest_at_handoff(
            ship.client, receipts, mandate=FIXTURE["l2"], checkout_jwt=FIXTURE["checkout_jwt"],
            merchant="merchant-uuid-1", items=[("BAB86345", 1)], amount_minor=40001, currency="USD",
            **AUD, out=ship.root / "vi-bad", workdir=ship.root, env=ship.env,
        )
    assert not (ship.root / "vi-bad").exists()
    assert receipts.head == head_before
    assert len(ship.artifacts()) == n_before, "a refused attest signs nothing"
    with pytest.raises(TreeshipError):
        vi_check(ship.client, mandate=FIXTURE["l2"], merchant="merchant-uuid-1", items=[("ZX-9999", 1)], amount_minor=100, workdir=ship.root, env=ship.env)
    ok = vi_check(ship.client, mandate=FIXTURE["l2"], **PURCHASE, workdir=ship.root, env=ship.env)
    assert ok["satisfied"] is True
