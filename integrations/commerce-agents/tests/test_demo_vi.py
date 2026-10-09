"""The retail-mock wallet demo: a real mandate, a real cart, a signed Layer 3 pair.

Runs ``python -m treeship_commerce.demo_vi`` against the reference SDK and the
retail mock. The issuer key is the SDK's published demo key. The payment
instrument is a demo token. Nothing here charges a card.
"""

from __future__ import annotations

import json

import pytest

from .conftest import BIN, needs_cli

pytestmark = needs_cli

pytest.importorskip("verifiable_intent")
pytest.importorskip("shopping_agent_sdk")


async def test_demo_signs_layer3_for_the_tent_and_verifies(tmp_path):
    from treeship_commerce.demo_vi import run

    assert await run(tmp_path, BIN) == 0
    summary = json.loads((tmp_path / "vi-out" / "summary.json").read_text())
    assert summary["status"] == "ok"
    assert summary["attestation"]["recorded"] is True
    assert summary["attestation"]["reaches_session_root"] is True
    checked = set(summary["constraints"]["checked"])
    assert {
        "mandate.payment.amount_range",
        "mandate.payment.allowed_payees",
        "mandate.checkout.allowed_merchants",
        "mandate.checkout.line_items",
    } <= checked
    assert summary["constraints"]["skipped"] == []
    for name in ("l3a.sdjwt", "l3b.sdjwt", "l2-payment.sdjwt", "l2-checkout.sdjwt", "attestation.json"):
        assert (tmp_path / "vi-out" / name).is_file(), name
