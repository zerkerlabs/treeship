"""A local HTTP 402 under one budget. No network rail, no card, no settlement."""

from __future__ import annotations

import base64
import json

from .conftest import BIN, needs_cli

pytestmark = needs_cli


def _statement(ship_root, artifact_id: str) -> dict:
    path = ship_root / ".treeship" / "artifacts" / f"{artifact_id}.json"
    record = json.loads(path.read_text())
    payload = record["envelope"]["payload"]
    padded = payload + "=" * (-len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(padded))


async def test_demo_signs_three_vouchers_and_withholds_the_fourth(tmp_path):
    from treeship_commerce.demo_402 import run

    assert await run(tmp_path, BIN) == 0
    summary = json.loads((tmp_path / "402-out" / "summary.json").read_text())
    assert summary["status"] == "ok"
    assert summary["scheme"] == "local.402.v1"
    assert summary["budget_minor"] == 500
    assert summary["spent_minor"] == 450
    assert summary["settlement"] == "not performed"
    assert summary["currency"] == "USD"
    assert [v["amount_minor"] for v in summary["vouchers"]] == [150, 200, 100]
    assert [d["resource"] for d in summary["deliveries"]] == [
        "social-research-1",
        "campaign-image-2",
        "campaign-image-3",
    ]
    assert summary["withheld"]["voucher_signed"] is False
    assert summary["withheld"]["amount_minor"] == 100

    for voucher in summary["vouchers"]:
        statement = _statement(tmp_path, voucher["artifact_id"])
        assert statement["action"] == "payment.voucher.sign"
        meta = statement["meta"]
        assert meta["amount_minor"] == voucher["amount_minor"]
        assert meta["payee"] == voucher["payee"]
        assert meta["settlement"] == "not performed"
        assert meta["spent_after"] <= summary["budget_minor"]

    withheld = _statement(tmp_path, summary["withheld"]["artifact_id"])
    assert withheld["action"] == "payment.voucher.withheld"
    assert withheld["meta"]["voucher_signed"] is False
    assert withheld["meta"]["reason"] == "amount would exceed the approved budget"
    assert withheld["meta"]["spent_minor"] + withheld["meta"]["amount_minor"] > summary["budget_minor"]

    budget = _statement(tmp_path, summary["budget"])
    assert budget["action"] == "payment.budget.approved"
    assert budget["meta"]["amount_minor"] == 500
    assert budget["meta"]["actor_binding"] == "asserted"
    assert budget["meta"]["principal"] == "principal://campaign"
