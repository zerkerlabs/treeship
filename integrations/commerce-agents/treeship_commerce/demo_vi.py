"""Commerce blueprint, a wallet mandate, and a Verifiable Intent credential.

    TREESHIP_BIN=/path/to/treeship python -m treeship_commerce.demo_vi

Drives Anthropic's shopping executor over the retail mock, the same path as
``python -m treeship_commerce.demo``. Before the agent may buy, a local
wallet (``treeship_commerce.wallet``) issues a Layer 2 mandate bound to the
key ``treeship vi keygen`` just minted. At checkout hand-off, ``treeship vi
attest`` signs the Layer 3 pair. The network's half and the merchant's half
are different disclosures of that mandate. ``treeship vi verify --local``
then checks the credential and the receipt chain it names, including the
add the provenance gate refused.

No card is charged. The issuer key is the reference SDK's demo key. The
payment instrument is a demo token. A live Mastercard authorization is the
network's step after it accepts L3a, and this process does not take it.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import os
import sys
import tempfile
import uuid
from pathlib import Path

from treeship_sdk import Treeship, TreeshipError

from . import TreeshipReceipts, attach, order_placed, receipted, receipted_backend
from .lifecycle import close_session, open_demo_session
from .vi import attest_at_handoff, vi_verify
from .wallet import issue_mandate

ACTOR = "agent://shopping"
MERCHANT = {"id": "acme-retail", "name": "ACME", "website": "https://acme.example"}
AUD_NETWORK = "https://www.mastercard.com"


def _executor(session_id: str):
    try:
        from commerce_common.memory import InMemoryMemoryStore
        from commerce_common.skills import SkillRegistry
        from shopping_agent import ShoppingAgentConfig, ShoppingSessionContext, ShoppingSessionState
        from shopping_agent.executor import ShoppingToolExecutor, build_memory
        from shopping_agent.types import CheckoutHandoff
        from shopping_agent_sdk import load_mock_backend
    except ImportError as err:
        sys.exit(
            "commerce-agents is not installed "
            f"({err}). Clone anthropics/commerce-agents and pip install -r requirements.txt"
        )

    base = load_mock_backend()

    class Hosted(type(base)):
        async def checkout_handoff(self, session, cart):
            return [CheckoutHandoff(url=f"https://pay.acme.example/c/{session.session_id}")]

    config = ShoppingAgentConfig(brand_name="ACME", assistant_name="Scout")
    cls = receipted(ShoppingToolExecutor)
    return cls(
        backend=receipted_backend(Hosted()),
        config=config,
        skills=SkillRegistry([]),
        session=ShoppingSessionContext(session_id=session_id, user_id="demo-user"),
        state=ShoppingSessionState(),
        memory=build_memory(config, InMemoryMemoryStore()),
        inline_context=True,
    )


def _seen(executor) -> dict:
    """Provenance map the shopping agent keeps. Keys are product ids.

    ``remember()`` reinserts a product at the end when details are fetched,
    so "the first key" after ``get_product_details`` is a different product
    than the one just opened. Look up by id.
    """
    seen = getattr(executor._state, "seen_products", None) or {}
    if not isinstance(seen, dict) or not seen:
        raise SystemExit("the retail mock returned nothing for 'tent'")
    return seen


def _describe(executor, product_id: str) -> tuple[str, int]:
    product = _seen(executor)[product_id]
    title = getattr(product, "title", None) or product_id
    price = getattr(product, "price", None)
    if price is None:
        raise SystemExit(f"{product_id} has no price")
    return str(title), int(round(float(price) * 100))


async def _cart_lines(executor) -> list[dict]:
    """Lines in the storefront cart. The cart lives on the backend, not on session state."""
    cart = await executor._backend.get_cart(executor._session)
    lines = []
    for item in getattr(cart, "items", None) or []:
        price = getattr(item, "price", None)
        if price is None:
            raise SystemExit(f"cart line {getattr(item, 'product_id', '?')} has no price")
        qty = int(getattr(item, "quantity", 1) or 1)
        lines.append(
            {
                "id": str(item.product_id),
                "title": str(getattr(item, "title", None) or item.product_id),
                "quantity": qty,
                "unit_minor": int(round(float(price) * 100)),
            }
        )
    return lines


async def run(root: Path, binary: str) -> int:
    config = root / ".treeship" / "config.json"
    # Separate bindings. A single combined assignment has corrupted a real
    # ~/.treeship before.
    home = str(root)
    config_path = str(config)
    iso = {"HOME": home, "TREESHIP_CONFIG": config_path, "TREESHIP_ALLOW_INSECURE_KEY_PERMS": "1"}
    env = {**os.environ, **iso}
    import subprocess

    init = subprocess.run(
        [binary, "init", "--name", "vi-commerce-demo", "--config", config_path],
        cwd=root,
        env=env,
        capture_output=True,
        text=True,
    )
    if init.returncode != 0 and not config.is_file():
        sys.exit(init.stderr.strip() or init.stdout.strip() or "treeship init failed")

    ts = Treeship(cli_path=binary, env=iso, cwd=root)
    commerce_session = f"demo-{uuid.uuid4().hex}"
    session_root = open_demo_session(ts, name="commerce:vi-demo", actor=ACTOR, env=iso, cwd=root)
    executor = attach(
        _executor(commerce_session),
        TreeshipReceipts(ts, actor=ACTOR, session_id=commerce_session, parent_id=session_root),
    )
    receipts: TreeshipReceipts = executor.treeship_receipts

    from .lifecycle import _run_json

    key = _run_json(ts, ["vi", "keygen", "--label", "shopping-agent"], env=iso, cwd=root)
    print("agent key         ", key["kid"])
    print("session root      ", session_root)

    async def call(name: str, tool_input: dict) -> None:
        before = len(receipts.recorded)
        outcome = await executor.execute(name, tool_input)
        status = "blocked:" + outcome.blocked if outcome.blocked else ("error" if outcome.is_error else "ok")
        ids = " ".join(receipts.recorded[before:]) or "(no receipt)"
        print(f"  {name:<22} {status:<22} {ids}")
        return outcome

    print("tool calls")
    await call("search_products", {"query": "tent"})
    pid = next(iter(_seen(executor)))
    await call("get_product_details", {"product_id": pid})
    title, unit = _describe(executor, pid)
    ceiling = max(unit * 2, unit, 1)
    mandate = issue_mandate(
        agent_public_jwk=key["public_jwk"],
        agent_kid=key["kid"],
        merchant=MERCHANT,
        items=[{"id": pid, "title": title, "quantity": 2}],
        amount_max_minor=ceiling,
        prompt=f"Buy {title} from ACME, at most {ceiling / 100:.2f} USD",
    )
    print(f"wallet            {title} ({pid}) · ceiling {ceiling / 100:.2f} {mandate.currency}")
    print(f"issuer            {mandate.issuer_public_jwk['crv']} demo key · not a Mastercard issuer")
    print(f"instrument        {mandate.instrument['description']}")

    await call("add_to_cart", {"product_id": pid, "quantity": 1})
    await call("add_to_cart", {"product_id": "p-not-from-this-session", "quantity": 1})
    outcome = await call("checkout", {"note": "Ready when you are."})
    if getattr(outcome, "refused", False) or getattr(outcome, "is_error", False):
        print("checkout did not hand off; stopping")
        return 1

    lines = await _cart_lines(executor)
    if not lines:
        raise SystemExit("checkout handed off an empty cart")
    total = sum(line["unit_minor"] * line["quantity"] for line in lines)
    checkout_jwt = mandate.checkout_jwt(items=lines, total_minor=total)
    out = root / "vi-out"
    summary = attest_at_handoff(
        ts,
        receipts,
        mandate=mandate.l2,
        checkout_jwt=checkout_jwt,
        merchant=MERCHANT["id"],
        items=[(line["id"], line["quantity"]) for line in lines],
        amount_minor=total,
        currency="USD",
        aud_network=AUD_NETWORK,
        aud_merchant=MERCHANT["website"],
        iss="https://agent.example",
        out=out,
        workdir=root,
        env=iso,
    )
    att = summary["attestation"]
    print(f"L3 attest         {att['artifact_id']}  chain_head={att['chain_head']}")
    print(f"  network (L3a)   {out / 'l3a.sdjwt'}")
    print(f"  merchant (L3b)  {out / 'l3b.sdjwt'}")
    order = await order_placed(receipts, order_ref="ord_demo_vi", amount=total / 100, currency="USD", handoff_id=att["artifact_id"])
    print(f"order             {order}  chained onto the attestation")

    report = vi_verify(
        ts,
        mandate=mandate.l2,
        out=out,
        l1=mandate.l1,
        issuer_jwk=mandate.issuer_public_jwk,
        workdir=root,
        env=iso,
    )
    print(f"verify            {report.get('outcome')}")
    if report.get("outcome") != "pass":
        failed = [c for c in report.get("checks", []) if not c.get("pass")]
        print(failed)
        return 1

    tag = hashlib.sha256(commerce_session.encode()).hexdigest()[:12]
    sealed = close_session(
        ts,
        summary=(
            f"VI demo: catalog {pid}, one add, one provenance refusal, "
            f"mandate ceiling {ceiling} minor, L3 signed, no card charged. session tag {tag}."
        ),
        headline="Commerce blueprint with a Verifiable Intent mandate",
        env=iso,
        cwd=root,
    )
    print(f"package           {sealed.get('package')}")
    print("no card charged. L3a is what a payment network would authorize next.")
    return 0 if receipts.dropped == 0 else 2


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=None, help="isolated ship directory (default: a temp dir)")
    args = parser.parse_args()
    binary = os.environ.get("TREESHIP_BIN", "treeship")
    if args.root:
        args.root.mkdir(parents=True, exist_ok=True)
        code = asyncio.run(run(args.root, binary))
    else:
        with tempfile.TemporaryDirectory(prefix="ts-vi-commerce-") as tmp:
            code = asyncio.run(run(Path(tmp), binary))
    raise SystemExit(code)


if __name__ == "__main__":
    try:
        main()
    except TreeshipError as err:
        sys.exit(str(err))
