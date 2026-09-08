"""Verifiable Intent at checkout hand-off.

Anthropic's blueprint stops at ``backend.checkout_handoff``: the cart is
signed (see :mod:`treeship_commerce.checkout`) and a hosted checkout takes
over. Verifiable Intent (the Mastercard-maintained v0.1 draft) wants a chain
from the user's mandate to the transaction. ``treeship vi attest`` signs that
chain's Layer 3 pair with the spec's ``agent_attestation`` claim pointing at
the receipt chain; run at hand-off, the chain head it names is the hand-off
receipt, so the credential binds the cart that went to checkout.

    from treeship_commerce.vi import attest_at_handoff

    summary = attest_at_handoff(
        ts, receipts,
        mandate=l2_sdjwt, checkout_jwt=merchant_jwt,
        merchant="merchant-uuid-1", items=[("BAB86345", 1)],
        amount_minor=27999, currency="USD",
        aud_network="https://www.mastercard.com", aud_merchant="https://tennis-warehouse.com",
        out="./vi-out",
    )
    summary["attestation"]["chain_head"] == receipts.last_handoff   # True

Nothing here changes what the reference does. The mandate check happens
before anything is signed; a cart outside the mandate raises and writes
nothing. Requires treeship >= 0.31.
"""

from __future__ import annotations

import os
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from treeship_sdk import Treeship

from .lifecycle import _run_json
from .receipts import TreeshipReceipts

__all__ = ["attest_at_handoff", "vi_check", "vi_verify"]


def _write(dir_: Path, name: str, text: str) -> str:
    dir_.mkdir(parents=True, exist_ok=True)
    p = dir_ / name
    p.write_text(text)
    return str(p)


def _purchase_args(mandate_path: str, merchant: str, items: Sequence[tuple[str, int]], amount_minor: int, currency: str) -> list[str]:
    args = ["--mandate", mandate_path, "--merchant", merchant, "--amount", str(int(amount_minor)), "--currency", currency]
    for item_id, qty in items:
        args += ["--item", f"{item_id}:{int(qty)}"]
    return args


def vi_check(
    client: Treeship,
    *,
    mandate: str,
    merchant: str,
    items: Sequence[tuple[str, int]],
    amount_minor: int,
    currency: str = "USD",
    workdir: str | os.PathLike[str] | None = None,
    env: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Is this purchase inside the mandate? Returns the CLI's JSON; raises on a violation."""
    work = Path(workdir or ".")
    mandate_path = _write(work / ".vi", "l2.sdjwt", mandate)
    return _run_json(client, ["vi", "check", *_purchase_args(mandate_path, merchant, items, amount_minor, currency)], env=env, cwd=workdir)


def attest_at_handoff(
    client: Treeship,
    receipts: TreeshipReceipts,
    *,
    mandate: str,
    checkout_jwt: str,
    merchant: str,
    items: Sequence[tuple[str, int]],
    amount_minor: int,
    currency: str,
    aud_network: str,
    aud_merchant: str,
    out: str | os.PathLike[str],
    iss: str | None = None,
    exp_secs: int = 300,
    key: str | None = None,
    head: str | None = None,
    workdir: str | os.PathLike[str] | None = None,
    env: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Sign the Layer 3 pair for the cart that just went to checkout.

    ``head`` defaults to the recorder's most recent hand-off receipt, so the
    attestation names it as the chain head. Returns ``summary.json`` as a
    dict. Raises :class:`treeship_sdk.TreeshipError` when the purchase is
    outside the mandate (nothing is signed) or the CLI fails.
    """
    chain_head = head or receipts.last_handoff or receipts.head
    if chain_head is None:
        raise ValueError("no chain head: sign the hand-off first (receipted_backend) or pass head=")
    work = Path(workdir or ".")
    mandate_path = _write(work / ".vi", "l2.sdjwt", mandate)
    jwt_path = _write(work / ".vi", "checkout.jwt", checkout_jwt)
    args = [
        "vi", "attest",
        *_purchase_args(mandate_path, merchant, items, amount_minor, currency),
        "--checkout-jwt", jwt_path,
        "--aud-network", aud_network,
        "--aud-merchant", aud_merchant,
        "--exp-secs", str(int(exp_secs)),
        "--head", chain_head,
        "--actor", receipts.actor,
        "--out", str(out),
    ]
    if iss:
        args += ["--iss", iss]
    if key:
        args += ["--key", key]
    summary = _run_json(client, args, env=env, cwd=workdir)
    # The attestation is a receipt chained onto the hand-off; keep the
    # recorder's head current so the host's order chains onto it too.
    art = summary.get("attestation", {}).get("artifact_id")
    if art and summary.get("attestation", {}).get("recorded"):
        receipts.adopt(art)
    return summary


def vi_verify(
    client: Treeship,
    *,
    mandate: str,
    out: str | os.PathLike[str],
    l1: str | None = None,
    issuer_jwk: Mapping[str, Any] | None = None,
    local: bool = True,
    workdir: str | os.PathLike[str] | None = None,
    env: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Verify the pair ``attest_at_handoff`` wrote to ``out``. Returns the CLI's report; raises on failure."""
    import json

    work = Path(workdir or ".")
    out_p = Path(out)
    args = [
        "vi", "verify",
        "--mandate", _write(work / ".vi", "l2.sdjwt", mandate),
        "--l3a", str(out_p / "l3a.sdjwt"), "--l3b", str(out_p / "l3b.sdjwt"),
        "--l2-payment", str(out_p / "l2-payment.sdjwt"), "--l2-checkout", str(out_p / "l2-checkout.sdjwt"),
        "--require-attestation",
    ]
    if l1:
        args += ["--l1", _write(work / ".vi", "l1.sdjwt", l1)]
    if issuer_jwk:
        args += ["--issuer-jwk", _write(work / ".vi", "issuer.jwk", json.dumps(dict(issuer_jwk)))]
    if local:
        args.append("--local")
    return _run_json(client, args, env=env, cwd=workdir)
