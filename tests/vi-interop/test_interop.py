"""Interop with the Verifiable Intent reference SDK, both directions.

The reference (agent-intent/verifiable-intent, pinned in CI) issues the L1
and L2 with its own deterministic demo keys, binding a key `treeship vi
keygen` produced. `treeship vi attest` signs the Layer 3 pair. Then:

  1. the reference's `verify_chain` and `check_constraints` accept what
     treeship signed, and read past the `agent_attestation` claim as the
     spec requires of an unknown scheme;
  2. `treeship vi verify` accepts what the reference issued;
  3. a request outside the mandate is refused before anything is signed;
  4. one edited byte fails on both verifiers.

Run locally:
    pip install -e /path/to/verifiable-intent
    TREESHIP_BIN=target/debug/treeship python -m pytest -q tests/vi-interop
"""

from __future__ import annotations

import json
import os
import subprocess
import time
import uuid
from pathlib import Path

import pytest

vi = pytest.importorskip("verifiable_intent")
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402

from verifiable_intent.crypto.disclosure import hash_bytes, hash_disclosure  # noqa: E402
from verifiable_intent.crypto.sd_jwt import decode_sd_jwt, resolve_disclosures  # noqa: E402
from verifiable_intent.crypto.signing import _jwt_encode, public_key_to_jwk  # noqa: E402
from verifiable_intent.issuance.issuer import create_layer1  # noqa: E402
from verifiable_intent.issuance.user import create_layer2_autonomous  # noqa: E402
from verifiable_intent.models.constraints import (  # noqa: E402
    AllowedMerchantConstraint,
    AllowedPayeeConstraint,
    CheckoutLineItemsConstraint,
    PaymentAmountConstraint,
)
from verifiable_intent.models.issuer_credential import IssuerCredential  # noqa: E402
from verifiable_intent.models.user_mandate import CheckoutMandate, MandateMode, PaymentMandate, UserMandate  # noqa: E402
from verifiable_intent.verification.chain import verify_chain  # noqa: E402
from verifiable_intent.verification.constraint_checker import check_constraints  # noqa: E402

BIN = os.environ.get("TREESHIP_BIN", "treeship")
MERCHANTS = [{"id": "merchant-uuid-1", "name": "Tennis Warehouse", "website": "https://tennis-warehouse.com"}]
ITEMS = [{"id": "BAB86345", "title": "Babolat Pure Aero Tennis Racket"}, {"id": "HEA23102", "title": "Head Graphene 360 Speed"}]
INSTRUMENT = {"type": "mastercard.srcDigitalCard", "id": "f199c3dd-7106-478b-9b5f-7af9ca725170", "description": "Mastercard **** 1234"}
PRICE = 27999


class Ship:
    def __init__(self, root: Path):
        self.root = root
        self.config = root / ".treeship" / "config.json"
        self.env = {**os.environ, "HOME": str(root), "TREESHIP_ALLOW_INSECURE_KEY_PERMS": "1"}
        self.run("init", "--name", "vi-interop")

    def run(self, *args: str, check: bool = True) -> subprocess.CompletedProcess:
        p = subprocess.run([BIN, *args, "--config", str(self.config)], cwd=self.root, env=self.env, capture_output=True, text=True)
        if check and p.returncode != 0:
            raise AssertionError(f"treeship {' '.join(args)} failed ({p.returncode}):\n{p.stdout}\n{p.stderr}")
        return p

    def json(self, *args: str) -> dict:
        return json.loads(self.run(*args, "--format", "json").stdout)


@pytest.fixture
def ship(tmp_path: Path) -> Ship:
    return Ship(tmp_path)


def _keys(d_int: int):
    return ec.derive_private_key(d_int, ec.SECP256R1())


def issue_l1_l2(agent_public_jwk: dict, agent_kid: str):
    """The reference issues L1 and L2 with its demo issuer/user keys, binding the treeship-made agent key."""
    issuer = _keys(0x1A2B3C4D5E6F708192A3B4C5D6E7F80112233445566778899AABBCCDDEEFF01)
    user = _keys(0x2B3C4D5E6F708192A3B4C5D6E7F80112233445566778899AABBCCDDEEFF0102)
    merchant = _keys(0x4D5E6F708192A3B4C5D6E7F80112233445566778899AABBCCDDEEFF01020304)
    now = int(time.time())
    l1 = create_layer1(
        IssuerCredential(iss="https://www.mastercard.com", sub="user-alice-001", iat=now, exp=now + 86400, aud="https://wallet.example.com",
                         cnf_jwk=public_key_to_jwk(user), email="alice@example.com", pan_last_four="1234", scheme="Mastercard"),
        issuer,
    )
    jwk = {k: v for k, v in agent_public_jwk.items() if k != "kid"}
    mandate = UserMandate(
        nonce=str(uuid.uuid4()), aud="https://agent.example", iat=now, iss="https://wallet.example.com", exp=now + 86400,
        mode=MandateMode.AUTONOMOUS, sd_hash=hash_bytes(l1.serialize().encode("ascii")), prompt_summary="Buy a Babolat tennis racket under $400",
        checkout_mandate=CheckoutMandate(vct="mandate.checkout.open.1", cnf_jwk=jwk, cnf_kid=agent_kid,
                                         constraints=[AllowedMerchantConstraint(allowed=MERCHANTS), CheckoutLineItemsConstraint(items=[{"id": "line-item-1", "acceptable_items": ITEMS, "quantity": 1}])]),
        payment_mandate=PaymentMandate(vct="mandate.payment.open.1", cnf_jwk=jwk, cnf_kid=agent_kid, payment_instrument=INSTRUMENT,
                                       constraints=[PaymentAmountConstraint(currency="USD", min=10000, max=40000), AllowedPayeeConstraint(allowed=MERCHANTS)]),
        merchants=MERCHANTS, acceptable_items=ITEMS,
    )
    l2 = create_layer2_autonomous(mandate, user)
    checkout_jwt = _jwt_encode({"alg": "ES256", "typ": "JWT"}, {"merchant_id": "merchant-uuid-1", "items": [{"sku": "BAB86345", "quantity": 1}], "total": PRICE, "iat": now}, merchant)
    return l1, l2, checkout_jwt, issuer.public_key()


PURCHASE = ["--mandate", "l2.sdjwt", "--merchant", "merchant-uuid-1", "--item", "BAB86345", "--amount", str(PRICE), "--currency", "USD"]
AUD = ["--aud-network", "https://www.mastercard.com", "--aud-merchant", "https://tennis-warehouse.com", "--iss", "https://agent.example.com"]


def prepare(ship: Ship):
    key = ship.json("vi", "keygen", "--label", "interop")
    l1, l2, checkout_jwt, issuer_pub = issue_l1_l2(key["public_jwk"], key["kid"])
    (ship.root / "l1.sdjwt").write_text(l1.serialize())
    (ship.root / "l2.sdjwt").write_text(l2.serialize())
    (ship.root / "checkout.jwt").write_text(checkout_jwt)
    (ship.root / "issuer.jwk").write_text(json.dumps(public_key_to_jwk(issuer_pub)))
    ship.run("session", "start", "--name", "vi-interop", "--actor", "agent://shopping")
    root = ship.json("session", "status")["root_artifact_id"]
    ship.json("attest", "action", "--actor", "agent://shopping", "--action", "commerce.checkout.handoff", "--parent", root)
    return l1, l2, checkout_jwt, issuer_pub


def test_reference_verifier_accepts_what_treeship_signed(ship: Ship):
    l1, l2, checkout_jwt, issuer_pub = prepare(ship)
    summary = ship.json("vi", "attest", *PURCHASE, "--checkout-jwt", "checkout.jwt", *AUD, "--out", "vi-out")
    assert summary["status"] == "ok"
    out = ship.root / "vi-out"
    l3a = decode_sd_jwt((out / "l3a.sdjwt").read_text())
    l3b = decode_sd_jwt((out / "l3b.sdjwt").read_text())
    r = verify_chain(
        decode_sd_jwt(l1.serialize()), decode_sd_jwt(l2.serialize()), l3_payment=l3a, l3_checkout=l3b, issuer_public_key=issuer_pub,
        l1_serialized=l1.serialize(), l2_serialized=l2.serialize(),
        l2_payment_serialized=(out / "l2-payment.sdjwt").read_text(), l2_checkout_serialized=(out / "l2-checkout.sdjwt").read_text(),
        expected_l3_payment_aud="https://www.mastercard.com", expected_l3_checkout_aud="https://tennis-warehouse.com",
    )
    assert r.valid, r.errors
    assert "l3_cross_reference" in r.checks_performed
    # The spec's unknown-scheme rule: the claim is there, and it was ignored.
    assert r.l3_checkout_claims["agent_attestation"]["type"] == "treeship.receipt-chain.v1"
    assert r.l3_payment_claims["agent_attestation"]["value"]["artifact_id"] == summary["attestation"]["artifact_id"]

    # The network's constraint check.
    l2_claims = resolve_disclosures(decode_sd_jwt(l2.serialize()))
    pay_constraints = next(d for d in l2_claims["delegate_payload"] if isinstance(d, dict) and d.get("vct") == "mandate.payment.open.1")["constraints"]
    fulfillment = next(d for d in r.l3_payment_claims["delegate_payload"] if isinstance(d, dict) and d.get("vct") == "mandate.payment.1")
    disc = {hash_disclosure(s): v for s, v in zip(l2.disclosures, l2.disclosure_values)}
    for c in pay_constraints:
        if c.get("type") == "mandate.payment.allowed_payees":
            fulfillment["allowed_merchants"] = [disc[ref["..."]][-1] for ref in c["allowed"] if ref.get("...") in disc]
    cr = check_constraints(pay_constraints, fulfillment)
    assert cr.satisfied, cr.violations
    assert fulfillment["payment_instrument"]["id"] == INSTRUMENT["id"]
    assert fulfillment["transaction_id"] == hash_bytes(checkout_jwt.encode("ascii"))


def test_treeship_verifies_what_the_reference_issued_and_checks_its_own_chain(ship: Ship):
    prepare(ship)
    ship.json("vi", "attest", *PURCHASE, "--checkout-jwt", "checkout.jwt", *AUD, "--out", "vi-out")
    r = ship.json("vi", "verify", "--mandate", "l2.sdjwt", "--l3a", "vi-out/l3a.sdjwt", "--l3b", "vi-out/l3b.sdjwt",
                  "--l2-payment", "vi-out/l2-payment.sdjwt", "--l2-checkout", "vi-out/l2-checkout.sdjwt",
                  "--l1", "l1.sdjwt", "--issuer-jwk", "issuer.jwk", "--local", "--require-attestation")
    assert r["outcome"] == "pass", [c for c in r["checks"] if not c["pass"]]
    names = {c["name"] for c in r["checks"]}
    assert {"l1_signature", "l2_signature", "l2_sd_hash", "l3a_signature", "l3b_signature", "l3_cross_reference", "local_checkpoint"} <= names
    assert r["attestation"]["chain_length"] == 2


def test_outside_the_mandate_is_refused_before_signing(ship: Ship):
    prepare(ship)
    before = ship.json("session", "status")["receipts"]
    p = ship.run("vi", "attest", "--mandate", "l2.sdjwt", "--merchant", "merchant-uuid-1", "--item", "BAB86345", "--amount", "40001",
                 "--checkout-jwt", "checkout.jwt", *AUD, "--out", "vi-bad", check=False)
    assert p.returncode == 1 and "refused" in p.stderr, p.stderr
    assert not (ship.root / "vi-bad").exists()
    assert ship.json("session", "status")["receipts"] == before
    p = ship.run("vi", "check", "--mandate", "l2.sdjwt", "--merchant", "merchant-uuid-1", "--item", "ZX-9999", "--amount", "100", check=False)
    assert p.returncode == 1


def test_one_edited_byte_fails_on_both_verifiers(ship: Ship):
    l1, l2, _, issuer_pub = prepare(ship)
    ship.json("vi", "attest", *PURCHASE, "--checkout-jwt", "checkout.jwt", *AUD, "--out", "vi-out")
    out = ship.root / "vi-out"
    ser = (out / "l3b.sdjwt").read_text()
    jwt, rest = ser.split("~", 1)
    h, p, s = jwt.split(".")
    # Edit one claim inside the signed payload (a well-formed credential with
    # a broken signature, which is what a real edit produces).
    from verifiable_intent.crypto.signing import _b64url_decode, _b64url_encode
    payload = json.loads(_b64url_decode(p))
    payload["aud"] = "https://evil.example"
    p2 = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    tampered = f"{h}.{p2}.{s}~{rest}"
    (ship.root / "l3b-tampered.sdjwt").write_text(tampered)
    r = verify_chain(decode_sd_jwt(l1.serialize()), decode_sd_jwt(l2.serialize()), l3_checkout=decode_sd_jwt(tampered), issuer_public_key=issuer_pub,
                     l1_serialized=l1.serialize(), l2_serialized=l2.serialize(), l2_checkout_serialized=(out / "l2-checkout.sdjwt").read_text())
    assert not r.valid
    pr = ship.run("vi", "verify", "--mandate", "l2.sdjwt", "--l3b", "l3b-tampered.sdjwt", "--l2-checkout", "vi-out/l2-checkout.sdjwt", check=False)
    assert pr.returncode == 1
