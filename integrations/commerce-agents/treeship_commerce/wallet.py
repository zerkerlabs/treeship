"""A local wallet and issuer for a Verifiable Intent mandate.

This is the user's side of the draft at verifiableintent.dev: an issuer
signs Layer 1, the wallet signs Layer 2, and the agent's key (minted by
``treeship vi keygen``) is what Layer 2 binds under ``cnf.jwk``. The
reference SDK (agent-intent/verifiable-intent) does the SD-JWT encoding.
The issuer key and the user key are that SDK's published demo scalars, so
a verifier with those public keys can check the chain. They are not
Mastercard's keys, and the payment instrument is a demo token. Nothing
here authorizes a charge on a card network.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass
from typing import Any

# The reference SDK's published demo scalars. Same ones tests/vi-interop uses.
_ISSUER_D = 0x1A2B3C4D5E6F708192A3B4C5D6E7F80112233445566778899AABBCCDDEEFF01
_USER_D = 0x2B3C4D5E6F708192A3B4C5D6E7F80112233445566778899AABBCCDDEEFF0102
_MERCHANT_D = 0x4D5E6F708192A3B4C5D6E7F80112233445566778899AABBCCDDEEFF01020304


@dataclass(frozen=True)
class Mandate:
    """What the wallet handed the agent, and what the merchant will sign."""

    l1: str
    l2: str
    issuer_public_jwk: dict[str, Any]
    merchant: dict[str, str]
    instrument: dict[str, str]
    amount_max_minor: int
    currency: str
    _merchant_key: Any
    _user_public: Any

    def checkout_jwt(self, *, items: list[dict[str, Any]], total_minor: int) -> str:
        """The merchant-signed checkout token for this cart.

        The token's bytes are what ``checkout_hash`` covers. The payload
        names the merchant id the mandate allowlist expects.
        """
        from verifiable_intent.crypto.signing import _jwt_encode

        now = int(time.time())
        lines = []
        for item in items:
            lines.append(
                {
                    "sku": item["id"],
                    "name": item.get("title") or item["id"],
                    "quantity": int(item["quantity"]),
                    "unitPrice": item.get("unit_minor", 0) / 100,
                }
            )
        payload = {
            "iss": self.merchant["website"],
            "sub": "cart_checkout",
            "iat": now,
            "exp": now + 3600,
            "id": self.merchant["id"],
            "merchant_id": self.merchant["id"],
            "cart": {
                "items": lines,
                "subTotal": {"amount": total_minor / 100, "currencyCode": self.currency},
            },
        }
        return _jwt_encode({"alg": "ES256", "typ": "JWT", "kid": "merchant-key-1"}, payload, self._merchant_key)


def issue_mandate(
    *,
    agent_public_jwk: dict[str, Any],
    agent_kid: str,
    merchant: dict[str, str],
    items: list[dict[str, Any]],
    amount_max_minor: int,
    currency: str = "USD",
    prompt: str,
) -> Mandate:
    """Issuer signs L1. Wallet signs L2 delegating to ``agent_kid``.

    ``items`` are ``{"id", "title"}`` the agent may buy. ``amount_max_minor``
    is the ceiling in ISO 4217 minor units. One line, quantity up to the
    caller's cap, encoded as a single ``mandate.checkout.line_items`` entry.
    """
    from cryptography.hazmat.primitives.asymmetric import ec

    from verifiable_intent.crypto.disclosure import hash_bytes
    from verifiable_intent.crypto.signing import public_key_to_jwk
    from verifiable_intent.issuance.issuer import create_layer1
    from verifiable_intent.issuance.user import create_layer2_autonomous
    from verifiable_intent.models.constraints import (
        AllowedMerchantConstraint,
        AllowedPayeeConstraint,
        CheckoutLineItemsConstraint,
        PaymentAmountConstraint,
    )
    from verifiable_intent.models.issuer_credential import IssuerCredential
    from verifiable_intent.models.user_mandate import CheckoutMandate, MandateMode, PaymentMandate, UserMandate

    def key(d: int):
        return ec.derive_private_key(d, ec.SECP256R1())

    issuer = key(_ISSUER_D)
    user = key(_USER_D)
    merchant_key = key(_MERCHANT_D)
    now = int(time.time())
    user_jwk = public_key_to_jwk(user)
    l1 = create_layer1(
        IssuerCredential(
            iss="https://issuer.demo.treeship.dev",
            sub="user-demo-001",
            iat=now,
            exp=now + 86400,
            aud="https://wallet.demo.treeship.dev",
            cnf_jwk=user_jwk,
            email="buyer@example.com",
            pan_last_four="1234",
            scheme="Mastercard",
        ),
        issuer,
    )
    agent_jwk = {k: v for k, v in agent_public_jwk.items() if k != "kid"}
    merchants = [merchant]
    acceptable = [{"id": item["id"], "title": item["title"]} for item in items]
    instrument = {
        "type": "mastercard.srcDigitalCard",
        "id": "demo-src-token-not-a-live-pan",
        "description": "Demo token · not a live card",
    }
    qty = max(int(item.get("quantity", 1)) for item in items) if items else 1
    mandate = UserMandate(
        nonce=str(uuid.uuid4()),
        aud="https://agent.example",
        iat=now,
        iss="https://wallet.demo.treeship.dev",
        exp=now + 86400,
        mode=MandateMode.AUTONOMOUS,
        sd_hash=hash_bytes(l1.serialize().encode("ascii")),
        prompt_summary=prompt,
        checkout_mandate=CheckoutMandate(
            vct="mandate.checkout.open.1",
            cnf_jwk=agent_jwk,
            cnf_kid=agent_kid,
            constraints=[
                AllowedMerchantConstraint(allowed=merchants),
                CheckoutLineItemsConstraint(
                    items=[{"id": "line-1", "acceptable_items": acceptable, "quantity": qty}],
                ),
            ],
        ),
        payment_mandate=PaymentMandate(
            vct="mandate.payment.open.1",
            cnf_jwk=agent_jwk,
            cnf_kid=agent_kid,
            payment_instrument=instrument,
            constraints=[
                PaymentAmountConstraint(currency=currency, min=1, max=int(amount_max_minor)),
                AllowedPayeeConstraint(allowed=merchants),
            ],
        ),
        merchants=merchants,
        acceptable_items=acceptable,
    )
    l2 = create_layer2_autonomous(mandate, user)
    return Mandate(
        l1=l1.serialize(),
        l2=l2.serialize(),
        issuer_public_jwk=public_key_to_jwk(issuer.public_key()),
        merchant=merchant,
        instrument=instrument,
        amount_max_minor=int(amount_max_minor),
        currency=currency,
        _merchant_key=merchant_key,
        _user_public=user.public_key(),
    )
