#!/usr/bin/env python3
"""Reference verifier for a Treeship receipt triple — no Treeship code.

A Treeship signature is over the DSSE PAE (the exact bytes in the `message`
field), not the payload JSON. `treeship receipt export <id> --format json`
emits the {message, signature, public_key} triple in base64; this script
verifies it with an independent Ed25519 implementation, offline, so a
counterparty can confirm a receipt without trusting Treeship or any endpoint.

    treeship receipt export art_xxx --format json | python3 verify-receipt.py
    python3 verify-receipt.py triple.json

Exit 0 = valid, 1 = invalid, 2 = malformed input. Requires `cryptography`
(pip install cryptography). Copy this file freely — it is the reference a
partner runs.
"""
import base64
import json
import sys


def main() -> int:
    src = open(sys.argv[1]) if len(sys.argv) > 1 else sys.stdin
    try:
        t = json.load(src)
    except json.JSONDecodeError as e:
        print(f"input is not valid JSON: {e}", file=sys.stderr)
        return 2

    if t.get("algorithm") != "ed25519":
        print(f"unsupported algorithm: {t.get('algorithm')!r} (expected ed25519)", file=sys.stderr)
        return 2

    try:
        d = base64.b64decode
        message = d(t["message_b64"])       # the DSSE PAE — what was signed
        signature = d(t["signature_b64"])   # 64 bytes
        public_key = d(t["public_key_b64"]) # 32 bytes
    except (KeyError, ValueError) as e:
        print(f"triple is missing or malformed: {e}", file=sys.stderr)
        return 2

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature

    artifact = t.get("artifact_id", "<unknown>")
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
    except InvalidSignature:
        print(f"INVALID: signature does not verify for {artifact}", file=sys.stderr)
        return 1

    print(f"VALID: {artifact} verified offline (ed25519 over the DSSE PAE)")
    preview = message[:64].decode("utf-8", errors="replace")
    print(f"  signed message begins: {preview}...")
    return 0


if __name__ == "__main__":
    sys.exit(main())
