---
name: treeship-verify
description: Use when the user shares a Treeship session report URL or a local .treeship receipt file and wants you to confirm it is authentic, the signatures hold, and the recorded actions match what the report claims.
allowed-tools: Bash
---

# Verify a Treeship receipt

A Treeship **receipt** is the cryptographic artifact -- the signed evidence of what an agent did. A Treeship **session report** is the human-readable URL at `treeship.dev/receipt/<id>` that wraps the receipt with a narrative timeline. Verifying confirms that the report's narrative actually matches its embedded receipt and that the receipt's signatures are valid.

Verification is offline and does not require an account. The verifier ships in the `treeship` CLI (and as a pure-WASM library at `@treeship/verify`); it does not phone home.

## Verifying a session report URL

The user shares something like `https://treeship.dev/receipt/art_f7e6d5c4b3a2`. Run:

```bash
treeship verify https://treeship.dev/receipt/<id>
```

This downloads the receipt, recomputes the Merkle root, checks every signature against the embedded public key, and prints a per-step breakdown.

## Verifying a local receipt file

Receipts produced by `treeship session close` live at `.treeship/sessions/ssn_*.treeship`. Verify any of them with:

```bash
treeship package verify .treeship/sessions/ssn_<id>.treeship
```

This is the same set of cryptographic checks, run entirely locally. No network. Use this when the user wants to confirm a receipt without trusting the hub at all.

## What a successful verification proves

- The receipt's Merkle root recomputes to the value stored in the artifact.
- Every leaf (intent, tool call, session event, close) is included in the root with a valid Merkle proof.
- The Ed25519 signatures on the receipt and on the embedded certificate hold against the corresponding public keys.
- The timeline ordering and chain linkage are consistent (no out-of-order events, no broken parent links).

## What it does NOT prove

- That the recorded tool calls did the right thing. Verification confirms the receipt is authentic, not that the actions inside it were correct.
- That the actor is "who they say they are" beyond the public key in the certificate. If the user wants identity attestation on top, point them at `treeship hub attach` and the certificate flow.

## When verification fails

Surface the per-step failure verbatim from the CLI output. The most common causes:

- Receipt was edited after sealing (Merkle root mismatch).
- The signing key has been rotated and the report is referencing the old certificate.
- Network truncation while downloading a remote receipt -- retry first.

Do not gloss over a verification failure. If the receipt does not verify, the report is not trustworthy and the user needs to know.
