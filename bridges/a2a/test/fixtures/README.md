# Real verifier output

Captured from `treeship verify-presentation --format json` on 2026-09-01 against
two isolated ships (separate `HOME` **and** `TREESHIP_CONFIG`), not hand-written.
Per the AI-assisted development policy, test vectors are recorded from a real
run rather than fabricated.

| File | Case | CLI exit |
|---|---|---|
| `verify-unpinned-issuer.json` | receiver never pinned the sender's `cert_issuer` | 1 |
| `verify-accepted.json` | pinned, correct nonce | 0 |
| `verify-replayed-nonce.json` | pinned, nonce answers a different challenge | 1 |

The first and third both print verdict `CHALLENGE FAILED`. That collision is why
the gate classifies on structured fields and not on the verdict string: telling a
sender its challenge failed, when the truth is that we never pinned its issuer,
sends it to fix the wrong thing.
