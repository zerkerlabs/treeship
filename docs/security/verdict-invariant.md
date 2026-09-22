# The verdict invariant

**No green verdict is reachable without signature verification against a key the verifier trusts.**

Three advisories in four months shared one root cause. In v0.10.4 verifiers trusted keys embedded in the artifact. In v0.19 higher-level surfaces reported "verified" from attacker-controlled input without anchoring to a checked signature. In v0.31.2 `package verify` never checked an artifact's Ed25519 signature at all. Each got a regression test for its instance. This is the test for the class.

## The suite

`packages/cli/tests/verdict_invariant_cli.rs` builds one real workspace that exercises every verdict surface on the happy path, forks it once per mutation, applies the mutation to the copy, and asserts two things every time: the command exits nonzero, and neither its text nor its JSON output carries a green verdict. It runs in CI as its own workflow, `verdict-invariant`, so it has its own badge.

| Command | flipped payload byte | stripped signatures | unknown signing key | forged artifact id | reordered chain | emptied package | unpinned root |
|---|---|---|---|---|---|---|---|
| `verify` | rejected | rejected | rejected | rejected | rejected | | |
| `verify-capability` | rejected | **rejected since this suite** | rejected | rejected | | | |
| `verify-presentation` | rejected | rejected | rejected | | | | rejected |
| `verify-profile` | rejected | rejected | rejected | | | | |
| `package verify` | rejected | rejected | rejected | | | rejected | never `verified`; `--strict` fails |
| `session report` | `verification_status: fail`, exit nonzero | | | | | | |
| `workflow verify` | rejected | rejected | rejected | | | | |
| `vi verify --local` | **rejected since this suite** | rejected | rejected | | | | |

"Rejected" means both assertions held. An empty cell is a mutation that does not apply to that command's input.

## What the suite found on the day it was written

- `verify-capability` on a card whose envelope had its signatures stripped exited 0 and printed a check mark, because "no valid signature" was folded into the "self-asserted" grade. It now fails closed: an unsigned card, or one no key this machine trusts can verify, gets no verdict. Self-asserted still means what it meant: signed by a key this machine holds, not pinned under the agent's certificate.
- `vi verify --local --require-attestation` checked that the attestation artifact existed in local storage, not that it verified. A flipped byte in the stored record still reported PASS. It now verifies the attestation's signature under a trusted key and re-derives its id from the signed bytes, and does the same for every artifact in the walked chain.

Both fixes shipped in the same change as the suite, with the suite as the fail-before-fix.

## What the invariant does not cover

It is about the verifier's own surfaces. It does not test the Hub, the JavaScript and WASM verifiers, or the SDKs, each of which has its own tests. It does not prove the absence of a fourth surface that prints a verdict; the green detector is written broad on purpose, and any new command that prints a verdict should be added to the fixture.

Related: [threat model](threat-model.md), [TS-2026-002](TS-2026-002.md), [What a receipt proves](https://docs.treeship.dev/docs/concepts/what-receipts-prove).
