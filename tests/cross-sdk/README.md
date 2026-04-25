# Cross-SDK contract tests

Proves that every Treeship SDK returns the same verify verdict for the same
artifact. Two SDKs (TypeScript and Python) take the same inputs through their
public surface; if they diverge on accept/reject or on the reported chain
length, CI fails.

## Why this exists

The TypeScript SDK and Python SDK have very different shapes:

- TS exposes `ship().verify.verify(idOrPath)` (CLI shell-out) and
  `ship().verify.verifyReceipt(json)` (in-process WASM).
- Python wraps the CLI binary with `Treeship().verify(artifact_id)`.

Because they have different code paths, they can drift independently. A
ship-side fix that updates one path can leave the other returning the wrong
outcome -- and we won't notice until a downstream user files a bug.

This suite makes the divergence visible at PR time.

## What it tests

Two phases, both must pass for `run.sh` to exit 0.

**Phase A — Vector parity (`verify(artifact_id)`)**

Both SDKs verify the same corpus of pre-attested artifacts (action,
decision, approval, plus one DSSE-tampered variant). They must agree on
`{outcome, chain}` for every vector. Catches drift in HOW each SDK
interprets the CLI's structured output.

**Phase B — Roundtrip (`attest` + `verify` across SDKs)**

TS attests an artifact, Python verifies it. Python attests an artifact,
TS verifies it. All four legs must pass. Catches a deeper class of
drift: an artifact attested by SDK A whose envelope shape, digest scheme,
or signature encoding diverges from what SDK B expects to verify.

Higher-fidelity contracts (`verifyReceipt(json)`, certificate cross-verify,
`hub.push` parity against a live Hub) will land here as those surfaces
get exposed in both SDKs.

## Layout

```
tests/cross-sdk/
├── README.md           # this file
├── gen-vectors.sh      # generator: mints a scratch keystore + N artifacts
├── verify-vectors.ts   # Phase A: TS runner (Node 20+)
├── verify_vectors.py   # Phase A: Python runner (3.10+)
├── roundtrip.sh        # Phase B: TS↔Python attest+verify roundtrip
├── _sdk-helper.mjs     # Phase B: tiny TS dispatcher (attest-action / verify)
├── _sdk_helper.py      # Phase B: tiny Python dispatcher (attest-action / verify)
├── run.sh              # orchestrator: gen, Phase A, Phase B, diff outcomes
└── corpus.json         # written by gen-vectors.sh; runners read it
```

`corpus.json` is regenerated on every run -- it isn't checked in. It
contains the temp keystore path and the per-vector expected outcomes:

```json
{
  "config_path": "/tmp/.../config.json",
  "vectors": [
    {
      "name": "valid.action.tool-call",
      "artifact_id": "art_abc...",
      "category": "valid",
      "expected_outcome": "pass",
      "expected_chain": 1
    },
    {
      "name": "broken.tampered-payload",
      "artifact_id": "art_def...",
      "category": "broken-chain",
      "expected_outcome": "fail",
      "expected_chain": 0
    }
  ]
}
```

## Running locally

```sh
# from repo root
./tests/cross-sdk/run.sh
```

Prerequisites: built `treeship` binary, Node 20+, Python 3.10+, the SDK
packages installed (`npm install` in `packages/sdk-ts`, `pip install -e .`
in `packages/sdk-python`).

## Adding a vector

1. Add a generation step to `gen-vectors.sh` -- usually one or two lines
   calling `treeship attest <kind> ...`, plus an entry in the JSON output.
2. Re-run `run.sh` to confirm both SDKs agree on the new vector.
3. If they disagree, that's the contract bug to file.

## What a divergence looks like in CI

```
[ts-runner]  valid.action.tool-call: PASS (outcome=pass, chain=1)
[py-runner]  valid.action.tool-call: PASS (outcome=pass, chain=1)
[ts-runner]  broken.tampered-payload: PASS (outcome=fail, chain=0)
[py-runner]  broken.tampered-payload: FAIL -- expected outcome=fail got outcome=error

DIVERGENCE
  vector: broken.tampered-payload
  ts:     {outcome: "fail", chain: 0}
  py:     {outcome: "error", chain: 0}
exit 1
```
