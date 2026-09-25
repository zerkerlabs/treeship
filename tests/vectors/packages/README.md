# T2 package vectors

Frozen `.treeship` packages and the verdict every verifier must give each one.
Gate T2 of the 2026-09-25 audit.

- `honest/*`: packages an honest producer wrote.
- `tampered/*`: `honest/basic` with one edit each (see `generate.sh`).
- `expected.json`: per vector, the verdict per verifier column, plus `xfail`
  entries naming the fix-plan task that makes a wrong column right.

Run:

```bash
bash tests/vectors/packages/run.sh target/debug/treeship     # cli, cli_strict, cli_structural
cargo test -p treeship-core --test package_vectors            # receipt_only (core-wasm / verify-js)
```

## Rules

1. A tampered vector is never `verified` or `signatures-pass`, in any mode.
2. The receipt-only verifier never says more than `structural-pass`.
3. `failed` exits nonzero; every other verdict exits 0.
4. An `xfail` column that starts passing fails the run (XPASS). Remove the
   entry in the PR that fixes it.
5. Every new advisory and every verifier fix adds a vector.

## Provenance

The expected verdicts are not read off the verifier. Each follows from what
the edit does: a tampered vector changes signed or bound bytes, so any
verifier that checks them must fail it, and a keyless one can at most report
structure.

The package bytes were written by the CLI's own session writer, which is the
input the verifiers have to handle in the field:

| Vectors | Writer | Source |
|---|---|---|
| `honest/basic`, `honest/approval`, `tampered/*` | treeship 0.31.9 debug build | zerkerlabs/treeship `df93fa09` (main, 2026-09-25) |
| `honest/legacy-0.24` | treeship 0.24.0 release build | a local 0.24.0 build; packages before 0.31.2 carry no envelopes |

Each vector is signed by a throwaway key generated in a temp `HOME` by
`generate.sh`. The keys were discarded; nothing here is a production key.
`preview.html` is removed from every vector (optional, ~150 KB, unread by any
verifier).

The site verifier (Lane C, W0-1/W2-5) and verify-js package mode (W2-6) add
their own columns to `expected.json` when they land.
