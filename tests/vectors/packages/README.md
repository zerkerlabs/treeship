# T2 package vectors

Frozen `.treeship` packages and the verdict every verifier must give each one.
Gate T2 of the 2026-09-25 audit.

- `honest/*`: packages an honest producer wrote.
- `tampered/*`: `honest/basic` with one edit each (see `generate.sh`).
- `expected.json`: per vector, the verdict per verifier column, plus `xfail`
  entries `{task, got}` naming the fix-plan task that makes a wrong column
  right and the exact wrong verdict main gives today.

Run:

```bash
bash tests/vectors/packages/run.sh target/debug/treeship     # cli, cli_strict, cli_structural
cargo test -p treeship-core --test package_vectors            # receipt_only (core-wasm / verify-js)
(cd packages/verify-js && npx vitest run test/package-vectors.test.ts)  # verify_js, verify_js_pinned
```

## Rules

1. A tampered vector is never `verified` or `signatures-pass`, in any mode. The one exception is explicit: a vector marked `unpinned_indistinguishable` (a forger's own, self-consistent package) may accept in the unpinned `cli` column only, because with nothing pinned it is byte-for-byte an honest package under an unknown key; its pinned columns (`cli_strict`, `cli_pinned`) must fail.
2. The receipt-only verifier never says more than `structural-pass`.
3. `failed` exits nonzero; every other verdict exits 0.
4. An `xfail` column passes only while it gives exactly its pinned wrong
   verdict. Any other wrong verdict fails the run, and so does the right one
   (XPASS): remove the entry in the PR that fixes it.
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
| `honest/endorse-non-latest`, `tampered/endorsement-parent-edited` | treeship 0.31.9 + W1-1 debug build | branch `fix/W1-1` (endorsements sign `parentId`) |
| `honest/legacy-endorsement-0.31.9` | treeship 0.31.9 release binary (installed CLI) | the published 0.31.9 release; its endorsement signs no parent |
| `honest/room-two-ships` | treeship main at `d9221569` (after #499) | the T1 flow `room_two_ships`: host and joiner on separate ships, pending envelope sent as a file |

Each vector is signed by a throwaway key generated in a temp `HOME` by
`generate.sh`. The keys were discarded; nothing here is a production key.
Regenerating is not byte-identical: keys and timestamps are fresh each run,
so regenerate only to add or change a vector and review the whole diff.
`honest/legacy-0.24` is only rebuilt when a 0.24.0 binary is given as
`LEGACY_024_BIN` (build tag `v0.24.0` with `cargo build --release -p
treeship-cli`), and `honest/legacy-endorsement-0.31.9` only when
`RELEASE_0319_BIN` names a 0.31.9 binary; without them `generate.sh` leaves
the committed vectors alone. Pass vector names to rebuild only those.
`preview.html` is removed from every vector (optional, ~150 KB, unread by any
verifier).

`verify_js` and `verify_js_pinned` are `@treeship/verify`'s `verifyPackage`
(W2-6), with no key pinned and with the package's own keys pinned:
`cd packages/verify-js && npx vitest run test/package-vectors.test.ts`. It
caps a package holding kinds whose rules it does not evaluate (approvals,
endorsements, rooms) at `structural-pass`, so the room vectors the CLI fails
read `structural-pass` there, never `signatures-pass`.
