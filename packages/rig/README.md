# rig-treeship

Signed, chained, offline-verifiable receipts for every tool call a [Rig](https://crates.io/crates/rig-core) agent makes — built natively on [`treeship-core`](https://crates.io/crates/treeship-core).

Both stacks are Rust, so this is a type-level integration: no CLI subprocess, no shell wrapping. Signing happens in-process with Ed25519 over DSSE envelopes, and the compiler checks the seam — if `rig-core` or `treeship-core` changes shape, the build fails instead of your audit trail.

## What it does

Wrap any Rig `PortableTool`:

```rust
use std::sync::Arc;
use rig_treeship::{AttestedExt, TreeshipLedger};

let ledger = Arc::new(TreeshipLedger::open_default("agent://my-agent")?);
let tool = MyTool.attested(ledger.clone());
// register `tool` with your runtime exactly like the bare tool
```

Every call then:

1. hashes the deserialized arguments (SHA-256, compact JSON),
2. runs the inner tool,
3. hashes the output — or records the failure (`outcome: "error"`),
4. signs a `treeship/action/v1` statement carrying both hashes, chained to the previous receipt via `parentId`,
5. returns the result **only after** the receipt is stored (fail-closed: an unattested action is treated as no action).

The wrapper is transparent to the model — same `NAME`, description, and JSON schema — so it changes what your agent can *prove*, not what it can do.

## Verifying

```rust
let head = ledger.head().unwrap();
let verified = ledger.verify_chain(&head)?;   // walks parentId back to genesis
println!("{} receipts verified", verified.length);
```

`verify_chain` re-derives every artifact ID from its PAE bytes, checks each Ed25519 signature, and confirms the stored parent pointer matches the *signed* `parentId` — so neither payloads nor chain structure can be rewritten. Flip one byte anywhere and verification fails (see the `tampering_breaks_verification` test).

Receipts are standard Treeship artifacts on disk, so the CLI workflow still applies: `treeship verify <id>`, `treeship hub push <id>` for a public `treeship.dev/verify/...` URL.

## Design notes

- **Hashes, not content.** Receipts carry `args_hash` / `output_hash`, never raw arguments — sensitive tool inputs don't leak into the audit trail.
- **Linear chain under concurrency.** The ledger holds its head lock across sign+store, so parallel tool calls serialize into one chain rather than forking.
- **Failed calls are attested.** A chain with gaps proves nothing; errors get receipts too.
- **Ledger modes.** `open_default()` uses `$TREESHIP_HOME` or `~/.treeship`; `open(dir)` for project-local ships; `ephemeral()` for tests (signed + chained, not persisted).

## Layout

```
src/
  lib.rs        crate docs, re-exports, integration tests
  ledger.rs     TreeshipLedger: keystore, artifact store, chain head, verify_chain
  attested.rs   Attested<T>: PortableTool impl + .attested() extension
  error.rs      AttestError / AttestedError (tool vs attestation failure)
examples/
  attested_agent.rs   end-to-end: 3 calls (one failing) → verified chain
```

## Run it

```
cargo test
cargo run --example attested_agent
```

Built and tested against `rig-core 0.41.0` and `treeship-core 0.23.0` on Rust 1.91.
