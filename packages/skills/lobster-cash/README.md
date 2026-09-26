# Treeship

[![lobster.cash compatible](https://img.shields.io/badge/lobster.cash-compatible-ff6600)](https://lobster.cash)

Cryptographic proof of what your agent did.

Every other skill executes payments. Treeship proves they happened correctly -- signed receipts for every action, a tamper-evident chain, and a URL anyone can verify offline.

## Includes

- Signed receipt for every agent action (always on, zero config)
- Tamper-evident chain of custody -- editing a signed action breaks its signature; verifiable offline
- Scoped, single-use human approvals (Ed25519, binding nonce)
- One URL to verify everything: treeship.dev/verify/[session]

<!-- Editor's note (2026-09-27): this card used to list "ZK proof: policy
compliance" and "ZK proof: spend within limits". Neither ships: the
Circom/Groth16 proving path is quarantined (its proving keys were never
generated under a real ceremony, so the circuits are forgeable by
construction; prove/verify-proof fail closed), and a RISC Zero full-chain
proof requires the CLI built with --features zk, which release binaries
don't have, and does not run automatically at session close. Removed
rather than left as an unqualified claim about a payments skill. -->

## How it works with lobster.cash

Treeship doesn't execute payments. lobster.cash does that. Treeship wraps every step with cryptographic attestation so anyone can verify the agent acted correctly.

| Step | What happens | What Treeship proves |
|------|-------------|---------------------|
| Wallet check | Agent checks lobster.cash balance | Action attested (Ed25519) |
| Human approval | User authorizes the payment | Scoped approval (binding nonce + actor/action/subject scope; replay package-local) |
| Payment | lobster.cash executes the transfer | Action attested (Ed25519); the approval's nonce is bound to this action |
| Confirmation | lobster.cash confirms status | Receipt attested |
| Session close | Workflow complete | Signed close record binds the sealed receipt (`package verify`'s `receipt_binding`) |

The verification URL works in any browser via WebAssembly. No account, no install, no trust in Treeship's servers.

## Install

```bash
npm install -g treeship @crossmint/lobster-cli
treeship init
```

There is no `lobster-cash-commerce` template. `treeship templates` lists what's real; none of them is lobster-specific yet.

## Demo

```bash
./packages/skills/lobster-cash/demo.sh
```

Produces a verification URL showing all proof panels.

## Delegation boundary

**Treeship owns:** attestation, audit trail, scope enforcement

**lobster.cash owns:** wallet provisioning, transaction signing, payment execution, settlement

Treeship never touches private keys, seed phrases, or card details.

## Links

- Integration docs: [docs.treeship.dev/integrations/lobster-cash](https://docs.treeship.dev/integrations/lobster-cash)
- Blog: [Agent Payments: Lobster.cash + Treeship](https://docs.treeship.dev/blog/lobster-cash-treeship-agent-payments)
- GitHub: [github.com/zerkerlabs/treeship](https://github.com/zerkerlabs/treeship)

## Built by

[Zerker Labs](https://zerker.ai) -- builders of Treeship, the trust layer for agent workflows.
