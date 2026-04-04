# Treeship -- Lobster Cash Ecosystem Listing

## Card copy (for lobster.cash/skills directory)

**Treeship**

Cryptographic proof for every agent payment. ZK-verifiable audit trails.

**Includes**

- Signed receipts for every agent action, approval, and payment
- Zero-knowledge proof that payments stayed within declared limits
- Tamper-evident Merkle-anchored audit trail anyone can verify at a URL

**Visit website**: https://treeship.dev

---

## Extended description (for detail page)

Treeship adds cryptographic attestation to every Lobster Cash payment.
Every agent action is signed (Ed25519), Merkle-anchored for tamper-evident
ordering, and ZK-proved for policy compliance and spend limits.

The full audit trail verifies at treeship.dev/verify -- in the browser
via WebAssembly, no server trust required, no Treeship account needed.

### What Treeship proves

| Proof | What it shows | ZK system |
|-------|---------------|-----------|
| Action attestation | Agent performed this action | Ed25519 signature |
| Policy compliance | Action was within declared scope | Circom Groth16 |
| Spend limit | Payment was within declared max | Circom Groth16 |
| Chain integrity | Full session is unmodified | RISC Zero |
| Temporal ordering | Artifacts existed before checkpoint | Merkle (RFC 9162) |

### Delegation boundary

Treeship owns: attestation, ZK proofs, audit trail, scope enforcement
lobster.cash owns: wallet provisioning, transaction signing, payment execution, settlement

### Install

```bash
npm install -g treeship @crossmint/lobster-cli
treeship init --template lobster-cash-commerce
```

### Links

- Integration docs: https://docs.treeship.dev/integrations/lobster-cash
- GitHub: https://github.com/zerkerlabs/treeship
- Skill files: https://github.com/zerkerlabs/treeship/tree/main/packages/skills/lobster-cash
- Demo: Run `./packages/skills/lobster-cash/demo.sh` for a complete workflow

### Compatible wallets

- lobster.cash (tested and certified)

### Built by

Zerker Labs -- https://zerker.ai

---

## Message to Fede

Hey Fede -- I'm building Treeship, a cryptographic attestation layer for
agent workflows. We built a Lobster Cash compatible skill and want to
get listed in the ecosystem directory.

What makes it different: every Lobster Cash payment gets a ZK-provable
audit trail. The agent's declared scope, every action it took, and a
proof that the payment was within authorized limits -- all verifiable
at a URL without trusting any server.

Integration docs: https://docs.treeship.dev/integrations/lobster-cash
GitHub: https://github.com/zerkerlabs/treeship/tree/main/packages/skills/lobster-cash
Demo verification: treeship.dev/verify/[session-id]

Would love to sync when you're ready to review.

-- Amit, Zerker Labs
