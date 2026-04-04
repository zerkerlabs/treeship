# Treeship

[![lobster.cash compatible](https://img.shields.io/badge/lobster.cash-compatible-ff6600)](https://lobster.cash)

Cryptographic proof of what your agent did.

Every other skill executes payments. Treeship proves they happened correctly -- signed receipts for every action, privacy-preserving ZK proofs for what you can't disclose.

## Includes

- Signed receipt for every agent action (always on, zero config)
- Tamper-evident chain of custody -- permanent, verifiable offline
- ZK proof: policy compliance -- proved without revealing the policy
- ZK proof: spend within limits -- proved without revealing the amount
- One URL to verify everything: treeship.dev/verify/[session]

## How it works with lobster.cash

Treeship doesn't execute payments. lobster.cash does that. Treeship wraps every step with cryptographic attestation so anyone can verify the agent acted correctly.

| Step | What happens | What Treeship proves |
|------|-------------|---------------------|
| Wallet check | Agent checks lobster.cash balance | Action attested (Ed25519) |
| Human approval | User authorizes the payment | Nonce-bound approval (single-use) |
| Payment | lobster.cash executes the transfer | Policy compliance + spend limit (Circom ZK) |
| Confirmation | lobster.cash confirms status | Receipt attested |
| Session close | Workflow complete | Full chain proof (RISC Zero) |

The verification URL works in any browser via WebAssembly. No account, no install, no trust in Treeship's servers.

## Install

```bash
npm install -g treeship @crossmint/lobster-cli
treeship init --template lobster-cash-commerce
```

## Demo

```bash
./packages/skills/lobster-cash/demo.sh
```

Produces a verification URL showing all proof panels.

## Delegation boundary

**Treeship owns:** attestation, ZK proofs, audit trail, scope enforcement

**lobster.cash owns:** wallet provisioning, transaction signing, payment execution, settlement

Treeship never touches private keys, seed phrases, or card details.

## Links

- Integration docs: [docs.treeship.dev/integrations/lobster-cash](https://docs.treeship.dev/integrations/lobster-cash)
- Blog: [Agent Payments: Lobster.cash + Treeship](https://docs.treeship.dev/blog/lobster-cash-treeship-agent-payments)
- GitHub: [github.com/zerkerlabs/treeship](https://github.com/zerkerlabs/treeship)

## Built by

[Zerker Labs](https://zerker.ai) -- builders of Treeship, the trust layer for agent workflows.
