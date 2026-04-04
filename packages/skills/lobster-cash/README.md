# Lobster Cash Skill

[![lobster.cash compatible](https://img.shields.io/badge/lobster.cash-compatible-ff6600)](https://lobster.cash)

Cryptographic attestation for every payment made through lobster.cash. Every wallet action is wrapped, proved, and pushed to the Treeship hub so you have a verifiable audit trail from intent to settlement.

## What It Does

This skill sits between the agent and the lobster.cash wallet. It does not execute transactions itself. Instead, it wraps each wallet operation with a Treeship attestation so every step is independently verifiable.

- Agent requests a payment
- Treeship records the intent, gets human approval, and wraps the execution call
- lobster.cash handles the actual transaction
- Treeship records the result and pushes the full attestation bundle to the hub

## Install

```bash
treeship skill install lobster-cash
```

### Prerequisites

| Dependency    | Install                          |
|---------------|----------------------------------|
| treeship      | `npm i -g @treeship/cli`         |
| lobstercash   | See https://lobster.cash/docs    |

## Attestation Table

| Step               | Action Attested                | Actor              |
|--------------------|--------------------------------|--------------------|
| Session start      | session.start                  | agent              |
| Balance check      | lobster.balance.check          | agent              |
| Intent declared    | lobster.tx.create              | agent              |
| Approval granted   | lobster.tx.approve             | human://approver   |
| Payment executed   | lobster.send / lobster.card.request / lobster.x402.fetch | agent              |
| Status confirmed   | lobster.tx.status              | agent              |
| Session closed     | session.close                  | agent              |
| Hub push           | hub.push                       | agent              |

## Delegation Boundary

| Treeship Owns                        | lobster.cash Owns                    |
|--------------------------------------|--------------------------------------|
| Session lifecycle                    | Wallet provisioning                  |
| Attestation wrapping                 | Key management                       |
| Approval gating                      | Transaction signing                  |
| Audit trail and hub push             | Network broadcast and confirmation   |
| Trust template enforcement           | Balance and account state            |

Treeship never touches private keys, seed phrases, or card details. All sensitive operations are delegated to lobster.cash.

## Run the Demo

```bash
chmod +x demo.sh
./demo.sh
```

## Built By

[Zerker Labs](https://zerker.dev)
