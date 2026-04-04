---
name: verifiable-intent
version: 0.6.0
description: Credential chain skill for delegating user intent to agents via Verifiable Intent (VI)
metadata:
  spec: verifiable-intent-v1
  credential_levels:
    - L1 (Issuer SD-JWT)
    - L2 (User Mandate)
    - L3a (Agent Payment)
    - L3b (Agent Checkout)
  compatible_wallets:
    - lobster.cash
  requires_bins:
    - treeship
---

# Verifiable Intent Skill

## Core Principle

A user's intent is delegated through a three-level credential chain:

1. **L1** - The issuer (bank, payment network) issues an SD-JWT asserting the user holds a valid instrument.
2. **L2** - The user creates a mandate that delegates bounded authority to an agent, specifying checkout and payment constraints.
3. **L3** - The agent produces a credential (L3a for payment, L3b for checkout) that operates strictly within L2 bounds.

Every level is cryptographically linked. The chain is verifiable end to end without revealing more data than necessary.

## Treeship's Role

Treeship provides `agent_attestation`, embedded directly in every L3 credential. When an agent builds an L3 credential, Treeship:

1. Verifies the L2 mandate is valid and not expired.
2. Checks that the requested action satisfies all constraints (amount, merchant, category).
3. Optionally generates a ZK proof of constraint satisfaction.
4. Signs the attestation and embeds it in the L3 credential.

This means any verifier can check not only the credential chain but also that a trusted runtime (Treeship) confirmed constraint compliance at execution time.

## Workflow

### Receiving a Mandate

The agent receives an L2 mandate containing:
- A reference to the L1 credential
- Checkout constraints (allowed merchants, categories, item limits)
- Payment constraints (max amount, currency, allowed methods, transaction limits)
- A `cnf` key binding that ties the mandate to the agent's P-256 key

### Verifying Constraints

Before building an L3 credential, the agent must verify:
- The mandate has not expired
- The requested operation falls within the declared constraints
- The agent's key matches the `cnf` binding in the mandate

### Building L3 Credentials

For payment (L3a):
- Confirm amount is within `max_amount_minor`
- Confirm currency matches
- Confirm payment method is in the allowed list

For checkout (L3b):
- Confirm merchant is in the allowed list (or list is empty, meaning any)
- Confirm category is in the allowed list (or list is empty)
- Confirm item count is within `max_items`

### Attesting

Treeship wraps the L3 credential with an `AgentAttestation` that includes:
- Attestation and session IDs linking to Treeship's receipt store
- Hashes of the mandate and credential for tamper detection
- A boolean `constraints_satisfied` flag
- An optional ZK proof reference
- Treeship's signature

## Lobster Cash Compatibility

When the L3a payment credential specifies `lobster_cash` as the payment method, execution is delegated to the lobster.cash wallet. The attestation chain flows:

L1 (bank) -> L2 (user mandate) -> L3a (agent payment + Treeship attestation) -> lobster.cash (execution)

Treeship attests every step. Lobster.cash handles the actual fund movement.

## Security Rules

- Never store or transmit raw L1 SD-JWT disclosures beyond what is needed
- Never exceed L2 mandate constraints under any circumstances
- Never create L3 credentials without verifying the `cnf` key binding
- Never skip Treeship attestation
- Do not use em dashes in any user-facing copy

## Wording Rules

- Refer to the credential chain as "Verifiable Intent" or "VI".
- Refer to levels as "L1", "L2", "L3a", "L3b".
- Use "mandate" for L2, not "token" or "permission".
- Use "attested" or "attestation" when describing Treeship records.
- Use "delegated" when describing how authority flows from user to agent.
