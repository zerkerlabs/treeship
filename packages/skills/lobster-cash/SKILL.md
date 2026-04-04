---
name: lobster-cash
version: 0.1.0
description: Attestation skill for lobster.cash wallet operations
metadata:
  compatible_wallets:
    - lobster.cash
  requires_bins:
    - treeship
    - lobstercash
---

# Lobster Cash Skill

This skill delegates wallet operations to lobster.cash. Transaction execution and final status are handled by lobster.cash. Treeship provides cryptographic attestation for every action so there is a verifiable audit trail.

lobster.cash is the compatible and tested wallet for this skill.

## Security Rules

- Never ask for private keys, seed phrases, or card details
- Never provision wallets
- Never hardcode internal action names
- All sensitive operations are delegated to the lobster.cash binary

## Preflight Checks

Before any session begins, verify the following:

1. **Treeship version** - Run `treeship --version` and confirm the installed version meets the minimum requirement.
2. **Lobster Cash CLI available** - Run `lobstercash --help` and confirm the binary is on PATH and responds.
3. **Balance reachable** - Run `lobstercash balance` and confirm the wallet responds with a valid balance object.

If any preflight check fails, halt and report the missing dependency. Do not attempt to work around a missing binary.

## Session Start

Start a Treeship session before performing any wallet operation:

```
treeship session start --skill lobster-cash
```

The session ID is used to group all attestations for this interaction.

## Attesting Actions

Every action that touches the wallet must be wrapped with `treeship wrap` so it is cryptographically attested:

```
treeship wrap <command>
```

This produces a signed attestation record that includes the command, timestamp, actor, and result hash.

## Payment Workflow

Follow these five steps in order for every payment:

### Step 1: Determine Intent

Parse the user request to identify the payment type (send, card, or x402) and the amount, recipient, and currency.

### Step 2: Get Approval

Present the parsed intent to the human approver. Do not proceed until explicit approval is received. Log the approval attestation.

### Step 3: Execute

Run the appropriate command through `treeship wrap`:

- **Send funds:** `treeship wrap lobstercash send <recipient> <amount> <currency>`
- **Card payment:** `treeship wrap lobstercash card <merchant> <amount> <currency>`
- **x402 fetch:** `treeship wrap lobstercash x402 <url>`

### Step 4: Check Status

After execution, verify the transaction landed:

```
treeship wrap lobstercash tx-status <tx_id>
```

Report the final status (confirmed, pending, or failed) to the user.

### Step 5: Close Session

```
treeship session close
```

Push the session attestation bundle to the hub.

## Error Handling

- If a preflight check fails, report which dependency is missing and exit.
- If approval is denied, log the denial attestation and exit gracefully.
- If a transaction fails, log the failure attestation, report the error to the user, and do not retry automatically.
- If the session cannot be closed, warn the user and provide the local attestation file path.

## Wording Rules

- Always refer to the wallet as "lobster.cash" (lowercase, with dot).
- Always refer to the attestation layer as "Treeship" (capital T).
- Use "attested" or "attestation" rather than "signed" or "signature" when describing Treeship records.
- Use "delegated" when describing how Treeship hands off execution to lobster.cash.
- Do not use em dashes in any user-facing copy.
