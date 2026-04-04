# Verifiable Intent (VI)

Verifiable Intent is a credential chain that lets a user delegate bounded authority to an AI agent for commerce operations. Authority flows from issuer to user to agent, with every step cryptographically linked.

## How It Works

```
L1: Issuer SD-JWT          The bank or payment network asserts the user
    |                      holds a valid instrument.
    v
L2: User Mandate           The user delegates bounded authority to an
    |                      agent with checkout and payment constraints.
    v
L3: Agent Credential       The agent produces a credential (payment or
    + Treeship Attestation  checkout) within L2 bounds. Treeship attests
                           that constraints were satisfied.
```

## How Treeship Integrates

Treeship is embedded at the L3 level via `agent_attestation`. When an agent builds an L3 credential:

1. Treeship verifies the L2 mandate constraints.
2. Treeship confirms the agent's key binding matches.
3. Treeship optionally generates a ZK proof of constraint satisfaction.
4. Treeship signs and embeds the attestation in the L3 credential.

Any downstream verifier (merchant, payment processor, auditor) can check the full chain: issuer assertion, user mandate, agent credential, and Treeship attestation.

## Trust Stack

```
+----------------------------------+
|  L1: Issuer (bank / network)    |
|  SD-JWT with instrument claim    |
+----------------------------------+
              |
              v
+----------------------------------+
|  L2: User Mandate               |
|  Constraints + cnf key binding   |
+----------------------------------+
              |
              v
+----------------------------------+
|  L3: Agent Credential           |
|  L3a (payment) or L3b (checkout)|
|  + AgentAttestation (Treeship)   |
+----------------------------------+
              |
              v
+----------------------------------+
|  Execution                       |
|  lobster.cash / x402 / direct    |
+----------------------------------+
```

## Status

- **v0.6.0** - Foundation: types, P-256 key management, skill definition
- **v0.7.0** - Full credential chain: L2 mandate parsing, L3 construction, constraint verification, ZK proof integration
