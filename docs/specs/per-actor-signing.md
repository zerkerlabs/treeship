# Per-Actor Signing — design draft

**Status:** draft, not implemented
**Pairs with:** capability cards (`verify-capability` key-bound check), `TrustRootKind::AgentCert`, `treeship agent register`
**Last updated:** 2026-06-24

## The shift

Today every action in a Treeship is signed by the **single default key**. `agent://deployer` and `agent://planner` working in the same Treeship both produce receipts signed by that one key, and the `actor` field is a free string. So actor identity is **asserted, not proven**: a compromised `agent://deployer` can label its actions `agent://planner` and the signature still verifies. This is the actor-forgery gap, and it is the gap the capability card's `key-bound` status is waiting on, today every card is `self-asserted` because nothing pins a per-agent key.

Per-actor signing closes it: **each agent signs its own actions with its own key, certified by the ship.** Then the `actor` becomes provable (the receipt's signing key is the agent's pinned `AgentCert` key), and `verify-capability` lights up `key-bound: yes`.

## What's already in the box

- **`KeyStore::generate()`** — mint a new keypair. **`KeyStore::signer(id)`** — sign with a *specific* key, not just the default. So multiple keys and per-key signing already exist.
- **`TrustRootKind::AgentCert`** — "a ship issues a certificate to one of its agents." The exact primitive for binding agent → key.
- **`treeship agent register`** — already issues an `AgentCertificate`, but signs it with `default_signer()` (so it certifies the *ship's* key, not a per-agent key). That is the one thing to change.
- **Agent Card store** (`cards.rs`) — per-agent records with a `certificate_digest`. A natural home for the actor → key binding.
- **`verify-capability`** already checks "is the action's signer the card's keyid, pinned under AgentCert." The consumer side is built; it just never sees per-agent keys yet.

Per-actor signing composes these. It introduces no new trust primitive and no new signature path, it changes *which key* signs and adds a lookup.

## The model: ship issues, agent signs

Two keys, the existing two-role split made real:

- **Ship key** (today's default): the issuer. It signs each agent's certificate, binding `agent://uri → agent_key`. It does not sign the agent's actions.
- **Agent key** (new, per agent): signs that agent's actions. Pinned under `AgentCert` via the ship-signed certificate.

```
ship_key  --signs-->  AgentCertificate { agent: agent://deployer, key: agent_key_A }
agent_key_A  --signs-->  every action receipt for agent://deployer
verify: action.signer == agent_key_A == cert.key, cert issued by a trusted ship  =>  actor PROVEN
```

## What changes

1. **`treeship agent register --actor agent://deployer`** generates a *new* per-agent key (or adopts a named one), issues a ship-signed `AgentCertificate` binding the actor URI to that key, pins the agent key under `AgentCert`, and records the `actor → key_id` mapping on the agent card.
2. **`treeship attest action --actor agent://deployer`** resolves the actor URI to its registered key id and signs with `keys.signer(key_id)`. If the actor has no registered per-agent key, it signs with `default_signer()` exactly as today (backward compatible).
3. **Verification** treats `actor` as **proven** when the action's signer is the actor's pinned `AgentCert` key, and as **asserted** otherwise (shared/default key). `verify-capability` already encodes this; it just starts returning `key-bound: yes` for properly-registered agents.

## Proven vs asserted (the line moves, honestly)

| Situation | `actor` zone |
|---|---|
| Action signed by the actor's pinned `AgentCert` key | **Proven** — the signing key *is* the certified agent key |
| Action signed by the shared default key (no per-agent key registered) | **Asserted** — today's behavior, a free-text label |

Per-actor signing is what moves `actor` from the asserted column to the proven column. Both states coexist; verification reports which.

## Honest limits

- Per-actor signing closes **intra-Treeship** actor separation. It does **not** close host compromise: a compromised machine holds every key it can decrypt and can sign as any agent. The trust boundary is still the machine. (Strongest separation remains: different agents on different machines / Treeships.)
- Existing default-key-signed receipts stay valid; they are simply "shared-key," not "per-actor." No migration, no break.

## Backward compatibility

Strictly additive. An agent with no registered per-agent key signs with the default key, byte-for-byte as today. Existing certs (which certify the default key) keep verifying. The only new behavior is *opt-in* per-agent keys.

## Slices

1. **`agent register` mints + binds a per-agent key.** Generate a key, issue the ship-signed cert over *that* key, pin it `AgentCert`, store `actor → key_id` on the agent card. (The cert-issuance and pinning code largely exists; the change is generating/using a per-agent key instead of the default.)
2. **`attest action` resolves actor → key and signs with it**, fallback to default. This is the load-bearing change; keep it small and well-tested, with the fallback path covered.
3. **Verification surfaces `actor` proven vs asserted**, and `verify-capability` returns `key-bound: yes` for registered agents. Mostly reporting; the check already exists.

## Open questions

1. **Where the `actor → key_id` map lives.** Proposal: a `key_id` field on the `AgentCard` (it already carries `certificate_digest`), so `attest` resolves via the card store. Alternative: derive from the pinned `AgentCert` roots by matching the cert's `agent` URI.
2. **Key rotation.** When an agent rotates keys, a new cert supersedes the old; past receipts stay valid under the old (still-trusted-at-the-time) key. Needs the same resolution semantics as capability-card `supersedes`.
3. **Default-key actions after registration.** If an agent is registered but a tool path still calls `default_signer`, the receipt is shared-key (asserted) even though the agent has a key. Decide whether to warn, or to make the resolved-key path the default once a per-agent key exists.

## First slice to build

Slice 1: `agent register` generates a per-agent key and records `actor → key_id` on the card. Self-contained, additive, and it is the prerequisite the other two slices resolve against. Slice 2 (`attest` resolves + signs) is the load-bearing change and deserves the most test coverage, especially the fallback-to-default path.
