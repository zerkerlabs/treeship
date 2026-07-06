# Registry Topology: what the Hub is trusted for, and how agents verify each other without it

**Status:** draft, not implemented (analysis section reflects shipped behavior)
**Pairs with:** [transparency-log](./transparency-log.md), [agent-resolver](./agent-resolver.md), [work-history](./work-history.md), [protocol-integration](./protocol-integration.md)
**Last updated:** 2026-07-06

## Why this spec exists

On 2026-07-06 a routine deploy wiped the production Hub's entire database (no persistent volume — an ops mistake, since fixed). The incident was the best possible stress test of the trust model, and this spec captures what it proved, what it demands, and the two surfaces it motivates: **presentation** (agent-to-agent verification with no registry in the loop) and **private registries** (the same protocol inside one trust domain).

Three empirical results from the incident:

1. **Nothing of cryptographic value was lost.** Every card, receipt, checkpoint, and proof lives client-side; recovery was `hub attach` + re-`publish`. "The Hub creates nothing" is not a slogan, it is a recovery procedure.
2. **The monitoring caught the operator.** A third party who had audited before the wipe permanently detects the discontinuity: `append-only INVALID — chain not contiguous at tree_size 57`. Re-publishing restores *content* but cannot forge *continuity*. The transparency log holds its operator to account, which is the entire point of having one.
3. **Availability is the Hub's only real job** — and therefore the only thing "protecting the database" means.

## The trust table

The question is never "is there a server?" (TLS has CAs, DNS, and CT logs; nobody calls it centralized). The question is **what breaks when the server lies or dies**:

| Property | Guaranteed by | What a malicious/dead Hub can do |
|---|---|---|
| Integrity (is this receipt real?) | Ed25519 + client-side verification; the Hub holds no keys | Nothing. It serves bytes it cannot alter undetected |
| History (was the log rewritten?) | Merkle consistency proofs + client witnessing | Try, and be caught by any prior witness |
| Completeness (is anything hidden?) | `evidence_anchor` commitments + witnesses | Withhold — detectably, for committed sets |
| Availability (can I fetch it now?) | **The Hub. Its only real job.** | Die. Lookups fail; nothing becomes false |
| Freshness (is this still unrevoked *now*?) | The Hub, within a staleness window | Serve stale — bounded by the verifier's policy |

Corollary for operations: the Hub's database needs **durability, not secrecy** — it holds only public, signed artifacts (metadata + anchors, never payloads). Its real threat list is loss (volumes/backups), withholding (more witnesses), spam (per-dock quotas, future), and metadata privacy (the argument *for* private registries, below). The crown jewels remain client keystores.

## The load-bearing theorem

> **Signatures decentralize the past. A log exists to answer the two questions signatures cannot: "is this still true?" (freshness) and "is this everything?" (completeness).**

No topology eliminates this; systems that claim to (global consensus on every read) just make everyone pay for it. Treeship's position is the honest optimum: verification of the past needs no registry at all, and freshness/completeness carry an explicit, verifier-chosen staleness bound.

## Surface 1: Presentation — mutual TLS for agents

Today resolution is registry-first (`resolve --hub`), which is backwards for the agent-to-agent case: in TLS the server *hands you* its cert chain. Presentation fixes the shape — the agent carries its proof and produces it to whoever asks.

### The bundle

`treeship present agent://x --out x.presentation` — a profile over the existing bundle/package machinery (NOT a new subsystem), containing:

- the current capability card (signed, typed)
- **the full certificate chain**: card → AgentCert → ship key, so a counterparty pins one Ship root and verifies everything under it (this fixes the leaf-pinning gap: today `publish` ships no chain and remote verifiers must pin each agent key directly)
- **the staple**: latest witnessed checkpoint + this card's inclusion proof + the consistency chain — freshness evidence, self-contained
- profile `identity` (the above, kilobytes) or `track-record` (adds `session.v1` records + proofs — the verifiable CV, from [work-history](./work-history.md))

`treeship verify-presentation x.presentation [--max-staple-age <dur>] [--require-class <class>]` re-verifies everything offline against the verifier's own trust roots and reports each fact with its grade.

### Static vs. challenge — labeled, never conflated

A presentation file is **replayable**: it proves the *record* is real, not that your counterparty is its subject. Two modes, honestly labeled:

- **Static** — attach to a PR, an A2A AgentCard, a job posting. Proves: this identity exists, holds this card, has this anchored history.
- **Challenge** — `treeship present --challenge <nonce>` additionally signs the verifier's fresh nonce with the agent key. Proves: *the party you are talking to* controls this identity, now. This is the handshake mode; gateways and rooms use nothing weaker.

### Revocation honesty

Offline, absence cannot be proven — a liar omits, and the Hub signs nothing so it cannot vouch. The output states the bound instead of faking a guarantee:

```
revocation: none included — current as of checkpoint #47 (staple 12m old)
            for currency, audit a log
```

Verifier policy picks the tolerance (a trading gateway: minutes, plus an async log check behind the accept — the CT accept-then-audit pattern; a code-review bot: a day).

## Surface 2: Public and private registries

**The public Hub (api.treeship.dev) is the Let's Encrypt move** — the free utility that makes the format default. It stays legitimate under three conditions, all already true: the protocol never trusts it; anyone can run one (a single open-source binary + SQLite, `--endpoint` points anywhere); and witnessing + consistency proofs make it accountable to its users.

**Private registries** are the same binary inside one trust domain — the enterprise story ("your evidence never leaves your VPC") and the answer to the public log's one genuine sensitivity, metadata (the log carries no payloads, but who-did-what-kind-of-thing-when is traffic analysis). Needs beyond self-hosting today: read-side auth, tenancy, retention policy — pull-driven, not speculative.

**Cross-anchoring** is the pattern that joins them: a private hub periodically publishes *its checkpoint hash* into the public log. One hash discloses nothing, but gives the private registry public tamper-evidence — private contents, public accountability. Composes entirely from shipped primitives.

## The decentralization ladder

Each rung is pull-driven; none is required for the previous to be sound:

1. **Now** — one public hub, client-side verification, witnessing. The server cannot lie undetected, only vanish.
2. **Presentation/stapling** — agents carry proofs; the hub becomes optional per interaction (this spec's surface 1).
3. **Multi-hub** — publish to N, resolve from any, clients cross-check; hubs become interchangeable commodities.
4. **Witness cosigning** — independent parties countersign checkpoints; verifiers demand K-of-N. The public hub is then non-authoritative even for freshness.

## Slices

1. **Chain delivery.** `publish` pushes the AgentCert alongside the card; `resolve` (local + remote) walks card → AgentCert → Ship root, so pinning the ship suffices. Prerequisite for presentation; independently fixes the leaf-pinning gap.
2. **`treeship present` + `verify-presentation`** — static mode, `identity` profile, staple included; verification fully offline with `--max-staple-age`.
3. **Challenge mode** — nonce signing + verification; the handshake.
4. **`track-record` profile** — session.v1 records + proofs in the bundle (gated on work-history slices).
5. **Consumers** — the gateway verifies challenge-mode presentations before releasing tool calls; the A2A middleware attaches a static presentation to the AgentCard it serves. A presentation surface without a consumer is a brochure; these two are named up front.

Deferred (pull-driven): private-registry auth/tenancy, cross-anchoring command, multi-hub resolve, witness cosigning.

## What is explicitly out of scope

- **Blockchain anchoring.** The staleness trade-off is fundamental; paying consensus costs on every read to pretend otherwise is not honesty, it is marketing.
- **Hub-side verdicts of any kind.** A hub that vouches is a hub that can lie. The Hub serves bytes; verifiers decide.
- **Global naming.** Unchanged from [vision](./vision.md): gated on a real buyer.
