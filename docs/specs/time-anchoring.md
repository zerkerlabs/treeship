# Time Anchoring: proving *when*, not just *what*

**Status:** draft, not implemented
**Pairs with:** [transparency-log](./transparency-log.md) (omission detection), [merkle-consistency](./merkle-consistency.md), the `Witness` trait in `statements/action_v2.rs`
**Last updated:** 2026-08-13

## The shift

Every receipt Treeship signs carries a timestamp. That timestamp comes from
`SystemTime::now()` on the agent's own machine and is signed with the agent's
own key.

So a receipt proves *"this key asserted this."* It does not prove *"this
happened then."* Signing stops **third-party** tampering. It does nothing
about **first-party** fabrication, and an agent that holds its key and
controls its clock can emit a chain saying whatever it likes.

This matters because the story we tell about Treeship is a time story: *an
agent spent 11 hours on a dead end, then rewrote the logs to look like 4.*
Today, nothing in the default path prevents or detects that.

This spec is about closing that — and about being precise regarding what
"closing it" can mean, because part of it is not achievable and saying so is
load-bearing.

## Who the adversary is decides the ceiling

The two cases are usually conflated and have completely different answers.

| Adversary | What they control | Ceiling |
|---|---|---|
| **Agent process** — prompt-injected, misaligned, or buggy | its own context and tool calls | **Fully preventable.** The signing key never has to be within the agent's reach. |
| **Operator** — the human or org running the machine | everything local: clock, keystore, binaries, the store | **Not preventable. Only detectable, and only with an external witness.** |

The billing-fraud story is the *operator* case. No local cryptography fixes
it, because the adversary owns everything local. That is not a gap in
Treeship; it is a property of running on someone else's computer. The only
open question is how cheaply the lie becomes visible.

Everything below is written for the operator case. The agent-process case is
mostly custody hygiene (see "Custody" at the end) and is a different piece of
work.

## Two frauds, pointing opposite directions

Conflating these is the main way time-anchoring designs go wrong, because
the obvious mechanism only addresses one of them.

### Inflation — "worked 4 hours, bill 11"

Requires making a receipt appear **older** than it is.

**Solved by upper-bound anchoring.** An OpenTimestamps / Rekor / RFC 3161
attestation proves *"this data existed no later than T."* Backdating one
means forging the underlying log's history. This is the easy direction.

### Omission — "worked 11 hours, show 4"

Requires **hiding** work, not forging it. The agent presents a shorter chain
and discards the rest.

**Anchoring alone does not catch this.** The four-hour chain it hands you is
honestly signed and honestly anchored. It simply is not the whole story, and
nothing about the artifact in your hand reveals that.

What catches omission is **discoverability**: anchors must be findable *by
identity*, so an auditor can ask "every anchor ever published under
`agent://x`" and notice a 09:00 chain root absent from the report. A bare
`.ots` file the agent chooses to hand you cannot do this. A transparency log
searchable by key can.

That is [transparency-log](./transparency-log.md)'s job, and its honest
constraint applies here unchanged: completeness is detectable for **committed
sets**, not absolutely. An agent that never anchored anything has hidden
nothing detectable — it has simply produced no evidence, which the verdict
must say plainly rather than scoring as clean.

**Design consequence:** upper-bound anchoring and a discoverable log are not
alternatives. Each defeats a fraud the other does not.

## Bracketing a session

An upper bound alone still leaves the middle unconstrained. Two bounds
bracket it.

### Upper bound — "existed no later than T"

Anchor the chain head. Options, which fail differently and should coexist:

| Mechanism | Latency | Trust | Discoverable by identity |
|---|---|---|---|
| **Hub checkpoint** | immediate | trust the Hub | yes (already indexed) |
| **Rekor** | seconds | trust the log operator + its own transparency | yes, searchable by key |
| **OpenTimestamps / Bitcoin** | ~1 hour | trustless | no — the `.ots` file must be presented |
| **RFC 3161 TSA** | immediate | trust the TSA | no |

OTS is the only trustless option and the only one with no discoverability, so
it is a complement to Rekor rather than a replacement.

### Lower bound — "existed no earlier than T"

Less familiar, and the half that makes bracketing work.

Roughtime: the client sends a nonce, the server returns a signature over
`(nonce, time)`. Because the signature covers *your* nonce and you could not
have predicted it, holding that response proves you had the nonce at or after
`T`. Derive the nonce from the current chain head and you have proven *the
chain head existed no earlier than T*.

Chain the nonces — each request's nonce derived from the previous head — and
the session carries a verifiable spine of "no earlier than" points that an
agent cannot construct retroactively without the servers' cooperation.

### Cadence is the resolution

**The anchoring interval *is* the precision of the proof.** Anchoring only at
session close proves nothing about the middle: the whole session collapses to
one point. A session anchored every 15 minutes has 15-minute resolution.

Bitcoin block time plus OTS calendar aggregation puts the trustless floor
around an hour. Hub and Rekor anchoring can be far tighter. Both numbers
should be visible to a reader rather than implied.

## Coverage is a verdict, not a boolean

Whatever gets built, an agent can always **not use it** for part of the work.
Nothing prevents that, so the verifier must report it.

`anchored: true` is the wrong output. It flattens three materially different
situations into one word — the same failure as `NoRevocationSource` resolving
to a passing exit code, where the honest detail exists and the top-level
answer discards it.

The verdict needs at minimum:

```json
{
  "anchoring": {
    "coverage": "continuous | endpoint-only | none",
    "interval_seconds": 900,
    "first_anchor": "2026-08-13T09:00:00Z",
    "last_anchor":  "2026-08-13T20:00:00Z",
    "unwitnessed_span_seconds": 0,
    "mechanisms": ["hub", "rekor"]
  }
}
```

`unwitnessed_span_seconds` is the number that matters: **the longest stretch
of claimed work with no external witness.** For the 11-hour story, an honest
session reports a small number and a fabricated one reports the whole
session, whatever its receipts claim.

A verifier gating on time MUST be able to require a maximum. Never expose a
single boolean that a caller could read as "time is proven."

## What's already in the box

| Existing primitive | Role here |
|---|---|
| **`Witness` + `WitnessAuthority`** (`statements/action_v2.rs`) | Already models external corroboration, already requires `observer != actor`, already fails closed via `NoWitnessAuthority`. No implementation exists. A time anchor is a witness whose observation is "I saw this digest at T". |
| **Merkle checkpoints** (`v0.10.3+`) | The thing to anchor. Anchoring a checkpoint root covers every receipt beneath it. |
| **Rekor anchoring** (Hub, `internal/rekor`) | Already wired on push, best-effort. Needs its result surfaced in verification rather than stored and ignored. |
| **`checkpoint_cadence`** ([trusted-rooms](./trusted-rooms.md)) | Cadence is specified — for rooms only. Ordinary sessions have none. |
| **Transparency log** ([transparency-log](./transparency-log.md)) | The discoverability half. Omission detection lives there, not here. |

The gap is not primitives. It is that none of this is on by default, and
nothing reports coverage.

## Honest constraints

State these or the surface over-promises, which is the failure mode the
2026-08 audit filed as P1-10.

- **Anchoring proves order and existence, never truth.** A receipt attesting
  a thing that did not happen, anchored punctually, is a punctual lie. This
  bounds *when the claim was made*, not whether the claim is correct.
- **Absence of an anchor is not proof of wrongdoing.** Offline work,
  air-gapped machines, and network failures all produce unanchored sessions.
  The verdict reports coverage; the *policy* about acceptable coverage
  belongs to the verifier, not to us.
- **The lower bound depends on live servers.** Roughtime cannot be obtained
  retroactively — which is the point — but it also cannot be obtained
  offline. Offline sessions get an upper bound only, and should say so.
- **Trustless and discoverable are different properties.** OTS gives the
  first, Rekor the second. Claiming one implies the other is the kind of
  overstatement that makes integrators pick the wrong gate.

## Slices

1. **Cadence on by default for sessions.** Extend `checkpoint_cadence` beyond
   rooms; push checkpoints as they seal rather than only at close. Uses
   machinery that exists today, and immediately makes omission expensive:
   discarding an 11-hour chain means discarding anchors already pushed under
   your identity.
2. **Coverage in the verdict.** Compute and report the block above.
   `treeship verify --max-unwitnessed <duration>` for callers that gate on it.
   Worth doing early — it makes the current weakness *visible* before it is
   fixed, which is the honest ordering.
3. **A real `WitnessAuthority`.** Implement the trait against trust roots so
   Hub and Rekor anchors count as witnesses instead of being ignored. The
   `observer != actor` rule is already specified and is the load-bearing part.
4. **OpenTimestamps backend.** Trustless upper bound, no wallet needed
   (calendar servers aggregate). Pairs with, does not replace, Rekor.
5. **Roughtime lower bound.** Nonce chained to the previous head, so sessions
   are bracketed rather than only capped.

## First slice to build

**Slice 2, then slice 1.**

Reporting coverage before improving it looks backwards, and is deliberate. A
verifier that says `unwitnessed_span: 11h` on today's receipts tells the truth
about what Treeship currently proves, and makes the case for slice 1 with
evidence instead of assertion. Shipping cadence first would improve the
number nobody can see yet.

It is also the slice that prevents the marketing claim from getting ahead of
the implementation again — once coverage is in the verdict, "you always know
what your agent did" is falsifiable against our own output.

## Open questions

- **Who pays for anchoring?** Rekor is free and rate-limited; OTS calendars
  are free and best-effort. A busy agent anchoring every minute is a load
  question before it is a crypto question.
- **What is the default cadence?** Too tight and it is noisy and expensive;
  too loose and the resolution is useless. 5–15 minutes is the guess and
  should be measured rather than picked.
- **Does an unanchored session fail closed?** Leaning no by default — offline
  work is legitimate — with `--max-unwitnessed` for callers that need it.
  This is the same shape as revocation's `Unknown`, and should be decided
  alongside it rather than separately.
- **Custody (separate work).** Against the *agent-process* adversary the key
  should sit behind a daemon under a different uid, or in hardware (Secure
  Enclave / TPM / YubiKey — the audit's P2-4). That closes a different
  attacker and is out of scope here, but the two are often confused and the
  distinction belongs somewhere written down.
