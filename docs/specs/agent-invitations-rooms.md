# Agent Invitations and Multi-Agent Rooms — design draft

**Status:** draft, not implemented
**Pairs with:** [workflow-declarations.md](workflow-declarations.md) (PR #107)
**Last updated:** 2026-05-18

## The shift

Treeship today assumes one agent per session. A session opens, one agent attests actions into it, the session closes, a receipt seals.

This spec describes the multi-agent case: **how does a second agent join a session that's already running, prove they belong, and start signing actions that compose with the first agent's work?**

Two shapes matter:
- **Invitations** — single-use, scope-constrained grants that let a new agent join a specific session.
- **Rooms** — long-lived sessions where the participant set evolves over time and the host can mint invitations.

The goal: an elegant solution that doesn't introduce new trust primitives, just composes the ones we already have or are proposing.

## What's already in the box

Before specifying anything new, here's what we'd reuse:

| Existing primitive | Role in the multi-agent flow |
|---|---|
| **Agent Identity Certificate** (`v0.9.8`) | Each participating agent has a persistent identity certificate. The cert's issuer is verified against trust roots. |
| **Approval Use Journal** (`v0.9.9`) | An invitation is structurally an Approval Grant: nonce-bound, single-use, expiring, consume-before-action. The journal already does this. |
| **Portable Agent Identity** (`feat/portable-agent-identity` WIP) | The mechanism by which a new agent gets a keypair inside its sandbox. Composes with cert issuance. |
| **Trust roots** (`v0.10.3`) | The session host's pubkey must appear in the joining agent's trust store before it accepts an invitation as authoritative. |
| **Workflow Declarations** (spec PR #107, roadmap) | A room can declare a workflow that applies to all participants. Invitations can narrow but not exceed it. |
| **Merkle checkpoints** (`v0.10.3+`) | Room checkpoints seal participation events alongside actions. |
| **Canonical signing** (`v0.10.4`) | Invitation and room declarations use the same canonical-with-version-bound pattern. No new crypto. |

The headline: **invitations are approval grants for joining; rooms are sessions with delegated invitation authority.** Both compose what's already shipped.

## The three primitives

### 1. Invitation

A single-use grant authorizing one identity to join one session. Structurally:

```
treeship/invitation/v1
  session_ref:        <session_id>
  issuer:             <pubkey of inviter; must be session host or delegated>
  invitee_restriction: enum
    | Pubkey { fp }          // tightest: only this exact keypair
    | Cert { criteria }      // sweet spot: any agent with matching cert
    | Open                   // loosest: anyone holding the blob; opt-in only
  granted_capabilities:
    workflow_node_ids:  [w1, w2, ...]   // narrowing within the room's workflow
    action_types:       [tool.call, agent.handoff, ...]   // legacy fallback
  expires_at:         <RFC 3339>
  max_uses:           1     // always 1 for v1
  nonce:              <random>
  signature:          <Ed25519 by issuer>
```

The invitation IS an Approval Grant in shape, with `action_type = "session.join"` and a `session_ref` field. The Approval Use Journal already enforces consume-once + replay protection. The new fields are the session reference, the invitee restriction, and (optionally) the narrowed capability scope.

**Paste-ability.** Invitations serialize to an armored ASCII bootstrap blob (`BEGIN TREESHIP INVITATION` / `END TREESHIP INVITATION`), same pattern as the portable agent identity bootstrap. They're paste-safe across sandboxes, terminals, chat. Same threat model: whoever holds the blob can redeem it (subject to the `invitee_restriction`).

### 2. Room

A long-lived session whose participant set evolves over time. Structurally a normal session with these additional fields:

```
treeship/session/v2
  ... existing session fields ...
  room: optional
    room_id:                <stable id>
    host_pubkey:            <Ed25519 pubkey>
    invitation_authority:   enum
      | HostOnly                                // only host signs invitations
      | DelegatedTo([pubkey, ...])              // host + delegated keys
      | Open                                    // any participant can invite
    workflow_ref:           optional <workflow_id>   // applies to all participants
    checkpoint_cadence:     <duration or action count>   // when to seal a checkpoint
    participants:           []                  // populated by join events
```

The room differs from a single-agent session in three ways: it has a `host_pubkey` (the signing authority for invitations), it carries an explicit `participants` list maintained by the timeline, and it commits to a checkpoint cadence (not just on close).

### 3. Participant (join event)

An attestation that an agent presented an invitation and joined the room. Structurally:

```
treeship/session.participant/v1
  session_ref:            <room session_id>
  invitation_ref:         <invitation artifact id>
  joining_agent:          <Ed25519 pubkey>
  joining_agent_cert_ref: optional <cert id>
  joined_at:              <RFC 3339>
  capabilities:           [...]   // copied from the invitation (immutable)
  signature_joinee:       <Ed25519 by joining_agent>
  signature_host:         <Ed25519 by host, countersigning>
```

Two-sided signature. The joining agent signs to say "I'm joining"; the host countersigns to say "I observed this join and confirm it consumed the invitation." Both signatures are required for the participant event to be valid. Without the host countersign, anyone with a leaked invitation blob could append fake participant events.

The Approval Use Journal already supports "consume-before-action with replay protection"; a participant event is structurally an Approval Use against the invitation grant. The journal logic doesn't change.

## The flow

```
HOST                                JOINING AGENT
----                                -------------
treeship room create
  --workflow-ref W
  --invitation-authority host-only
  --checkpoint-every 50actions
→ session_id S, host_pubkey HK

treeship session invite S
  --capabilities [tool.call:Bash]
  --invitee-cert "issuer=org-X"
  --expires +1h
→ invitation_id I,
  bootstrap blob B
                                    treeship session join
                                      --invite <paste B>
                                    → verifies I's signature against HK
                                    → checks invitee_restriction
                                      against this agent's cert
                                    → checks expiry, single-use
                                    → emits participant event P
                                      signed by joining agent

← host receives P, countersigns,
   emits P-final signed by both

                                    treeship attest action
                                      --session S
                                      --workflow-node tool.call:Bash
                                    → references P-final,
                                      respects capability scope

(actions accumulate)
treeship checkpoint S
→ merkle checkpoint over
  participants[] + timeline
```

## Composition with workflow declarations

A room declares a workflow (optional). An invitation can:
- **Narrow** the workflow scope — "this invitation joins you to the room but only authorizes workflow nodes A and B"
- **NOT extend** — invitations cannot grant capabilities beyond what the room's workflow allows

Asymmetric on purpose. The room's authorized envelope is set at room creation. Invitations can only carve out subsets. To grant more, the host signs a new workflow declaration and re-anchors the room.

The trust chain at verification time:

```
trust roots
  → workflow authority (signs workflow declaration)
    → host (signs room session declaration)
      → host (signs invitation)
        → joining agent (signs participant event)
          → joining agent (signs each action)
            → action verified against invitation's capabilities
                                    AND room's workflow
                                    AND joining agent's certificate
```

Every link is an Ed25519 signature. Every link's pubkey is either in trust roots or signed by something in trust roots. Standard certificate chain.

## What we're explicitly NOT building yet

- **No mid-session capability changes.** Once a participant joins with capability set C, that set is fixed. Granting more requires a fresh invitation + a new participant event. (Capability mutation is roadmap.)
- **No leave events.** v1 participants stay in the room until the room closes. Active leave/kick is roadmap.
- **No "discoverable rooms."** Rooms are private; you find them through invitations. A public-room discovery directory sits above this spec.
- **No federated rooms.** A room exists on one host's machine (or Hub instance). Multi-host rooms with state replication are roadmap.
- **No invitation revocation.** v1 invitations are immutable once minted; the only way to "revoke" is to wait for expiry or use them up. Revocation lists are roadmap. (Mitigation: keep invitation expiry short by default.)
- **No quorum / multi-signature invitations.** v1 invitations have one issuer signature. M-of-N quorum is roadmap.
- **No identity transfer between agents.** A participant event binds a specific keypair to a session. The keypair can't be transferred to another agent mid-session. (Different identities = different participants, period.)

## Four open design questions

### Q1: invitation restriction default

Three choices for `invitee_restriction`:
- **(a) Pubkey-restricted by default** — most secure; least convenient. Host has to know the joining agent's exact pubkey in advance.
- **(b) Cert-restricted by default** — production sweet spot. Host says "any agent whose cert is issued by org X." The joining agent's certificate proves their identity to the host.
- **(c) Open by default** — most convenient; least secure. Anyone with the blob joins. Same security model as Slack invite links.

Recommendation: **(b) cert-restricted.** Open invitations exist as opt-in for community rooms. Pubkey-restricted exists as opt-in for high-security cases. Cert-restricted is the default because it matches how production agent deployments work (issued certs from known org/issuer keys).

### Q2: invitation expiry default

How long is a minted invitation valid?
- **(a) 5 minutes** — assumes synchronous handoff. Tight, but a paste-able blob with 5 min TTL leaks much less risk.
- **(b) 1 hour** — practical for most flows.
- **(c) 24 hours** — flexible, but a leaked blob has a real window.

Recommendation: **(b) 1 hour default**, with a configurable max of 7 days. Bound the worst case at the protocol level. Sandboxes that leak invitation blobs into logs/scrollback have a real but bounded exposure.

### Q3: who can invite

The room declares `invitation_authority`:
- **(a) HostOnly** — only the room's original host can mint invitations. Simplest model.
- **(b) DelegatedTo([keys])** — host plus a named list of delegates. Better for rooms with multiple human operators.
- **(c) Open** — any current participant can invite. Most flexible; can lead to invitation sprawl.

Recommendation: **(a) HostOnly by default, with explicit opt-in to (b).** Open mode is roadmap; community rooms with open invite authority can come later once the moderation primitive (kick / mute / probation) is built.

### Q4: participant event countersign requirement

Should the participant event need both the joining agent's signature AND the host's countersign? Or is the joining agent's signature alone sufficient?

- **(a) Both required** — joining is consensual. The host has to acknowledge the join. An attacker with a leaked invitation cannot unilaterally insert a participant event.
- **(b) Single sig is enough** — the invitation's signature on the grant is sufficient authorization. The joining agent presents the invitation, signs the participant event, and joins. Host countersign is observational, not gating.

Recommendation: **(a) both required.** Mirrors the v0.10.4 handoff pattern (handoffs are two-sided signed envelopes). Without host countersign, a leaked invitation blob is unilaterally exploitable. With host countersign, exploitation requires the host's compromised key too.

## CLI surface

```
treeship room create [--workflow-ref W] [--invitation-authority host-only|delegated|open] [--checkpoint-every N]
treeship room close
treeship room status
treeship room participants

treeship session invite <session_id> [--capabilities ...] [--invitee-cert ...] [--invitee-pubkey ...] [--expires DURATION] [--format json]
treeship session join --invite <blob>
treeship session participants

treeship invitation revoke <invitation_id>   # roadmap; no-op in v1
```

The `treeship room` commands are sugar over `treeship session`. A room is just a session with the room field populated.

## Implementation phases

**Phase 1: invitation as approval grant (2-3 days)**
- New canonical type `treeship/invitation/v1` in `packages/core/src/statements/`
- Reuse Approval Use Journal for consume-before-join semantics
- `treeship session invite` and `treeship session join` CLI commands
- No room concept yet; works against any existing session

**Phase 2: room concept (3-5 days)**
- `room` field on session declaration (backwards compat via `#[serde(default)]`)
- `treeship room create / status / participants` CLI sugar
- Checkpoint-every-N-actions cadence
- Participant event canonical type with two-sided signature

**Phase 3: workflow integration (1 week, depends on PR #107)**
- Invitations can narrow workflow scope
- Verifier walks: workflow → invitation → participant → action → conformance
- Session receipt's verifier output gains a `participation_conformance` row

**Phase 4: room hosting + Hub side (separate scope)**
- Hub-hosted rooms (the host doesn't have to be local)
- Push/pull participant events through Hub
- "Room URL" that auto-issues invitations

## Open questions above the schema

- **Anonymous participation.** Can an agent join without a cert ("agent://anon")? The Open restriction allows it but the audit trail loses identity. Is anonymous participation a feature or an antifeature?
- **Revocation.** Aggressive defaults (1-hour expiry, single use, cert-restricted) avoid needing explicit revocation in v1. But a leaked + replayed-within-the-hour invitation IS exploitable. Is that acceptable for v1?
- **Federation.** A room hosted on machine A but joined from machine B requires the joining agent to talk to A. Hub-hosted rooms solve this but require Hub. Worth thinking about which is the default mental model.
- **Composition with treeship-perplexity / treeship-user / kimi skills.** The skills don't currently teach the room/invitation flow. When this lands, all skills need a section on multi-agent participation. Same drift class we've been fighting.

---

*If this direction is right, the next step is to settle Q1–Q4 and let me draft Phase 1 in a non-draft PR. Phase 1 ships invitations alone (no room concept); rooms come in Phase 2 once invitations have lived in main for a beat.*
