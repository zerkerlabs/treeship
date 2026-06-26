# Trusted Rooms Vision

Status: draft product spec

Treeship should make collaborative agent work in Slack-style rooms verifiable without becoming a chat app, a memory vendor, or a policy engine. The room is the coordination surface; Treeship is the trust, provenance, and reporting layer around it.

## Why now

Claude Tag popularizes a pattern that will spread across agent products: a team tags an AI coworker in a channel, the agent acts asynchronously with scoped tools and memory, and admins need logs, spend limits, and access controls per channel. That creates a natural trust boundary: the **room**.

Treeship already has the primitives needed to make that boundary verifiable:

- signed artifacts and receipts
- agent identities and capability cards
- human approvals
- session reports
- handoffs
- Hub reports
- Merkle/transparency logs
- resolver and capability provenance

Trusted Rooms packages those primitives into an organizational product.

## Relationship to Room Sessions

This spec does **not** introduce a competing room primitive. Treeship already has the lower-level Room Sessions direction:

- Concept: `docs/content/docs/concepts/room-sessions.mdx` — “one room, many agents, one Merkle-sealed report.”
- Protocol draft: `docs/specs/agent-invitations-rooms.md` / PR #109 — invitations let a second agent join a running session, prove it belongs, and sign composing actions.
- Built today: `treeship session invite` / `treeship session join` Phase 1.

So, in protocol terms, a “room” is a **session-based multi-agent room**: invitation-driven, participant identities remain separate, and the output is one shared verifiable session/room report. There is no separate `trusted_room.v1` predicate in this draft.

**Trusted Rooms is the product layer above Room Sessions.** It maps an organization/channel boundary — for example Slack `#engineering` or a Claude Tag channel identity — onto existing Treeship primitives: session invitations, agent certificates, capability cards, approvals, handoffs, session/room reports, Merkle checkpoints, transparency logs, resolver entries, Hub URLs, and zmem memory-use proofs.

## Product definition

A **Trusted Room** is a verifiable collaboration boundary that binds:

- organization identity
- channel/room identity
- human participants
- AI agents
- allowed tools and data sources
- room memory scope
- approval policy
- budget policy
- signed room/session reports

The room can be Slack today, Farcaster/Zerker gateway tomorrow, or any other collaboration surface. Treeship should not own the chat surface; it should issue and verify the trust layer for the surface.

## Identity model

Use stable actor URIs, not display names:

```text
org://slack/<team_id>
room://slack/<team_id>/<channel_id>
human://slack/<team_id>/<user_id>
agent://claude-tag/<team_id>/<channel_id>
agent://hermes/<profile-or-install-id>
agent://perplexity/<surface-or-workspace>
agent://farcaster/<gateway-agent-id>
```

Display names, personas, avatars, and role labels are metadata. The stable URI is what gets signed.

## Core primitives to package

### 1. Room Certificate

A signed declaration that a room exists and defines its boundary.

Captures:

- room URI
- organization URI
- owners/admins
- allowed agent identities
- allowed human identity providers
- memory scope
- default retention/publishing policy
- policy digest

### 2. Agent Room Capability Card

A room-scoped capability card for one agent.

Captures:

- agent URI
- room URI
- allowed tools/connectors
- allowed repositories/data sources
- forbidden actions
- escalation rules
- spend/budget class
- provenance grade: captured / checked / asserted

### 3. Human Identity Binding

A signed binding from platform identity to Treeship human URI.

Captures:

- platform: Slack, Farcaster, GitHub, etc.
- stable platform IDs
- display metadata
- role/persona claims
- issuer/admin who bound it
- expiry/rotation metadata

### 4. Room Session Receipt

A signed report for work that happened in a room.

Captures:

- requester(s)
- agent(s)
- task/thread IDs
- room policy digest at task start
- approvals used
- tool calls / command boundaries / artifacts
- handoffs
- budget consumed
- final outputs and verification links

### 5. Room Report

A higher-level report for a time window.

Answers:

- What did agents do in this room this week?
- Who requested each task?
- What tools/data did they use?
- Which tasks required approvals?
- Which restrictions/budget gates fired?
- What receipts prove it?

### 6. Room Policy Gate

A pre-action gate whose verdict is itself signed.

Examples:

- Claude may read support tickets but not billing exports in `#support`.
- Hermes may run CI but not deploy without approval in `#engineering`.
- Perplexity may search external web but not write to repo in `#research`.
- Channel budget is $500/month or 20M tokens/month.

Treeship does not need to become the policy runtime initially. It can record the declared policy, the gateway verdict, and the signed evidence that the action complied or was denied.

## Reference architecture

```text
Slack / Claude Tag / Hermes / Perplexity / Farcaster gateway
        |
        | room events, requests, tool events, approvals
        v
Farcaster gateway / integration adapter
        |
        | signs or asks Treeship CLI/SDK to sign
        v
Treeship artifacts + room/session reports
        |
        +--> local verifier
        +--> Treeship Hub share URL
        +--> transparency log / Merkle anchors
        +--> zmem room-scoped memory index
```

Farcaster is the control plane for routing, policy, observability, and product surfaces. Treeship is the evidence layer. ZMem (`zmem`) is the room-scoped verifiable memory layer.

## Claude Tag alignment

Claude Tag introduces four patterns Treeship should support natively:

1. **Multiplayer agent identity** — one Claude per channel/team context.
2. **Scoped memory** — channel memories do not leak across departments.
3. **Admin-scoped tools/data** — tools and data are provisioned per channel.
4. **Spend/task logs** — admins can see who requested work and what it cost.

Treeship should package these as room-level certificates, capability cards, signed task receipts, and room reports. The pitch is not “replace Claude Tag.” The pitch is:

> Bring your own room agent. Treeship makes the room’s work verifiable.

## Product surfaces

### CLI

Possible commands:

```bash
treeship room init slack://T123/C456 --name engineering-agents
treeship room bind-human --slack-user U123 --as human://slack/T123/U123
treeship room add-agent agent://claude-tag/T123/C456 --tools github,jira,linear --budget tokens:20M/month
treeship room start-session slack://T123/C456 --thread 171234.567
treeship room report slack://T123/C456 --since 7d
treeship room verify <room-report-id>
```

### Hub

Possible pages:

- `/rooms/<room_id>` — room trust boundary and current policy digest
- `/rooms/<room_id>/reports/<period>` — room report
- `/receipts/<session_id>` — task/session receipt
- `/agents/<agent_id>` — room-scoped agent identity/capability history

### Slack/Farcaster gateway

Possible bot commands:

```text
/treeship room status
/treeship approve <task>
/treeship report today
/treeship budget
/treeship why-denied <task>
```

## Boundaries

Treeship should remain within its direction:

- **Do:** sign, verify, package, publish, and audit evidence.
- **Do:** model room identities, agent capabilities, approvals, handoffs, and reports.
- **Do:** integrate with Farcaster/zmem/Slack/Claude Tag as sources and sinks.
- **Do not:** become the primary chat UI.
- **Do not:** claim to observe actions it did not capture.
- **Do not:** store raw private channel content unless explicitly configured.
- **Do not:** make unverifiable memory claims; use zmem or signed memory digests.
- **Do not:** overclaim policy enforcement when Treeship only recorded a gateway verdict.

## MVP wedge

Start with one room surface and one agent path:

1. Slack room identity binding.
2. Hermes or Claude Code agent identity in that room.
3. Treeship session receipt per task/thread.
4. Room report for a day/week.
5. Budget and approval events as signed artifacts.
6. Publish/share local-verifiable report URL.

The proof-of-value demo:

> In `#engineering-agents`, @Claude, Hermes, and a human collaborated on a task. Here is the Treeship room report showing who requested it, which agent acted, what tools were allowed, which approvals were used, what it cost, and which receipts verify every claim.

## Open questions

- Which gateway is source-of-truth for room policy: Farcaster, Slack app config, or Treeship Hub?
- What is the first supported human identity provider: Slack only, or Slack + GitHub?
- Should zmem store signed memory digests, full encrypted memories, or references to external memory stores?
- What room report is useful enough to sell: daily digest, compliance export, incident report, or PR/task report?
- How should room budgets be represented: token spend, dollar spend, action count, tool-specific quotas, or all of the above?
