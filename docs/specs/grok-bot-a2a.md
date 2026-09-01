# Grok Bot A2A verification — implementation (reference host)

**Status:** draft, not implemented
**Product:** [agent-to-agent-verification](./agent-to-agent-verification.md)
**Harness note (H2A verbs only):** [grok-bot-h2a](./grok-bot-h2a.md)
**Sources checked:** docs.x.ai/grok-bot/* (2026-09-01), Lauren @poteto pstack Pt.1 (2026-08-31), Treeship CLI/bridges as of this repo
**Last updated:** 2026-09-01

This is the build spec. Grok Bot is the first host. The adapter in §4 is what Claude, Codex, Hermes, and `@treeship/a2a` copy. Do not invent a second handshake for those hosts.

---

## 0. Three systems, three questions

| System | Question it answers | Proof | Who is in the loop |
|---|---|---|---|
| **Lauren / pstack** | Did *this* change work in *this* app? | Video, screenshots, `/control-app`, Feature Map | The agent, until green. Human is not the verifier. |
| **Grok Bot (docs)** | Can teammates finish work and hand it off on one account computer? | Conversation cards, `/workspace` files, approvals, screenshots the docs already ask for | Human for approvals. Bots route work among themselves. |
| **Treeship** | Should *this* ship act on work from *that* agent, live, with no registry? | `present` + `--challenge` against **your** pinned `cert_issuer` | The receiving agent. Fail closed before it acts. |

We are building the third, on the second's computer, and optionally attaching the first as evidence on the handoff.

Do not name anything a "verification skill." That phrase is Lauren's close-loop product.

---

## 1. Source map (what is actually there)

### 1.1 What Lauren specified (pstack Pt.1 + example repo)

From [the article](https://x.com/poteto/status/2094457600259842065) and [poteto/verification-skill-example](https://github.com/poteto/verification-skill-example):

| Piece | What it is | Treeship analogue | Do we build it? |
|---|---|---|---|
| `/create-verification-skill` | Meta-skill that writes a per-app skill + CLI + Feature Map | None. Wrong loop. | **No.** |
| `/maintain-verification-skill` | Daily refresh of Feature Map + control CLI | A Grok *routine* that re-runs *our* bootstrap (wipe recovery) | Bootstrap only, not her Feature Map. |
| "Build the Lever" | Small agent-friendly CLI (`control-*.mjs`), JSON, `--dry-run`, rich `--help` | Treeship CLI already is this lever for identity/liveness | Use `treeship`, do not write a second control CLI for Grok's Electron UI. |
| Feature Map | Markdown map of app features for token-cheap navigation | Capability card (`attest card`) is identity/capability, not UI geography | Do not clone. Optional later: `attest card --from-harness` of *our* tools. |
| `/control-app` + video/screenshots | Agent drives the app via CDP/CLI until green | `treeship wrap -- <her CLI>` then attach session id to the handoff | **Only if that CLI is on the machine.** Slice 4. |
| `/poteto-mode` | Pin pstack on every turn (Cursor custom mode; Grok: install plugin then type `/poteto-mode`) | Our packaged Grok skill, invoked with `/treeship` | Yes, as a **skill**, not a mode clone. |
| Cloud agents + `/swarm` | Cursor cloud VMs in parallel; Grok Bot is the coordinator ("spawn a cloud agent…") | Out of scope. Her infra. | **No.** |
| Dr Eggbot | Bot that teaches other bots pstack | A Treeship-capable Bot description + share link | Share-a-Bot copy of our skill, after v1 works. |
| pstack plugin | `https://x.ai/bot/plugin/9717366` | Our distribution path is the same: Settings → Plugins / share link | Package a Treeship skill this way. |

Her definition of verification, in her words: the agent **verifies its own work** and **keeps going until it succeeds** without you as the bottleneck. Proof is **video and screenshots**. That is close-loop agency inside one team's app.

That is not agent-to-agent verification. A Grok Bot can pass `/control-app` and still be a replayed presentation to Claude.

### 1.2 What Grok Bot docs support (do not mix with Grok CLI)

Pages read 2026-09-01: [overview](https://docs.x.ai/grok-bot/overview), [get-started](https://docs.x.ai/grok-bot/get-started), [computer-and-apps](https://docs.x.ai/grok-bot/computer-and-apps), [files-and-results](https://docs.x.ai/grok-bot/files-and-results), [skills-routines](https://docs.x.ai/grok-bot/skills-routines-and-automations), [chat-and-collaboration](https://docs.x.ai/grok-bot/chat-and-collaboration), [bots](https://docs.x.ai/grok-bot/bots), [approvals](https://docs.x.ai/grok-bot/approvals-security-and-privacy), [settings](https://docs.x.ai/grok-bot/settings-and-notifications), [troubleshooting](https://docs.x.ai/grok-bot/troubleshooting).

**Confirmed levers (v1 may use these):**

| Lever | Quote / fact | How we use it |
|---|---|---|
| Persistent cloud VM | "browser, filesystem, and terminal" | Install and run the Treeship CLI here. The human never opens a shell. |
| `/workspace` | Durable project files; "Ask Bots to keep durable project files there" | `TREESHIP_CONFIG=/workspace/treeship/config.json`. Inbox/outbox live here. **Not `TREESHIP_HOME`** -- see §2.7. |
| Shared computer | "Every Bot on your account uses the same computer." Files, cookies, CLI creds shared. "Do not use separate Bots as a security boundary." | **One ship, one keystore, one actor `agent://grok` per account.** Intra-roster "A2A" cannot be live-key proof. |
| Bot → Bot async message | "A Bot can send an asynchronous message to another Bot. The receiving Bot wakes…" | Transport for envelopes *on the same account*. Text pointer + file in `/workspace`. |
| Group chat | 2–6 Bots. Bot-to-group handoff messages are **text-only**. Images must go DM. | Pointers only in groups. Presentation files stay in `/workspace` or a DM. |
| Skills | "reusable set of instructions"; save from a finished task; `/` to invoke; Settings → Plugins → Yours to enable per Bot; Marketplace for packaged skills | **This is the install format.** Prose, not `SKILL.md`. |
| Teach a task | Record browser up to 10 minutes → draft skill | Not used for handshake. Optional for close-loop evidence later. |
| Routines | Schedule / event (Cursor Slack/GitHub integrations). Up to 50 per Bot. Test run does real work. | Nightly re-bootstrap after package wipe. |
| Connectors / Plugins | Settings → Plugins. `@` attaches a connector. Account-wide, not per-Bot. | Distribution + (if custom MCP ever appears here) later tools. |
| Approvals / Auto Review | Allow once / Deny / Always allow. Require Approval wins. Rules sync desktop → this computer. | Highest-value *receipt* if we can observe the event. Undocumented as a file/API. Slice 3b stays blocked until we can read it. |
| Share a Bot | Public link → recipient **copies config**. Does not share computer, logins, or history. | How another *account* gets our skill. New computer = real A2A peer. |
| Evidence culture | Docs already tell users to ask for screenshots, action logs, source links, "actions waiting for approval" | Close-loop *style* without pstack: wrap the commands that produced those artifacts. |
| Cursor account | Sign-in is Cursor. Plans: SuperGrok / Cursor Pro+ / Teams. No Linux desktop app. | Identity of the *operator*, not the agent. Do not treat Cursor login as `cert_issuer`. |
| Local computer | Separate; default Ask every time. | Never required. All Treeship work is on the cloud VM. |
| Wipe / recover | "Treat temporary directories, **manually installed packages**, and uncommitted application state as replaceable." Update/Recover preserve durable state; Reset can discard unsaved work. | Bootstrap **is** the recovery path. Idempotent or it is wrong. |

**Not documented on Grok Bot (do not design v1 on these):**

| Tempting source | What it actually is | Rule |
|---|---|---|
| `grok mcp add` / `~/.grok/config.toml` | [Grok CLI](https://docs.x.ai/build/features/mcp-servers) (coding agent), not Grok Bot | Ignore for this host. |
| grok.com custom MCP connectors | [Grok chat](https://docs.x.ai/grok/connectors), public URL, not the Bot VM | Unverified on Bot. Bonus path only after a human confirms Settings → Plugins accepts a custom MCP URL. |
| Overview "connectors/MCP where available" | One clause, no schema, no stdio, no env vars | CLI path is v1. |
| Per-Bot isolation | Explicitly denied | No `agent://grok/piper` key. |
| Thread id / approval journal / X handle on the VM | Not in docs | If a process cannot read it, do not claim it. |
| Feature Map, `/control-app`, `/swarm` | Lauren / pstack, not xAI Bot docs | Optional wrap if present on disk. |

### 1.3 What Treeship already ships

| Capability | Where | Ready for A2A? |
|---|---|---|
| Per-agent key (`agent register --own-key`) | CLI; MCP/A2A bridges provision on start | Yes. Grok bootstrap must call this. |
| Presentation file (card + chain + staple + revocations) | `treeship present` | Yes. |
| Live challenge | `present --challenge` / `verify-presentation --challenge`; `session mint-challenge` (128-bit OsRng, JSON) | Yes. Nonce floor is 32 chars (`gate.ts`). |
| Pin ship, not leaf | `trust add --kind cert_issuer` | Yes. Export via `keys export`. |
| Signed handoff | `attest handoff --from --to --artifacts` | Yes, but a handoff without a live verify is still accepted. Must become visible as `asserted`. |
| Wrap / session / package verify | CLI | Receipt of *this* side's work. Not the inbound gate. |
| `@treeship/mcp` | 5 tools: `session_status`, `session_event`, `attest_action`, `verify`, `session_report` | **Missing** `mint-challenge`, `present`, `verify-presentation`, `handoff`. CLI-only on Grok until we add them. |
| `@treeship/a2a` | Attests task + injects `treeship_receipt_url`; AgentCard extension | Attests **after**. `onTaskReceived` never refuses. |
| `bridges/a2a/src/gate.ts` | `mintChallenge` + `gateInbound` + `TREESHIP_A2A_UNVERIFIED=1` | **Written, tested, not exported, not called.** Middleware still "must never break the agent path." |
| Capability cards | `--from-harness`, `--tools-json`, `--from-a2a` | Optional on Grok. Do not auto-capture MCP meta-tools. |
| Hub / resolve | Optional transport | Not in the handshake. |
| Approval Use Journal | CLI `approve` + wrap `--approval-nonce` | Ready *if* we can see Grok's Allow/Deny. |
| `TREESHIP_HOME` | Rig: wins as bare base dir | Set to `/workspace/treeship`. |
| Host skills | Claude plugin, Codex/Kimi/Hermes/OpenClaw `SKILL.md` | Those hosts already have a file. Grok does not. Same *gate*, different *capture*. |

Honest leftover (do not sell past this): the gate proves **who is live** and **which ship you pinned**. It does not prove the sender's task result is true. That is wrap/session on each side, or Lauren's loop if attached.

---

## 2. Design constraints that decide the architecture

1. **Same-account Grok ↔ Grok is not live A2A.** Shared filesystem and shared keystore mean Bot B can read Bot A's key and sign a challenge as `agent://grok`. Grade those handoffs `custody: asserted (same_computer)`. `asserted` is the grade; `same_computer` is the reason. Do **not** introduce `same_computer` as a fourth grade word -- `scripts/check-verdict-vocabulary.py` exists because the 2026-08 dogfood found three vocabularies in one product, and the sanctioned set is `checked | captured | asserted`. Print the reason, never a new grade. The docs told us this.
2. **Real A2A is inter-host.** Grok account computer ↔ Claude / Codex / Cursor / another person's Grok (share-a-Bot created a *new* computer) / an A2A server. Different ship key, isolated per §2.7.
3. **The human is not the installer.** Bootstrap is a command the *Bot* runs. Skill text tells it when.
4. **Transport is files + a pointer.** Grok has no documented RPC. Group messages cannot carry the presentation bytes as an image. Write `/workspace/treeship/outbox/<id>.json`, paste the path (and for inter-host, the file contents or a hub URL).
5. **MCP is not the plan.** Add it the day Plugins accepts a user MCP server on the Bot VM.
6. **Lauren's lever is evidence, not the gate.** If `/control-app` exists, wrap it. Never block A2A on it.

7. **`TREESHIP_HOME` does not isolate a ship. Verified 2026-09-01 by running it.**
   The CLI resolves its config as `--config` → `TREESHIP_CONFIG` → `.treeship/config.json`
   walking up from cwd → `~/.treeship/config.json`. `TREESHIP_HOME` is read by
   `packages/rig`'s ledger and recorded in the receipt env allowlist; it does
   **not** move the ship or the keystore.

   Worse, config alone is not enough: `treeship present` failed with
   *"Checkpoints live in `~/.treeship/merkle/checkpoints` and are NOT scoped by
   `--config`"*. Two ships sharing a `$HOME` collide in the checkpoint store.

   **Isolation requires both `HOME` and `TREESHIP_CONFIG`.** On the Grok VM there
   is one account computer and one ship, so this matters mainly for the two-ship
   acceptance test -- but the bootstrap must set `TREESHIP_CONFIG`, not
   `TREESHIP_HOME`, or it will silently adopt whatever ship the cwd walk finds.

8. **`onboard` takes a bare name and requires a capability source.** The real
   form is `treeship onboard grok --tools "a2a.*"`, not `onboard agent://grok
   --own-key`; `--own-key` belongs to `agent register`. Onboard with no
   `--from-harness` / `--tools-json` / `--from-a2a` / `--tools` exits with
   *"no capability source"*.

---

## 3. Protocol (host-independent)

No new cryptography. This is the existing handshake as a four-message file protocol.

### 3.1 Envelope

One JSON object per file. UTF-8. No secrets.

```json
{
  "spec": "treeship.a2a/v1",
  "kind": "offer",
  "id": "a2a_01HZX...",
  "from": "agent://grok",
  "to": "agent://claude",
  "created_at": "2026-09-01T15:04:05Z",
  "reply_to": null,
  "body": {}
}
```

`kind` values:

| kind | Who writes it | Body |
|---|---|---|
| `offer` | Sender | `{ "intent": "review-pr", "summary": "...", "artifact_paths": ["..."], "presentation_path": null }` |
| `challenge` | Receiver | `{ "nonce": "<session mint-challenge>", "max_staple_age": "1h", "trust_hint": "pin our cert_issuer: …" }` |
| `present` | Sender | `{ "challenge_id": "a2a_…", "presentation_path": "…/presentations/<id>.json" }` |
| `accept` | Receiver | `{ "verdict": "verified (key-bound, anchored, live)", "handoff_id": "art_…", "parent_presentation": "…" }` |
| `refuse` | Receiver | `{ "refusal": "challenge_failed", "message": "…" }`  — values match `GateRefusal` in `gate.ts` |
| `handoff` | Either, after accept | `{ "from", "to", "artifacts": ["art_…"], "verify_artifact": "art_…", "close_loop": null }` |

Rules:

- Receiver **mints** the nonce (`treeship session mint-challenge --format json`). Never accept a nonce the sender chose.
- Sender answers with `treeship present <actor> --challenge <nonce> --format json` and writes the presentation file.
- Receiver runs `gateInbound({ presentationPath, challenge: nonce })` **before** any domain work.
- Replay of `present` against a new nonce → `challenge_failed`. Same nonce reused → refuse.
- Missing presentation → `no_presentation`. Missing/short nonce → `no_challenge`. CLI missing → `gate_unavailable` (refuse, do not skip).
- Opt-out: `TREESHIP_A2A_UNVERIFIED=1` only. Execute and set `accept.body.unverified = true` plus the would-be refusal. Silent skip is a bug.

### 3.2 When work is "foreign"

Foreign (gate required):

- Envelope `kind=offer` from another actor URI
- A2A protocol task (`onTaskReceived`)
- A chat/DM that says "take this from `agent://…`" and includes a presentation or outbox path
- A file dropped into `inbox/`

Not foreign (no gate):

- The human in this thread asking the Bot to do local work
- Re-bootstrap, `present` in response to a challenge *we* minted, `session status`
- Same-computer roster handoff (still write `handoff` with `custody: asserted`, `reason: same_computer`; do not run `--challenge` and call it live)

### 3.3 Pin

First contact with a new ship: receiver verifies the presentation *chain* and then the operator (or a policy) pins `cert_issuer`. Without a pin, the honest verdict is "internally consistent, issuer not trusted" — not `verified`. Skill text must say that. `trust add --kind cert_issuer` is the only pin that counts.

Proofmark `agent://x/<handle>` is a **name**. It is not a pin.

---

## 4. Host adapter (the reference)

Every host implements this. Grok is the first.

```ts
// integrations/a2a-host/types.ts  — shared types, no runtime on Grok required

export type HostName = 'grok-bot' | 'claude' | 'codex' | 'hermes' | 'a2a' | 'cursor';

export interface HostAdapter {
  name: HostName;
  /** Durable Treeship home. Grok: /workspace/treeship */
  home(): string;
  /** Account-scoped actor. Grok: agent://grok (or agent://x/<handle> if readable) */
  actor(): string;
  /** Put treeship on PATH, TREESHIP_HOME, onboard --own-key. Idempotent across wipe. */
  bootstrap(): Promise<void>;
  /** Write envelope, return a pointer the peer can fetch (path, URL, or paste). */
  send(env: Envelope): Promise<string>;
  /** Next unread foreign envelope, or null. */
  receive(): Promise<Envelope | null>;
  /** True if this message is inbound work from another agent. */
  isForeign(msg: unknown): boolean;
  /**
   * Grade for this hop.
   * inter_host = different TREESHIP_HOME / different ship.
   * same_computer = shared keystore (Grok roster). Never report live.
   */
  hopGrade(peer: string): 'inter_host' | 'same_computer';
}
```

Claude / Codex / Hermes: `send`/`receive` are MCP tool results + files in the repo. `@treeship/a2a`: `send` is the AgentCard + task metadata; `receive` is `onTaskReceived` **calling `gateInbound` first**. Same envelope `kind`s.

---

## 5. Grok Bot implementation

### 5.1 On-disk layout

```
/workspace/treeship/                 # TREESHIP_HOME
  bin/treeship                       # copied install, survives PATH wipes
  identity.json                      # { actor, ship_id, created_at, bootstrap_version }
  inbox/                             # envelopes we must gate
  outbox/                            # envelopes we sent
  presentations/                     # present output files
  peers/<ship_id>/trust.txt          # the trust add line we used
  challenges/<a2a_id>.json           # nonce we minted, not the sender's
```

Project `.treeship/` in random cwd is forbidden. `--config` does not fully isolate sessions in this repo; do not rely on it.

### 5.2 Bootstrap (one command the Bot runs)

`integrations/grok-bot/bootstrap.sh`

```bash
#!/usr/bin/env bash
set -euo pipefail
HOME_DIR="${TREESHIP_HOME:-/workspace/treeship}"
export TREESHIP_HOME="$HOME_DIR"
mkdir -p "$HOME_DIR"/{bin,inbox,outbox,presentations,peers,challenges}
# install to HOME_DIR/bin if missing or doctor fails
if ! "$HOME_DIR/bin/treeship" --version >/dev/null 2>&1; then
  curl -fsSL https://treeship.dev/install | sh
  # copy/link the resulting binary into HOME_DIR/bin
fi
export PATH="$HOME_DIR/bin:$PATH"
treeship init --quiet 2>/dev/null || true
treeship agent register --own-key --quiet --name grok \
  --description "Grok Bot account computer" || true
# identity.json: reuse actor + ship if present (wipe must not mint a second key)
```

Acceptance: delete `/usr` copies and `~/.treeship` but keep `/workspace/treeship` → same actor, same key, `verify` says `proven (key-bound)`. Delete `/workspace/treeship` → new ship, and the skill says so.

Env the Bot must export on every shell: `TREESHIP_HOME=/workspace/treeship`, `TREESHIP_ACTOR=agent://grok`, `PATH` includes `$TREESHIP_HOME/bin`.

### 5.3 Packaged skill (prose — this is the Grok format)

File to paste into Settings → Plugins → Yours, and later a share link:

`integrations/grok-bot/SKILL.txt` (not SKILL.md install semantics; plain instructions)

When to use: any time another agent, another Bot on a different account, or a human says "prove you", "take this from agent://…", "hand this to …", or drops a `treeship.a2a/v1` file.

Do:

1. If `treeship --version` fails, run bootstrap.
2. If the message is foreign (`offer` or "take this from agent://"):
   - `treeship session mint-challenge --format json`
   - write `challenge` envelope to `outbox/`, DM or paste the path + nonce command
   - **stop. Do not do the work.**
3. When a `present` envelope arrives: `verify-presentation --challenge <our nonce> --format json`. On nonzero, write `refuse` and stop.
4. On success: do the work, `attest handoff --from <peer> --to agent://grok --artifacts …`, write `accept`.
5. If *we* are sending work: write `offer`, wait for `challenge`, `present --challenge`, wait for `accept` or `refuse`.
6. Same-account `@other-bot`: copy artifacts in `/workspace`, write `handoff` with `grade: same_computer`. Do not print "verified live".
7. Coverage header on every reply: `coverage: cli-only; actor: account-scoped; hop: inter_host|same_computer`.

Do not: `cargo install`; `wrap -- npm test` as the first example; `present` without `--challenge` as "prove you"; claim which Bot on this roster signed; fetch a Hub URL and call it verified.

Human verbs (same protocol):

| They say | kind | Command |
|---|---|---|
| prove you | we are sender, they mint | we `present --challenge` their nonce |
| take this from agent://claude | we receive `offer` | we mint, they present, we gate |
| hand this to Claude | we send `offer` | wait for their challenge |
| receipt this | session | `session close` + `session report` or local package path |

### 5.4 Routine

> Every day, run the Treeship bootstrap. If `treeship doctor` fails, reinstall into `/workspace/treeship/bin`. Do not mint a new agent key if `identity.json` exists. Post a one-line status in this conversation only on failure.

### 5.5 Transports (Grok-specific)

| Hop | How the bytes move | Grade |
|---|---|---|
| Grok → Claude/Codex on a laptop | Conversation file card, or paste JSON, or Hub URL *plus* local `verify-presentation` | `inter_host` |
| Grok account A → Grok account B | Share skill/Bot (new computer) + same files/paste | `inter_host` |
| Piper → Writer on one account | `/workspace` + async Bot DM pointing at the path | `same_computer` |
| Group of 3 Bots | Text pointer only (docs: handoff messages text-only) | `same_computer` |
| A2A HTTP server | `@treeship/a2a` metadata + presentation path | `inter_host` |

### 5.6 Worked inter-host sequence (Grok ↔ Claude)

On Grok (sender), after bootstrap:

```bash
export TREESHIP_CONFIG=/workspace/treeship/config.json TREESHIP_ACTOR=agent://grok
treeship session start --name "a2a:offer-to-claude" --format json
# write offer to $TREESHIP_HOME/outbox/a2a_01.json
# attach that file in the Grok conversation (or paste)
```

On Claude (receiver):

```bash
treeship session mint-challenge --format json   # → nonce
# write challenge envelope; human or Claude pastes nonce back to Grok
```

On Grok:

```bash
treeship present agent://grok --challenge "$NONCE" --format json
# → /workspace/treeship/presentations/<id>.json  (attach / paste)
```

On Claude:

```bash
treeship verify-presentation ./grok.presentation.json --challenge "$NONCE" --format json
# exit 0 → do the work
treeship attest handoff --from agent://grok --to agent://claude --artifacts art_… --format json
```

Without Claude having pinned Grok's `cert_issuer`, exit is 1. **Verified 2026-09-01 against two real ships.** Note what it actually prints: `verdict: CHALLENGE FAILED`, because a card that never verified key-bound has no established key to check a response against -- the challenge failure is a *consequence* of the missing pin, not the cause. The structured fields are what distinguish them (`key_bound: false`, `signature: "UNVERIFIED (key not in your trust roots)"`), which is why `gate.ts` classifies on fields and never on the verdict string. Real outputs for all three cases are committed at `bridges/a2a/test/fixtures/`.

### 5.7 Files to add

```
integrations/grok-bot/README.md          # human: how to add the skill, pin a peer
integrations/grok-bot/bootstrap.sh       # §5.2
integrations/grok-bot/SKILL.txt          # §5.3 paste-into-Grok
integrations/grok-bot/routine.txt        # §5.4
integrations/a2a-host/types.ts           # §4
integrations/a2a-host/envelope.ts        # parse/validate treeship.a2a/v1
bridges/a2a/src/index.ts                 # export gate
bridges/a2a/src/middleware.ts            # gateInbound BEFORE onTaskReceived work
bridges/mcp/src/server.ts                # add mint/present/verify-presentation/handoff tools
```

Claude/Codex/Hermes skills: add a "foreign work" section that points at the same envelope and forbids acting before `verify-presentation --challenge` exits 0. Do not rewrite their install story.

---

## 6. Lauren close-loop as optional evidence (slice 4)

Implement this **after** the gate works. It is how we productize her loop without becoming her.

On the **sender**, if a host verify CLI exists:

```bash
# only when the binary is on PATH
treeship wrap -- /control-app doctor          # or: control-app --json …
# or Grok-native evidence without pstack:
treeship wrap -- <the CLI that wrote the screenshots>
```

Put the wrap/session id on the `handoff` envelope:

```json
"close_loop": {
  "kind": "wrap",
  "session_id": "ssn_…",
  "command": "/control-app doctor",
  "note": "proves this sender ran that CLI. Does not bind the UI pixels to the presentation key."
}
```

Receiver **may** require `close_loop` as policy. v1 must not.

Grok-native stand-in (docs-supported, no pstack):

1. Skill already requires "How to validate the result" ([skills](https://docs.x.ai/grok-bot/skills-routines-and-automations)).
2. Ask for a folder of screenshots + action log ([files](https://docs.x.ai/grok-bot/files-and-results) "Preserve evidence").
3. `wrap` the commands that produced that folder.
4. Attach those artifact ids on the handoff.

That is "what Lauren is talking about" mapped onto what Grok actually gives us: an agent that can keep going, plus a signed record of the commands that produced the screenshots. It is still not CDP of Grok Bot's own app. We do not build `control-grok.mjs`.

---

## 7. Slices

### 1. Shared envelope + Grok bootstrap + skill (this week)

Done when: on a Grok VM, bootstrap is idempotent across a documented package wipe; `agent://grok` verifies `proven (key-bound)`; the saved skill refuses an `offer` without minting a challenge; a second isolated ship with `cert_issuer` pinned can complete §5.6.

### 2. Wire the gate where work already arrives

- Export `gateInbound` / `mintChallenge` from `@treeship/a2a`.
- `onTaskReceived`: if `fromAgent` is set, refuse unless gate passes. This inverts today's "attestation must never break the agent path" for **foreign** tasks only. Local/unknown-without-from stays attest-only.
- MCP: add `treeship_mint_challenge`, `treeship_present`, `treeship_verify_presentation`, `treeship_attest_handoff`. Grok does not need these until Plugins accepts MCP.

### 3. Handoff records the verify

`attest handoff` grows an optional `--verified <art_or_path>` (or meta). `verify` prints `custody: live` vs `custody: asserted`. Same-computer Grok handoffs are `custody: asserted (same_computer)`.

### 3b. Grok approvals

Blocked until a process on the VM can read Allow/Deny. Then Approval Use Journal. Never invent an approver (#347).

### 4. Close-loop attach

§6. Only if `/control-app` or a wrap-able evidence command exists.

---

## 8. Acceptance (slice 1+2)

Two machines. Machine G is a Grok-like layout (`TREESHIP_HOME=/tmp/fake-workspace/treeship`). Machine C is a normal ship.

1. G bootstraps twice after deleting `bin/` only → same identity.
2. C has no pin. G presents with C's nonce → C reports untrusted issuer, does not act.
3. C pins G `cert_issuer`. Replay of the old presentation+nonce → refuse.
4. Fresh challenge → accept → C `attest handoff` → C `verify` shows live + `actor proof: proven`.
5. On G, Bot A "hands off" to Bot B via `/workspace` → envelope `custody: asserted` with `reason: same_computer`, no `live` string in the skill output.
6. `TREESHIP_A2A_UNVERIFIED=1` on C → work runs, receipt says unverified + reason.

Fail if: skill uses `wrap -- npm test` as the happy path; present without challenge sold as prove-you; per-Bot attribution; Hub fetch as verify; bootstrap mints a second key after wipe of packages only.

---

## 9. What this is not

- pstack, Feature Maps, `/swarm`, driving Grok Bot's Electron UI
- A registry in the handshake
- Per-Bot keys on one Grok account
- Treating Cursor login, Proofmark founding, or an X handle as `cert_issuer`
- Enforcing `invitation_authority` on rooms

## 10. Open questions (do not block slice 1)

- Does Settings → Plugins on Grok Bot accept a custom MCP URL? (Grok *chat* does. Bot docs do not say.)
- Can a process on the VM read the X handle, thread id, or Auto Review decision?
- Is `/workspace` on the durable snapshot after Reset, or only Update/Recover?

Re-check docs.x.ai/grok-bot before coding if more than two weeks have passed.
