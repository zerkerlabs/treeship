# Treeship for Grok Bot

Agent-to-agent verification on a Grok Bot cloud VM: refuse work from another
agent until it proves live control of a key you trust.

**This is not a verification skill in the pstack sense.** It does not drive an
app until the UI is green. It answers a different question: *should this ship
act on work from that agent?* The two compose — if you have a close-loop CLI,
wrap it and attach the session to the handoff — but they are not substitutes.

## Install

Ask your Bot to run:

```bash
curl -fsSL https://raw.githubusercontent.com/zerkerlabs/treeship/main/integrations/grok-bot/bootstrap.sh | bash
```

Then paste [`SKILL.txt`](./SKILL.txt) into a saved skill (Grok skills are prose,
not files) and invoke it with `/`. Optionally add [`routine.txt`](./routine.txt)
as a weekday routine so a package wipe self-heals.

## Layout

```
/workspace/treeship/
  ts                 shim — use this, never a bare `treeship`
  config.json        this account's ship
  home/              keystore, checkpoints
  bin/               the binary (replaceable)
  inbox/ outbox/ presentations/
```

`/workspace` is the durable path; the Grok docs say to treat manually installed
packages as replaceable. Bootstrap is idempotent: re-running after a wipe
restores the same ship key rather than minting a second identity.

**Why a shim.** The CLI resolves its ship as `--config` → `TREESHIP_CONFIG` →
`.treeship/config.json` walking up from cwd → `~/.treeship/config.json`.
`TREESHIP_HOME` does *not* move the ship, and `TREESHIP_CONFIG` alone leaves
checkpoints in `~/.treeship/merkle/checkpoints`, which is not durable here. The
shim pins both `HOME` and `TREESHIP_CONFIG` so a bare `treeship` typed by the
Bot cannot silently adopt whatever ship the directory walk finds.

## Pinning a peer

Verification is against *your* trust roots, with no registry in the loop. Until
you pin a peer's ship, the honest verdict is "internally consistent, issuer not
trusted" — not "verified".

Give a peer your line:

```bash
/workspace/treeship/ts keys export | grep cert_issuer
```

Pin theirs:

```bash
/workspace/treeship/ts trust add <key_id> <ed25519:...> --kind cert_issuer --yes
```

Pin only the powers you intend to grant. `cert_issuer` is the one the chain
walk consults.

## One account is one identity

Every Bot on a Grok account shares one computer and one keystore, and the docs
say plainly: *"Do not use separate Bots as a security boundary."* So a receipt
proves **this account's computer** signed it. Which Bot did it is `asserted`,
always — no actor URI spelling changes that.

Handoffs between Bots on one account are `custody: asserted (same_computer)`.
Real verification is with an agent on a different computer.

## What a receipt does not prove

That the work is correct. It proves who acted, under whose key, and that a live
challenge was answered. An agent can pass every check here and still be wrong
about the task.
