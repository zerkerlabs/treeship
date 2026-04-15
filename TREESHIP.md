# Treeship Skill

You are working in a project that uses [Treeship](https://treeship.dev) for portable, verifiable session receipts. Every command you run, every file you write, and every decision you make should be captured in a signed receipt that proves what happened during this task.

Follow these instructions for every task you work on in this project.

## Before you start: check the CLI

Before doing anything else, verify the Treeship CLI is installed:

```bash
treeship --version
```

If this fails, install it:

```bash
curl -fsSL treeship.dev/install | sh
treeship init
```

If `treeship init` has already been run in this project (a `.treeship/` directory exists), skip init.

## Scenario A: Starting a fresh task

At the beginning of every new task, start a Treeship session. Use the task name or a short description as the session name:

```bash
treeship session start --name "<short task description>"
```

Example:

```bash
treeship session start --name "fix JWT expiry bug in auth middleware"
```

**Set environment variables** before running any commands so your model, token usage, and cost are captured in the receipt:

```bash
export TREESHIP_MODEL="<your model name>"
export TREESHIP_TOKENS_IN="<input tokens for this interaction>"
export TREESHIP_TOKENS_OUT="<output tokens for this interaction>"
export TREESHIP_COST_USD="<cost in USD for this interaction>"
```

If you don't know the exact values, set what you can. Partial data is better than none. At minimum, set `TREESHIP_MODEL`.

### Environment variables reference

| Variable | What it means | Where to get the value |
|----------|--------------|----------------------|
| `TREESHIP_MODEL` | The LLM model you are running as (e.g. `claude-opus-4-6`, `gpt-4o`, `hermes-2`) | You know your own model name |
| `TREESHIP_TOKENS_IN` | Input token count for this interaction | Your runtime provides this; estimate if not available |
| `TREESHIP_TOKENS_OUT` | Output token count for this interaction | Your runtime provides this; estimate if not available |
| `TREESHIP_COST_USD` | Cost in USD for this interaction | Calculate from token counts and pricing, or estimate |

## Scenario B: Running commands during the task

**Every shell command you execute must be prefixed with `treeship wrap --`**. This creates a signed artifact for each command and records it in the session timeline.

Instead of:

```bash
npm test
```

Run:

```bash
treeship wrap -- npm test
```

Instead of:

```bash
cargo build --release
```

Run:

```bash
treeship wrap -- cargo build --release
```

Instead of:

```bash
git add -A && git commit -m "fix auth bug"
```

Run:

```bash
treeship wrap -- git add -A
treeship wrap -- git commit -m "fix auth bug"
```

### Common patterns

**Running tests:**

```bash
treeship wrap -- npm test
treeship wrap -- cargo test --workspace
treeship wrap -- pytest -v
```

**Building:**

```bash
treeship wrap -- npm run build
treeship wrap -- cargo build --release
treeship wrap -- go build ./...
```

**File operations:**

```bash
treeship wrap -- cat src/main.rs
treeship wrap -- ls -la packages/
```

**Git operations:**

```bash
treeship wrap -- git status
treeship wrap -- git diff HEAD
treeship wrap -- git add src/fix.rs
treeship wrap -- git commit -m "fix: resolve JWT expiry"
```

**External tools:**

```bash
treeship wrap -- curl -sS https://api.example.com/health
treeship wrap -- docker build -t myapp .
```

### What if you forget to wrap a command?

It won't appear in the receipt. The receipt only captures what was instrumented. It's better to wrap too many commands than too few. Commands that produce no side effects (like `echo`, `pwd`, `date`) are cheap to wrap and provide useful timeline context.

### Nested or sub-tasks

If you are working on a sub-task within a larger task, **do not start a new session**. Continue using the same session. The receipt should capture the entire task as one unit, including all sub-tasks. Starting a new session mid-task breaks the chain and produces incomplete receipts.

## Scenario C: Completing the task

When the task is done, close the session with a meaningful summary:

```bash
treeship session close \
  --headline "<one sentence: what was accomplished>" \
  --summary "<2-3 sentences: what you did and what changed>" \
  --review "<what a reviewer should check before trusting this work>"
```

### Writing a good headline

The headline is the first thing someone reads. It should be a single, specific sentence that tells the reader what was accomplished. Not a generic description.

**Good headlines:**

- "Fixed JWT expiry bug that caused 401s after 24 hours"
- "Added session receipt composer with Merkle root verification"
- "Migrated auth middleware from Express to Hono with zero downtime"

**Bad headlines:**

- "Fixed a bug"
- "Made some changes"
- "Updated code"

### Writing a good summary

The summary should answer: what exactly did you do, what files changed, and what was the outcome? Include specific details.

**Good summary:**

"Identified the JWT expiry bug in packages/auth/src/token.ts where the expiry was set to 24h instead of 7d. Fixed the TTL, added a regression test, and confirmed the fix resolves the 401 errors in staging. Three files changed: token.ts, token.test.ts, and the migration script."

**Bad summary:**

"Fixed the bug and updated tests."

### Writing a good review note

The review note tells the next person what to check. Be specific about risks and edge cases.

**Good review:**

"Verify the JWT TTL change doesn't break existing tokens in production. The migration script handles the transition but has not been tested against the production database. Also confirm the new test covers the edge case where a token is issued exactly at the boundary."

**Bad review:**

"Please review."

### After closing: upload the receipt

```bash
treeship session report
```

This uploads the receipt to the configured hub and prints a permanent public URL like:

```
receipt: https://treeship.dev/receipt/ssn_42e740bd9eb238f6
```

Share this URL with anyone who needs to verify what happened. No account, no token, no auth required.

## Complete worked example

Here is a complete session from start to report with realistic output:

```bash
# 1. Start the session
$ treeship session start --name "fix JWT expiry bug"

  session started
  id:     ssn_8a3f1e22bc4d5678
  name:   fix JWT expiry bug
  actor:  ship://ship_093924ee421b8515

# 2. Set env vars
$ export TREESHIP_MODEL=claude-opus-4-6
$ export TREESHIP_TOKENS_IN=18400
$ export TREESHIP_TOKENS_OUT=2100
$ export TREESHIP_COST_USD=0.42

# 3. Investigate the bug
$ treeship wrap -- cat packages/auth/src/token.ts

  exit:     0  passed
  elapsed:  4ms

$ treeship wrap -- grep -r "expiresIn" packages/auth/

  exit:     0  passed
  elapsed:  12ms

# 4. Fix the code (you edit the file directly, then wrap the test)
$ treeship wrap -- npm test --filter auth

  exit:     0  passed
  elapsed:  3.2s

# 5. Commit the fix
$ treeship wrap -- git add packages/auth/src/token.ts packages/auth/test/token.test.ts
$ treeship wrap -- git commit -m "fix: set JWT TTL to 7d, add regression test"

  exit:     0  passed
  elapsed:  180ms

# 6. Close the session
$ treeship session close \
    --headline "Fixed JWT expiry bug that caused 401s after 24 hours" \
    --summary "Found the TTL was set to 24h instead of 7d in token.ts. Fixed the constant, added a regression test covering the boundary case, and confirmed the fix in local tests." \
    --review "Verify the TTL change works with existing tokens in production. The migration handles token refresh but hasn't been tested against prod data."

  session receipt composed
  package:   .treeship/sessions/ssn_8a3f1e22bc4d5678.treeship
  digest:    sha256:1715dd61...
  merkle:    mroot_6041721b...
  files:     9

  session closed
  id:       ssn_8a3f1e22bc4d5678
  duration: 4m
  receipts: 5
  events:   8

# 7. Upload and share
$ treeship session report

  session receipt uploaded
  hub:      default
  session:  ssn_8a3f1e22bc4d5678
  agents:   1
  events:   8

  receipt:  https://treeship.dev/receipt/ssn_8a3f1e22bc4d5678

  share this URL freely -- it never expires and needs no auth
```

The receipt is now a portable, verifiable artifact that proves exactly what happened during this task. Anyone with the URL (or the `.treeship` package directory) can verify the Merkle root, check the inclusion proofs, and read the full timeline without needing Treeship installed.

## What the receipt captures

When you follow this skill correctly, the receipt will contain:

- **Timeline**: every wrapped command in chronological order
- **Agent identity**: your name, model, host, role
- **Cost and tokens**: model, input/output tokens, cost per interaction
- **File operations**: which files were created, modified, or deleted
- **Commands**: full command strings with exit codes and durations
- **Narrative**: your headline, summary, and review notes
- **Merkle proof**: cryptographic commitment over all artifacts
- **Ed25519 signatures**: every artifact individually signed

## What the receipt does NOT capture

- Commands you run without `treeship wrap --`
- File reads unless the daemon is running (`treeship daemon start`)
- Network connections unless explicitly emitted via `treeship session event`
- Actions by other agents unless they are also instrumented with Treeship

Be honest about what was and wasn't captured. A receipt with real data in every section is worth more than a receipt with gaps.
