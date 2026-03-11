# Treeship Attestation Skill

**For:** OpenClaw agents  
**Requires:** `curl` (pre-installed on all systems)  
**No pip install needed.**

---

## Setup

Add your credentials to your OpenClaw workspace `TOOLS.md`:

```
### Treeship
- API key: ts_live__YOUR_KEY
- Agent slug: your-agent-slug
- Verify page: https://treeship.dev/verify/your-agent-slug
```

---

## When to Attest

Attest **before completing** any of the following:
- Sending a message, email, or post on behalf of the user
- Deleting, modifying, or moving files
- Making an external API call with side effects
- Completing a multi-step task

---

## How to Attest

Copy this exactly. Replace `YOUR_API_KEY`, `YOUR_SLUG`, and `ACTION_DESCRIPTION` only.

### Step 1 — Create the attestation

```bash
RESULT=$(curl -s -X POST https://api.treeship.dev/v1/attest \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d "{
    \"agent_slug\": \"YOUR_SLUG\",
    \"action\": \"ACTION_DESCRIPTION\",
    \"inputs_hash\": \"$(echo -n 'ACTION_DESCRIPTION' | shasum -a 256 | cut -d' ' -f1)\"
  }")
echo $RESULT
```

### Step 2 — Extract the attestation ID

```bash
ATTESTATION_ID=$(echo $RESULT | python3 -c "import sys,json; print(json.load(sys.stdin)['attestation_id'])")
echo "Attestation ID: $ATTESTATION_ID"
```

### Step 3 — Verify it persisted (do not skip)

```bash
curl -s -H "Authorization: Bearer YOUR_API_KEY" \
  https://api.treeship.dev/v1/verify/$ATTESTATION_ID \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print('PERSISTED ✅' if d.get('valid') else 'FAILED: ' + str(d))"
```

**If Step 3 prints `PERSISTED ✅` — proceed with your task.**  
**If Step 3 prints `FAILED` — do not proceed. Report the error.**

### Step 4 — Share the verify URL

```
https://treeship.dev/verify/YOUR_SLUG/$ATTESTATION_ID
```

Anyone can open this URL to independently verify the attestation — no account needed.

---

## Why curl-only?

The Python SDK (`treeship-sdk`) can silently return fake responses without hitting the API in some environments. `curl` output is unambiguous — the agent sees the raw JSON and cannot hallucinate a success response. Step 3 is the anti-hallucination gate: attestations must be verified as persisted before the task proceeds.

---

## Example

```bash
# Attesting: "Posted comment to Moltbook thread on agent trust"
RESULT=$(curl -s -X POST https://api.treeship.dev/v1/attest \
  -H "Authorization: Bearer ts_live__abc123" \
  -H "Content-Type: application/json" \
  -d "{
    \"agent_slug\": \"openclaw1\",
    \"action\": \"Posted comment to Moltbook thread on agent trust\",
    \"inputs_hash\": \"$(echo -n 'Posted comment to Moltbook thread on agent trust' | shasum -a 256 | cut -d' ' -f1)\"
  }")

ATTESTATION_ID=$(echo $RESULT | python3 -c "import sys,json; print(json.load(sys.stdin)['attestation_id'])")

curl -s -H "Authorization: Bearer ts_live__abc123" \
  https://api.treeship.dev/v1/verify/$ATTESTATION_ID \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print('PERSISTED ✅' if d.get('valid') else 'FAILED: ' + str(d))"

# Output: PERSISTED ✅
# Verify: https://treeship.dev/verify/openclaw1/<attestation_id>
```

---

## Privacy

Your `action` string is the only content sent to Treeship. The `inputs_hash` is a SHA-256 hash computed locally — raw documents, user data, and API responses never leave your infrastructure.
