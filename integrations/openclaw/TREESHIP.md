# TREESHIP.md — OpenClaw Skill Definition

name: treeship_attest
description: Create a tamper-proof, independently verifiable record of this agent decision. Call at data reads, consequential decisions, external tool calls, and final outputs. Never blocks on failure.

## Parameters

- action (string, required): Human-readable description of what happened. Max 500 characters. Be specific: "User document summarized" not "action taken".
- inputs (object, optional): Key-value pairs of inputs. These are hashed locally — content is NEVER sent to Treeship. Include enough context to identify the decision uniquely.

## Returns

On success:
```json
{
  "attested": true,
  "url": "https://treeship.dev/verify/ts_abc123",
  "id": "ts_abc123"
}
```

On failure (never blocks):
```json
{
  "attested": false,
  "error": "reason"
}
```

## Example Calls

### Data Read
```json
{
  "action": "Read user document: contract_v2.pdf",
  "inputs": {"doc_id": "doc_123", "user_id": "u_456"}
}
```

### Decision
```json
{
  "action": "Loan application approved: income=$85k meets $50k threshold",
  "inputs": {"application_id": "app_789", "decision": "approved", "confidence": 0.95}
}
```

### External Tool Call
```json
{
  "action": "Email sent to user@example.com: appointment confirmation",
  "inputs": {"email_type": "confirmation", "recipient_hash": "a1b2c3..."}
}
```

## Privacy Contract

- Your inputs dict is hashed with SHA-256 locally
- Only the hash is sent to Treeship
- Raw content (documents, user data, API responses) NEVER leaves your infrastructure
- Suitable for healthcare, finance, and legal deployments

## When to Call

1. **Data reads**: Before making decisions based on external data
2. **Consequential decisions**: Approvals, rejections, recommendations
3. **External actions**: Emails, API calls, purchases
4. **Final outputs**: Summaries, reports, recommendations to users

## Endpoint

POST http://treeship-sidecar:2019/attest

Or if using the API directly:
POST https://api.treeship.dev/v1/attest
Authorization: Bearer $TREESHIP_API_KEY
