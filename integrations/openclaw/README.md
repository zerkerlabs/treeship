# Treeship × OpenClaw Integration

Add verifiable audit trails to OpenClaw agents with a single SKILL.md file.

## Installation

1. Copy `TREESHIP.md` to your OpenClaw agent's skills directory
2. Set environment variables:
   ```bash
   export TREESHIP_API_KEY="your_api_key"
   export TREESHIP_AGENT="your-agent-slug"
   ```
3. The agent can now call `treeship_attest` as a skill

## Usage

The OpenClaw agent will automatically have access to the `treeship_attest` skill.
Call it at key decision points:

```
User: Process this document and make a decision.

Agent: I'll process the document and create a verified record.
[calls treeship_attest with action="Document processed, decision: approved"]

The decision has been recorded. Verification: https://treeship.dev/verify/ts_abc123
```

## SKILL.md Contents

The TREESHIP.md skill file defines:

- **Name**: treeship_attest
- **Description**: Creates tamper-proof, independently verifiable records
- **Parameters**: action (required), inputs (optional)
- **Returns**: Verification URL

## When to Attest

Train your agent to attest at:
- Data reads (user documents, external APIs)
- Consequential decisions (approvals, rejections, recommendations)
- External tool calls (sending emails, making purchases)
- Final outputs to users

## Verification

Anyone can verify attestations at `treeship.dev/verify/{id}` — no account needed.
