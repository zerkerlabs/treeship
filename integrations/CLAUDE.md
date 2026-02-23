# Treeship Integration for Claude Code

Add this to your project's `CLAUDE.md` to enable automatic verification of agent actions.

---

## Treeship Verification

This project uses [Treeship](https://treeship.dev) for tamper-proof verification of AI agent actions.

### Setup

```bash
pip install treeship-sdk
export TREESHIP_API_KEY=ts_live_...  # Get key at https://treeship.dev
```

### Usage

After completing significant actions (approvals, decisions, generated outputs), create an attestation:

```python
from treeship_sdk import Treeship

ts = Treeship()

# After any important action
result = ts.attest(
    agent="your-agent-name",
    action="Description of what was done",
    inputs_hash=ts.hash({"relevant": "data"})  # Hash of inputs - never sent to Treeship
)

# Share the verification URL
print(f"Verified: {result.verify_url}")
```

### When to Attest

Create attestations for:
- Decisions (approvals, rejections, escalations)
- Generated content (reports, summaries, code)
- External actions (API calls, file modifications, deployments)
- Data processing (analysis results, transformations)

### Verification Page

All attestations for this agent are visible at:
```
https://treeship.dev/verify/your-agent-name
```

### Example

```python
# After approving a PR
ts.attest(
    agent="code-reviewer",
    action=f"Approved PR #{pr_number}: {pr_title}",
    inputs_hash=ts.hash({"pr": pr_number, "files_changed": files})
)

# After generating a report
ts.attest(
    agent="report-generator", 
    action=f"Generated Q1 sales report",
    inputs_hash=ts.hash({"period": "Q1-2026", "data_sources": sources})
)
```

### Privacy

| Sent to Treeship | Stays local |
|------------------|-------------|
| Agent name | Actual data |
| Action description | Files, PII |
| SHA-256 hash of inputs | Raw inputs |

You control what's in the action description. Sensitive data never leaves your infrastructure.
