# @treeship/a2a

Treeship attestation middleware for [A2A](https://a2a.dev) (Agent2Agent) servers and clients. Every task receipt, completion, and handoff becomes a signed Treeship artifact, and every outbound A2A artifact carries a receipt URL peers can fetch and verify.

> A2A makes agents interoperable. Treeship makes that interoperability trustworthy and auditable.

## Install

```bash
npm install @treeship/a2a
```

Requires the `treeship` CLI in PATH:

```bash
curl -fsSL treeship.dev/install | sh
treeship init
```

## What it does

| Phase | What gets attested |
|-------|--------------------|
| Task arrives at your agent | An **intent** artifact: who sent it, which skill, the A2A task/message ID |
| Task completes | A **receipt** artifact chained to the intent: elapsed time, status, artifact digest, token usage |
| Outbound artifact returned | `treeship_artifact_id` and `treeship_receipt_url` injected into artifact metadata |
| You delegate to another A2A agent | A signed **handoff** artifact: from-agent, to-agent, context, message ID |
| Your AgentCard at `/.well-known/agent.json` | A `treeship.dev/extensions/attestation/v1` extension publishing your ship ID and receipt endpoint |

The middleware is **framework-agnostic**. It does not import any specific A2A SDK, you wire its hooks into whichever server you run.

## Quickstart: wrap an A2A server

```typescript
import { TreeshipA2AMiddleware, buildAgentCard } from '@treeship/a2a';

const treeship = new TreeshipA2AMiddleware({
  shipId: process.env.TREESHIP_SHIP_ID!,
  receiptBaseUrl: 'https://treeship.dev/receipt',
});

// 1. Publish a Treeship-attested AgentCard
app.get('/.well-known/agent.json', (_req, res) => {
  res.json(
    buildAgentCard(
      {
        name: 'OpenClaw Research Agent',
        version: '1.2.0',
        url: 'https://openclaw.example/a2a',
        capabilities: { streaming: true, pushNotifications: true },
        skills: [
          { id: 'web-research', name: 'Web Research', description: 'Deep web research with source attribution' },
        ],
      },
      {
        ship_id: process.env.TREESHIP_SHIP_ID!,
        verification_key: 'ed25519:abc123...',
      },
    ),
  );
});

// 2. Attest the task lifecycle around your handler
app.post('/a2a/tasks', async (req, res) => {
  const { taskId, skill, from, messageId } = req.body;

  await treeship.onTaskReceived({ taskId, skill, fromAgent: from, messageId });

  const start = Date.now();
  let status: 'completed' | 'failed' = 'completed';
  let artifact;
  try {
    artifact = await runMyAgent(req.body);
  } catch (e) {
    status = 'failed';
    throw e;
  } finally {
    const result = await treeship.onTaskCompleted({
      taskId,
      elapsedMs: Date.now() - start,
      status,
      artifactDigest: artifact ? TreeshipA2AMiddleware.digestArtifact(artifact) : undefined,
    });
    if (artifact) artifact = treeship.decorateArtifact(artifact, result);
  }

  res.json(artifact);
});
```

The artifact your peer receives now has a verifiable trail:

```json
{
  "artifactId": "research-output-001",
  "parts": [{ "kind": "text", "text": "Research findings..." }],
  "metadata": {
    "treeship_artifact_id": "art_7f8e9d0a1b2c3d4e",
    "treeship_receipt_url": "https://treeship.dev/receipt/ssn_01HR9W2D4Q4M7A0C",
    "treeship_session_id": "ssn_01HR9W2D4Q4M7A0C",
    "treeship_ship_id": "shp_4a9f2c1d"
  }
}
```

## Quickstart: verify another agent before trusting it

```typescript
import { fetchAgentCard, hasTreeshipExtension, verifyArtifact } from '@treeship/a2a';

// 1. Discover the peer
const card = await fetchAgentCard('https://partner-agent.example');
if (!hasTreeshipExtension(card)) {
  throw new Error('Refusing to delegate: peer is not Treeship-attested');
}

// 2. Send your A2A task ... and when the artifact comes back:
const verification = await verifyArtifact(remoteArtifact.metadata);
if (!verification || !verification.withinDeclaredBounds) {
  throw new Error('Peer artifact failed Treeship verification');
}
```

## Recording a handoff

```typescript
await treeship.onHandoff({
  toAgent: 'agent://openclaw',
  taskId: 'a2a-task-7f8e9d',
  context: 'Research phase delegated: find comparable Merkle MMR implementations',
  messageId: 'msg_abc123',
});
```

This is the same artifact `treeship attest handoff` produces from the CLI, it appears in the parent session's receipt as a delegation boundary.

## Environment variables

| Variable | Effect |
|----------|--------|
| `TREESHIP_DISABLE=1` | Skips all attestation. Hooks return undefined. |
| `TREESHIP_SESSION_ID` | Inherited from `treeship session start`; auto-included in payloads. |
| `TREESHIP_DEBUG=1` | Logs attestation failures to stderr. |

## Design rules

- Treeship errors **never** fail the A2A handler.
- Only digests and metadata are stored, never raw task content.
- Intent attestation is **awaited** so the proof exists before the agent runs.
- Receipt attestation is fast and runs inside `onTaskCompleted` so the receipt URL is available before you return the artifact.
- Handoffs and AgentCard extensions are **opt-in but on-by-default**.

## License

Apache-2.0
