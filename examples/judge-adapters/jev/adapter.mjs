#!/usr/bin/env node
// A judge-contract adapter for TypeSafe's Jev (System One).
//
// Treeship's judge contract is "state plus typed questions in, typed
// answers out" (docs.treeship.dev/cli/judge). Jev's API is the same three
// primitives with different field names and one required field, `model`.
// This adapter listens on localhost, accepts a judge-contract request,
// forwards it to `POST https://api.typesafe.ai/v1/systemone`, and returns a
// judge-contract response, so `treeship judge --judge-url http://127.0.0.1:8787`
// puts Jev in the slot and every answer is signed as judgement.v1.
//
// Independent implementation against TypeSafe's published API docs
// (docs.typesafe.ai/api). Not coordinated with or endorsed by TypeSafe.
// Tested in CI against a mock of the documented request and response
// shapes (mock-jev.mjs), not against the live service.
//
//   TYPESAFE_API_KEY   required (never logged, never written to a receipt)
//   JEV_MODEL          default jev-1.13.0 (pinned, so the receipt names a version)
//   JEV_BASE_URL       default https://api.typesafe.ai
//   PORT               default 8787
//
// No dependencies. Node 18+.

import { createServer } from 'node:http';

const API_KEY = process.env.TYPESAFE_API_KEY;
const MODEL = process.env.JEV_MODEL || 'jev-1.13.0';
const BASE = (process.env.JEV_BASE_URL || 'https://api.typesafe.ai').replace(/\/$/, '');
const PORT = Number(process.env.PORT || 8787);

if (!API_KEY) {
  console.error('adapter: TYPESAFE_API_KEY is not set');
  process.exit(2);
}

/** Judge-contract questions -> Jev questions. */
export function toJev(state, questions) {
  const out = {};
  for (const [key, q] of Object.entries(questions || {})) {
    const instructions = q.instructions || key;
    switch (q.type) {
      case 'noul':
        out[key] = { type: 'noul', instructions };
        break;
      case 'choice': {
        const criteria = {};
        for (const opt of q.options || []) criteria[opt] = null;
        if (Object.keys(criteria).length === 0) {
          throw new Error(`question ${key}: a choice needs options`);
        }
        out[key] = { type: 'choice', instructions, criteria };
        break;
      }
      case 'score': {
        const levels = q.options || [];
        if (levels.length < 2 || levels.length > 10) {
          throw new Error(`question ${key}: a score needs 2 to 10 levels in options`);
        }
        out[key] = { type: 'score', instructions, criteria: levels };
        break;
      }
      default:
        throw new Error(`question ${key}: unknown type ${q.type}`);
    }
  }
  return { state, model: MODEL, questions: out };
}

/** Jev answers -> judge-contract answers. Nothing is invented: a field Jev
 * did not return is left out, and the CLI's own checks decide. */
export function fromJev(body, questions, latencyMs, requestId) {
  const answers = {};
  for (const [key, a] of Object.entries(body.answers || {})) {
    const q = questions[key] || {};
    const out = {};
    if (a.type === 'noul' && typeof a.noul === 'number') {
      out.noul = a.noul;
      out.probabilities = { yes: a.noul, no: 1 - a.noul };
      out.confidence = a.noul;
    } else if (a.type === 'choice') {
      out.choice = a.choice;
      if (a.probabilities) out.probabilities = a.probabilities;
      if (typeof a.confidence === 'number') out.confidence = a.confidence;
    } else if (a.type === 'score') {
      out.score = a.score;
      if (a.probabilities) {
        // Jev keys score probabilities by level index; name them by the
        // caller's level labels when it gave any.
        const labels = q.options || [];
        out.probabilities = {};
        for (const [k, p] of Object.entries(a.probabilities)) {
          out.probabilities[labels[Number(k)] ?? String(k)] = p;
        }
      }
      if (typeof a.confidence === 'number') out.confidence = a.confidence;
    }
    answers[key] = out;
  }
  return {
    judge: {
      model: body.model || MODEL,
      provider: 'typesafe',
      kind: 'decision-model',
      // A sampled model: the same state may not return the same answer,
      // so a verifier cannot re-run it. The receipt says so.
      replayable: false,
    },
    answers,
    latency_ms: latencyMs,
    usage: body.usage,
    // Jev's id for this answer, so the receipt can point at it.
    request_id: requestId,
  };
}

async function judge(req) {
  const started = Date.now();
  const payload = toJev(req.state, req.questions);
  const res = await fetch(`${BASE}/v1/systemone`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: `Bearer ${API_KEY}` },
    body: JSON.stringify(payload),
    signal: AbortSignal.timeout(8000),
  });
  const text = await res.text();
  const requestId = res.headers.get('x-typesafe-request-id') || undefined;
  if (!res.ok) {
    // Say what Jev said, minus nothing that could be a key. The CLI reports
    // any non-2xx from here as `judge unavailable`, which is the honest
    // outcome: an unavailable judge is not an allow.
    const err = new Error(`jev: HTTP ${res.status}: ${text.slice(0, 300)}`);
    err.status = res.status === 429 || res.status === 529 ? 503 : 502;
    throw err;
  }
  return fromJev(JSON.parse(text), req.questions || {}, Date.now() - started, requestId);
}

if (process.argv[1] && import.meta.url.endsWith(process.argv[1].split('/').pop())) {
  createServer(async (rq, rs) => {
    if (rq.method !== 'POST') {
      rs.writeHead(405).end();
      return;
    }
    let raw = '';
    for await (const chunk of rq) raw += chunk;
    try {
      const out = await judge(JSON.parse(raw));
      const headers = { 'content-type': 'application/json' };
      if (out.request_id) headers['x-typesafe-request-id'] = out.request_id;
      rs.writeHead(200, headers).end(JSON.stringify(out));
    } catch (e) {
      rs.writeHead(e.status || 500, { 'content-type': 'application/json' })
        .end(JSON.stringify({ error: String(e.message || e) }));
    }
  }).listen(PORT, '127.0.0.1', () => {
    console.error(`jev adapter listening on http://127.0.0.1:${PORT} (model ${MODEL}, upstream ${BASE})`);
  });
}
