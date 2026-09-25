#!/usr/bin/env node
// A mock of Jev's documented API, for the adapter's test. It implements the
// request and response shapes from docs.typesafe.ai/api and answers by
// rule, so the test is about the adapter's mapping, not about Jev.
//
//   noul   -> 0.96 when the state's command mentions rm -rf, else 0.04
//   choice -> "deny" when it does and the options include deny, else the first option
//   score  -> the top level when it does, else the bottom
//
// Refuses a request that is not shaped the way the docs say (no model, a
// question without a type, a choice without criteria) with 422, which is
// what the live service does.

import { createServer } from 'node:http';

const PORT = Number(process.env.PORT || 8788);

createServer(async (rq, rs) => {
  let raw = '';
  for await (const chunk of rq) raw += chunk;
  if (rq.headers.authorization !== 'Bearer test-key') {
    rs.writeHead(401, { 'content-type': 'application/json' }).end('{"error":"unauthorized"}');
    return;
  }
  let body;
  try {
    body = JSON.parse(raw);
  } catch {
    rs.writeHead(422).end('{"error":"invalid json"}');
    return;
  }
  if (!body.model || !body.questions || body.state === undefined) {
    rs.writeHead(422).end('{"error":"state, model and questions are required"}');
    return;
  }
  const text = JSON.stringify(body.state).toLowerCase();
  const hot = text.includes('rm -rf');
  const answers = {};
  for (const [key, q] of Object.entries(body.questions)) {
    if (q.type === 'noul') {
      answers[key] = { type: 'noul', noul: hot ? 0.96 : 0.04 };
    } else if (q.type === 'choice') {
      const opts = Object.keys(q.criteria || {});
      if (opts.length === 0) {
        rs.writeHead(422).end(`{"error":"choice ${key} needs criteria"}`);
        return;
      }
      const pick = hot && opts.includes('deny') ? 'deny' : opts[0];
      const probabilities = {};
      for (const o of opts) probabilities[o] = o === pick ? 0.9 : 0.1 / Math.max(1, opts.length - 1);
      answers[key] = { type: 'choice', choice: pick, probabilities, confidence: 0.9 };
    } else if (q.type === 'score') {
      const levels = q.criteria || [];
      if (levels.length < 2) {
        rs.writeHead(422).end(`{"error":"score ${key} needs 2+ levels"}`);
        return;
      }
      const top = levels.length - 1;
      const idx = hot ? top : 0;
      const probabilities = {};
      const legend = {};
      levels.forEach((l, i) => {
        probabilities[i] = i === idx ? 0.85 : 0.15 / top;
        legend[i] = l;
      });
      answers[key] = { type: 'score', score: idx, legend, probabilities, confidence: 0.85 };
    } else {
      rs.writeHead(422).end(`{"error":"question ${key} has no type"}`);
      return;
    }
  }
  rs.writeHead(200, { 'content-type': 'application/json', 'x-typesafe-request-id': 'req_mock_1' })
    .end(JSON.stringify({ model: body.model, answers, usage: { input_tokens: 120, output_tokens: 0 } }));
}).listen(PORT, '127.0.0.1', () => console.error(`mock jev on http://127.0.0.1:${PORT}`));
