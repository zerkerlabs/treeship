// Cloudflare Worker that verifies a Treeship receipt by URL.
//
// Deploy with: wrangler deploy
// Invoke:       curl -X POST https://<your-worker>.workers.dev \
//                 -H "content-type: application/json" \
//                 -d '{"url":"https://treeship.dev/receipt/ssn_abc"}'

import { verifyReceipt } from '@treeship/verify';

export default {
  async fetch(request: Request): Promise<Response> {
    if (request.method !== 'POST') {
      return new Response('POST only', { status: 405 });
    }

    let body: { url?: string };
    try {
      body = (await request.json()) as { url?: string };
    } catch {
      return new Response('invalid JSON body', { status: 400 });
    }
    if (!body.url) {
      return new Response('missing url', { status: 400 });
    }

    try {
      const result = await verifyReceipt(body.url);
      return Response.json(result);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      return Response.json({ outcome: 'error', message }, { status: 500 });
    }
  },
};
