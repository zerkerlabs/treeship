// Vercel Edge Function that verifies a Treeship receipt by URL.
//
// Deploy with: vercel --prod
// Invoke:       curl -X POST https://<your-deploy>.vercel.app/api/verify \
//                 -H "content-type: application/json" \
//                 -d '{"url":"https://treeship.dev/receipt/ssn_abc"}'
//
// The response body is the full result of @treeship/verify's verifyReceipt
// call. Shape matches `treeship verify <url> --format json` from the CLI.

import { verifyReceipt } from '@treeship/verify';

export const config = { runtime: 'edge' };

export default async function handler(req: Request): Promise<Response> {
  if (req.method !== 'POST') {
    return new Response('POST only', { status: 405 });
  }

  let body: { url?: string };
  try {
    body = (await req.json()) as { url?: string };
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
}
