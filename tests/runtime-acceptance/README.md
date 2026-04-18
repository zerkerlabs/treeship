# Edge runtime acceptance tests

Minimal verification endpoints that exercise `@treeship/verify` on each
supported edge runtime. Each subdirectory is a self-contained, runnable
project with deploy instructions in its own README.

The goal is one assertion: **posting a real Treeship receipt URL to the
deployed endpoint returns the same verification result `treeship verify`
produces on the CLI.**

Per-runtime acceptance criteria:

1. Receipt verifies successfully
2. Result matches CLI output on the same receipt
3. Cold start under 3 seconds (measured once per runtime)
4. No runtime errors or warnings in logs

These harnesses are code-complete and deployable, but the actual deploy +
cold-start measurement has been run out-of-band (see CHANGELOG). Rerun
the deploy steps in each subdir's README to reproduce.

| Runtime | Directory | Deploy | Status |
|---------|-----------|--------|--------|
| Vercel Edge Function | [vercel-edge/](./vercel-edge/) | `vercel --prod` | code-complete |
| Cloudflare Worker | [cloudflare-worker/](./cloudflare-worker/) | `wrangler deploy` | code-complete |
| AWS Lambda (Node) | [aws-lambda/](./aws-lambda/) | `sam deploy` or `serverless deploy` | code-complete |

Each endpoint expects a POST body:

```json
{"url": "https://treeship.dev/receipt/ssn_abc123"}
```

and returns the full `verifyReceipt` result shape (see the `@treeship/verify`
package for types).
