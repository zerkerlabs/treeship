# Cloudflare Worker acceptance test

## Deploy

```bash
cd tests/runtime-acceptance/cloudflare-worker
npm install
npx wrangler deploy
```

Note the worker URL wrangler prints.

## Test

```bash
curl -X POST https://<your-worker>.workers.dev \
  -H "content-type: application/json" \
  -d '{"url":"https://treeship.dev/receipt/ssn_<a-real-session-id>"}'
```

The response body should match `treeship verify <same-url> --format json`
byte for byte (modulo ordering of optional fields).

## Cold start

Cloudflare Workers cold-start is typically under 50ms even with a WASM
module of this size. Observe in the Cloudflare dashboard's Workers
observability view.

## Gotchas

- Worker size limit on the free tier is 1 MB post-compression. Our bundle
  (`@treeship/core-wasm` at ~170 KB gzipped plus a thin wrapper) fits with
  room to spare.
- `nodejs_compat` is enabled because some transitive wasm-bindgen glue
  may reference Node-compat shims. Not strictly required in every case;
  remove if the bundle builds without it.
