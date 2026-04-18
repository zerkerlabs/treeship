# Vercel Edge acceptance test

## Deploy

```bash
cd tests/runtime-acceptance/vercel-edge
npm install
npx vercel --prod
```

Note the deploy URL Vercel prints.

## Test

```bash
curl -X POST https://<your-deploy>.vercel.app/api/verify \
  -H "content-type: application/json" \
  -d '{"url":"https://treeship.dev/receipt/ssn_<a-real-session-id>"}'
```

The response body should match `treeship verify <same-url> --format json`
byte for byte (modulo ordering of optional fields).

## Cold start

Cold-start time is logged in Vercel's observability tab for the function.
Target is under 3 seconds for the first request after deploy.

## Gotchas

- Vercel Edge uses V8 isolates, not Node. Anything that touches `fs` or
  `child_process` in the import graph of `@treeship/verify` would fail to
  build. The dependency (`@treeship/core-wasm` only) is runtime-safe.
- The function expects `POST`. GET or other methods return 405.
