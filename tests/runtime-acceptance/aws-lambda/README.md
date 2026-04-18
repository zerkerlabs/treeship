# AWS Lambda acceptance test

Deployable as a SAM application or via the serverless framework. The
handler is a standard Node 20 Lambda that bundles `@treeship/verify` with
esbuild.

## Build

```bash
cd tests/runtime-acceptance/aws-lambda
npm install
npm run build
```

This emits `dist/handler.mjs` bundled for Node 20.

## Deploy (SAM)

```bash
sam build --use-container
sam deploy --guided
```

Note the `ApiUrl` output SAM prints.

## Test

```bash
curl -X POST https://<your-api>.execute-api.<region>.amazonaws.com/verify \
  -H "content-type: application/json" \
  -d '{"url":"https://treeship.dev/receipt/ssn_<a-real-session-id>"}'
```

The response body should match `treeship verify <same-url> --format json`
byte for byte (modulo ordering of optional fields).

## Cold start

Node Lambda cold starts for this bundle are typically under 1 second on
arm64 with 256 MB memory. Increase memory if cold start matters; Lambda
scales CPU proportionally.

## Gotchas

- esbuild bundles `@treeship/core-wasm` as a single `.mjs`. Lambda's Node
  runtime loads WASM via `WebAssembly.instantiate` the same way as Node
  itself, so no special config is needed beyond the `type: module` in
  package.json and the ESM-targeted bundle.
- If the bundle exceeds 250 MB unzipped, SAM will fail to deploy. Our
  bundle is well under 1 MB, so this is unlikely, but it is the one size
  limit Lambda imposes that matters here.
