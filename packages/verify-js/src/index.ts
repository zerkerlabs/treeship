// @treeship/verify -- zero-dependency cryptographic verification.
//
// Install this package alone to verify Treeship Session Receipts and Agent
// Certificates in any runtime with WebAssembly and fetch. It is deliberately
// tiny: the only dependency is @treeship/core-wasm (the compiled Rust core,
// ~170 KB gzipped). There is no transitive dependency on @treeship/sdk,
// so shipping this to an edge worker, browser dashboard, or Witness doesn't
// pull the subprocess code path in at all.
//
// Same rules `treeship verify` applies from the CLI, same result shape.
// If a new schema version lands in core, this package picks it up via
// core-wasm without an API change here.

// Lazy WASM load. Keeps the module graph resolvable even in environments
// where @treeship/core-wasm hasn't been installed yet. First call pays the
// load cost; subsequent calls reuse cached bindings.
type WasmBindings = {
  verify_receipt: (json: string) => string;
  verify_certificate: (json: string, now: string) => string;
  cross_verify: (receipt: string, cert: string, now: string) => string;
};

let wasmBindings: WasmBindings | null = null;

async function loadWasm(): Promise<WasmBindings> {
  if (wasmBindings) return wasmBindings;
  const mod = (await import('@treeship/core-wasm')) as unknown as WasmBindings;
  wasmBindings = mod;
  return mod;
}

/** Accepted input shapes across all exported functions. */
export type VerifyTarget = string | URL | Record<string, unknown>;

async function normalizeToJson(target: VerifyTarget): Promise<string> {
  if (typeof target === 'object' && !(target instanceof URL)) {
    return JSON.stringify(target);
  }
  const raw = target instanceof URL ? target.toString() : target;
  if (raw.startsWith('http://') || raw.startsWith('https://')) {
    // Accept both the Hub JSON API path and the human-readable mirror.
    const apiUrl = raw.replace('/receipt/', '/v1/receipt/');
    const res = await fetch(apiUrl, { headers: { accept: 'application/json' } });
    if (!res.ok) throw new Error(`fetch ${apiUrl} returned HTTP ${res.status}`);
    return await res.text();
  }
  return raw;
}

export interface VerifyCheck {
  step: string;
  status: 'pass' | 'fail' | 'warn';
  detail: string;
}

export interface VerifyReceiptResult {
  outcome: 'pass' | 'fail' | 'error';
  checks: VerifyCheck[];
  session: {
    id: string;
    ship_id?: string;
    schema_version?: string;
    agent: string;
    duration_ms?: number;
    actions: number;
  };
  error_code?: string;
  message?: string;
}

export interface VerifyCertificateResult {
  outcome: 'pass' | 'fail' | 'error';
  signature_valid: boolean;
  validity: 'valid' | 'expired' | 'not_yet_valid' | 'not_checked';
  certificate: {
    ship_id: string;
    agent_name: string;
    issued_at: string;
    valid_until: string;
    schema_version?: string;
  };
  error_code?: string;
  message?: string;
}

export interface CrossVerifyResult {
  outcome: 'pass' | 'fail' | 'error';
  ok: boolean;
  ship_id_status: 'match' | 'mismatch' | 'unknown';
  certificate_status: 'valid' | 'expired' | 'not_yet_valid';
  certificate_signature_valid: boolean;
  authorized_tool_calls: string[];
  unauthorized_tool_calls: string[];
  authorized_tools_never_called: string[];
  error_code?: string;
  message?: string;
}

/**
 * Verify a Treeship Session Receipt. Runs the checks derivable from the
 * receipt JSON alone (Merkle root recomputation, inclusion proofs, leaf
 * count, timeline ordering, chain linkage). Signature verification on
 * individual envelopes requires the original envelope bytes and is out of
 * scope for URL-fetched receipts; use the `treeship verify` CLI for that.
 *
 * Accepts:
 * - a parsed receipt object (best for callers that already have the JSON)
 * - a JSON string
 * - a URL string (fetched with the runtime's global fetch)
 * - a URL object
 */
export async function verifyReceipt(
  target: VerifyTarget,
): Promise<VerifyReceiptResult> {
  const json = await normalizeToJson(target);
  const wasm = await loadWasm();
  return JSON.parse(wasm.verify_receipt(json));
}

/**
 * Verify an Agent Certificate. Checks the embedded Ed25519 signature
 * against the certificate's embedded public key, then optionally
 * classifies the validity window relative to `now`.
 *
 * Omit `now` (or pass `undefined`) to defer validity classification
 * (signature-only). Pass a `Date` or RFC 3339 string to check expiry.
 */
export async function verifyCertificate(
  target: VerifyTarget,
  now?: Date | string,
): Promise<VerifyCertificateResult> {
  const json = await normalizeToJson(target);
  const nowStr =
    now === undefined ? '' : now instanceof Date ? now.toISOString() : now;
  const wasm = await loadWasm();
  return JSON.parse(wasm.verify_certificate(json, nowStr));
}

/**
 * Cross-verify a Session Receipt against an Agent Certificate. Answers
 * three questions in one call: do the receipt and certificate reference
 * the same ship? Was the certificate valid at `now`? Was every tool the
 * session called authorized by the certificate?
 *
 * The `ok` field is the roll-up: true iff all three checks pass. Defaults
 * `now` to `Date.now()` if omitted.
 */
export async function crossVerify(
  receipt: VerifyTarget,
  certificate: VerifyTarget,
  now?: Date | string,
): Promise<CrossVerifyResult> {
  const [receiptJson, certJson] = await Promise.all([
    normalizeToJson(receipt),
    normalizeToJson(certificate),
  ]);
  const nowStr =
    now === undefined
      ? new Date().toISOString()
      : now instanceof Date
        ? now.toISOString()
        : now;
  const wasm = await loadWasm();
  return JSON.parse(wasm.cross_verify(receiptJson, certJson, nowStr));
}
