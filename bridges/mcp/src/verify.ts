// WASM-backed verification helpers for @treeship/mcp consumers.
//
// The MCP bridge's primary role is to intercept tool calls and attest them.
// These helpers let the same consumer verify remote Treeship receipts and
// certificates in the same process without installing a second SDK.
//
// Same lazy-WASM pattern as @treeship/sdk: first call loads and caches
// @treeship/core-wasm; subsequent calls reuse the bindings. Module graph
// stays resolvable in environments that don't have WASM support.

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

export type VerifyTarget = string | URL | Record<string, unknown>;

async function normalizeToJson(target: VerifyTarget): Promise<string> {
  if (typeof target === 'object' && !(target instanceof URL)) {
    return JSON.stringify(target);
  }
  const raw = target instanceof URL ? target.toString() : target;
  if (raw.startsWith('http://') || raw.startsWith('https://')) {
    const apiUrl = raw.replace('/receipt/', '/v1/receipt/');
    const res = await fetch(apiUrl, { headers: { accept: 'application/json' } });
    if (!res.ok) throw new Error(`fetch ${apiUrl} returned HTTP ${res.status}`);
    return await res.text();
  }
  return raw;
}

export interface VerifyReceiptResult {
  outcome: 'pass' | 'fail' | 'error';
  checks: { step: string; status: 'pass' | 'fail' | 'warn'; detail: string }[];
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
 * Verify a Treeship Session Receipt via WASM. Same checks `treeship verify <url>`
 * runs on the CLI.
 */
export async function verifyReceipt(target: VerifyTarget): Promise<VerifyReceiptResult> {
  const json = await normalizeToJson(target);
  const wasm = await loadWasm();
  return JSON.parse(wasm.verify_receipt(json));
}

/**
 * Verify an Agent Certificate via WASM. Omit `now` to defer validity
 * classification (signature-only check).
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
 * Cross-verify a receipt against an agent certificate. Defaults `now` to
 * the current time if omitted.
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
