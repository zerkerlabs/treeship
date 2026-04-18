import type { TreeshipArtifactMetadata, VerifiedReceipt } from './types.js';

// Lazy WASM load. Same pattern as @treeship/sdk: the A2A middleware can be
// imported in environments where @treeship/core-wasm is not yet resolvable
// (early bootstrap CI, non-verification code paths in consumers). First
// verify call pays the load cost; subsequent calls reuse the cached
// bindings. Trades one-time latency for robustness.
type WasmBindings = {
  verify_receipt: (json: string) => string;
};

let wasmBindings: WasmBindings | null = null;

async function loadWasm(): Promise<WasmBindings | null> {
  if (wasmBindings) return wasmBindings;
  try {
    const mod = (await import('@treeship/core-wasm')) as unknown as WasmBindings;
    wasmBindings = mod;
    return mod;
  } catch {
    // Consumer runtime can't load WASM. Fall through to network-only
    // summary; the returned VerifiedReceipt still carries the parsed
    // receipt raw so callers can make their own decisions.
    return null;
  }
}

/**
 * Fetch a Treeship receipt JSON document from a public receipt URL.
 *
 * The Hub serves receipts at `/v1/receipt/:session_id` (and the human-readable
 * mirror at `treeship.dev/receipt/ssn_xxx`). This helper accepts either form.
 */
export async function fetchReceipt(receiptUrl: string): Promise<unknown | null> {
  const apiUrl = receiptUrl.replace(/\/receipt\//, '/v1/receipt/');
  try {
    const res = await fetch(apiUrl, { headers: { accept: 'application/json' } });
    if (!res.ok) return null;
    return await res.json();
  } catch {
    return null;
  }
}

/**
 * Fetch a Treeship receipt and cryptographically verify it via WASM.
 *
 * Runs the same checks `treeship verify <url>` runs on the CLI: Merkle root
 * recomputation, inclusion proofs, leaf-count parity, timeline ordering,
 * receipt-level chain linkage. Signature verification on individual
 * envelopes requires the original envelope bytes which a URL-fetched
 * receipt does not carry; for that, use the local-storage CLI path.
 *
 * Returns a `VerifiedReceipt` summary the calling agent can use to decide
 * whether to trust the remote work. `cryptographicallyVerified: true`
 * means the receipt's JSON-level integrity was confirmed. `null` if the
 * URL is unreachable or the document is unparseable.
 */
export async function verifyReceipt(receiptUrl: string): Promise<VerifiedReceipt | null> {
  const raw = await fetchReceipt(receiptUrl);
  if (!raw || typeof raw !== 'object') return null;
  const r = raw as Record<string, unknown>;

  const sessionId =
    (typeof r.session_id === 'string' && r.session_id) ||
    (typeof (r as { session?: { id?: unknown } }).session?.id === 'string' &&
      (r as { session: { id: string } }).session.id) ||
    (typeof r.id === 'string' && r.id) ||
    '';

  const session = r.session as Record<string, unknown> | undefined;
  const shipId =
    typeof r.ship_id === 'string'
      ? r.ship_id
      : typeof session?.ship_id === 'string'
        ? (session.ship_id as string)
        : undefined;

  const events = Array.isArray(r.events) ? r.events.length : 0;
  const artifacts = Array.isArray(r.artifacts) ? r.artifacts.length : 0;
  const declared = r.declaration as Record<string, unknown> | undefined;
  const violations = Array.isArray(r.violations) ? r.violations.length : 0;

  let cryptographicallyVerified = false;
  let verifyChecks:
    | { step: string; status: 'pass' | 'fail' | 'warn'; detail: string }[]
    | undefined;

  const wasm = await loadWasm();
  if (wasm) {
    try {
      const resultJson = wasm.verify_receipt(JSON.stringify(raw));
      const parsed = JSON.parse(resultJson) as {
        outcome: string;
        checks?: typeof verifyChecks;
      };
      cryptographicallyVerified = parsed.outcome === 'pass';
      verifyChecks = parsed.checks;
    } catch {
      // WASM available but verification threw. Leave cryptographicallyVerified=false.
    }
  }

  return {
    sessionId,
    shipId,
    digest: typeof r.digest === 'string' ? r.digest : undefined,
    events,
    artifacts,
    withinDeclaredBounds: declared ? violations === 0 : true,
    cryptographicallyVerified,
    verifyChecks,
    raw,
  };
}

/**
 * Convenience: verify the receipt linked from an A2A artifact's metadata.
 * Returns null if the artifact has no Treeship metadata.
 */
export async function verifyArtifact(metadata: TreeshipArtifactMetadata | undefined | null) {
  const url = metadata?.treeship_receipt_url;
  if (!url) return null;
  return verifyReceipt(url);
}
