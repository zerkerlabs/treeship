import type { TreeshipArtifactMetadata, VerifiedReceipt } from './types.js';

/**
 * Fetch a Treeship receipt JSON document from a public receipt URL.
 *
 * The Hub serves receipts at `/v1/receipt/:session_id` (and the human-readable
 * mirror at `treeship.dev/receipt/ssn_xxx`). This helper accepts either form.
 */
export async function fetchReceipt(receiptUrl: string): Promise<unknown | null> {
  // Map the human-readable mirror to the JSON API.
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
 * Verify a Treeship receipt URL pulled from an A2A artifact's metadata.
 *
 * Returns a structured summary the calling agent can use to decide whether
 * to trust the work. This is a network-level verification — for cryptographic
 * Merkle/Ed25519 verification, shell out to `treeship verify-receipt`.
 */
export async function verifyReceipt(receiptUrl: string): Promise<VerifiedReceipt | null> {
  const raw = await fetchReceipt(receiptUrl);
  if (!raw || typeof raw !== 'object') return null;
  const r = raw as Record<string, unknown>;

  const sessionId =
    (typeof r.session_id === 'string' && r.session_id) ||
    (typeof r.id === 'string' && r.id) ||
    '';

  const events = Array.isArray(r.events) ? r.events.length : 0;
  const artifacts = Array.isArray(r.artifacts) ? r.artifacts.length : 0;
  const declared = r.declaration as Record<string, unknown> | undefined;
  const violations = Array.isArray(r.violations) ? r.violations.length : 0;

  return {
    sessionId,
    shipId: typeof r.ship_id === 'string' ? r.ship_id : undefined,
    digest: typeof r.digest === 'string' ? r.digest : undefined,
    events,
    artifacts,
    withinDeclaredBounds: declared ? violations === 0 : true,
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
