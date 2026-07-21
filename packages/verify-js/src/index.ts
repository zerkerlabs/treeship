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
  verify_certificate: (json: string, now: string, trustRoots: string) => string;
  cross_verify: (
    receipt: string,
    cert: string,
    now: string,
    trustRoots: string,
  ) => string;
  verify_capability: (
    card: string,
    actions: string,
    trustRoots: string,
  ) => string;
  verify_resolution: (
    bundle: string,
    trustRoots: string,
    now: string,
  ) => string;
  verify_presentation: (
    presentation: string,
    trustRoots: string,
    expectedNonce: string,
    now: string,
  ) => string;
};

/**
 * Trust roots input shape. Mirrors the on-disk
 * `~/.treeship/trust_roots.json` so the browser-side verifier sees the
 * same data the CLI does.
 */
export interface TrustRootInput {
  key_id: string;
  /** `ed25519:<base64url-no-pad>` */
  public_key: string;
  /**
   * The powers a root grants, after the v0.19 trust-split. The single old
   * `ship` kind was split into `hub_org` / `cert_issuer` / `revoker` and is
   * now deprecated and inert (no verifier honors it), so it is intentionally
   * not offered here. See TrustRootKind in packages/core/src/trust/mod.rs.
   */
  kind:
    | 'hub_checkpoint'
    | 'hub_org'
    | 'cert_issuer'
    | 'revoker'
    | 'agent_cert'
    | 'session_host';
  label?: string;
  added_at?: string;
}

export interface TrustRootsBundle {
  version: 1;
  roots: TrustRootInput[];
}

/** Empty bundle is valid input -- the verifier will fail-closed. */
function serializeTrustRoots(
  roots: TrustRootsBundle | TrustRootInput[] | undefined,
): string {
  if (!roots) return '';
  if (Array.isArray(roots)) {
    return JSON.stringify({ version: 1, roots });
  }
  return JSON.stringify(roots);
}

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
  // `structural-pass` is the honest verdict for a receipt whose Merkle
  // structure and inclusion proofs are internally consistent but whose
  // authorship is not established here (no issuer trust). The WASM
  // `verify_receipt` emits it (see core-wasm, AUD-01); the type must admit it.
  outcome: 'pass' | 'structural-pass' | 'fail' | 'error';
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
 * count, timeline ordering). Signature verification on individual envelopes
 * requires the original envelope bytes and is out of scope for URL-fetched
 * receipts; use the `treeship verify` CLI for that.
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
 * against a trust root the caller pins via `trustRoots`, then optionally
 * classifies the validity window relative to `now`.
 *
 * `trustRoots` is REQUIRED for the signature to be accepted: as of the
 * v0.10.3 trust-root audit fix, the previous self-signed behavior (trust
 * the embedded pubkey) is gone. Pass the same JSON shape your CLI uses
 * (`~/.treeship/trust_roots.json`) or an array of `TrustRootInput`.
 * Omit it to get a deliberate fail-closed result for diagnostic UIs.
 *
 * Omit `now` (or pass `undefined`) to defer validity classification
 * (signature-only). Pass a `Date` or RFC 3339 string to check expiry.
 */
export async function verifyCertificate(
  target: VerifyTarget,
  now?: Date | string,
  trustRoots?: TrustRootsBundle | TrustRootInput[],
): Promise<VerifyCertificateResult> {
  const json = await normalizeToJson(target);
  const nowStr =
    now === undefined ? '' : now instanceof Date ? now.toISOString() : now;
  const wasm = await loadWasm();
  return JSON.parse(
    wasm.verify_certificate(json, nowStr, serializeTrustRoots(trustRoots)),
  );
}

/**
 * Cross-verify a Session Receipt against an Agent Certificate. Answers
 * three questions in one call: do the receipt and certificate reference
 * the same ship? Was the certificate valid at `now`? Was every tool the
 * session called authorized by the certificate?
 *
 * The `ok` field is the roll-up: true iff all three checks pass. Defaults
 * `now` to `Date.now()` if omitted. As with `verifyCertificate`,
 * `trustRoots` is required for the certificate's embedded signature to
 * be accepted.
 */
export async function crossVerify(
  receipt: VerifyTarget,
  certificate: VerifyTarget,
  now?: Date | string,
  trustRoots?: TrustRootsBundle | TrustRootInput[],
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
  return JSON.parse(
    wasm.cross_verify(receiptJson, certJson, nowStr, serializeTrustRoots(trustRoots)),
  );
}

/** Result of {@link verifyCapability}. Mirrors the WASM JSON output. */
export interface CapabilityVerifyResult {
  outcome: 'pass' | 'fail' | 'error';
  /** The actor the card claims, e.g. `agent://deployer`. */
  agent?: string;
  /** True iff the card's keyid is its signer AND pinned under AgentCert. */
  key_bound?: boolean;
  declared_tools?: string[];
  in_scope?: number;
  out_of_scope?: number;
  violations?: { tool: string }[];
  status?: 'verified' | 'self-asserted' | 'violations';
  error_code?: string;
  message?: string;
}

/**
 * Verify an agent_card.v1 capability card in the browser, the same check
 * `treeship verify-capability` runs (shared Rust logic via
 * `treeship_core::capability`). Pass the card envelope and the action
 * envelopes to cross-check; `trustRoots` is required for `key_bound` to be
 * true (otherwise the card is reported self-asserted).
 *
 * Honest contract: this is consistency over the actions you provide, not a
 * completeness guarantee. It cannot prove the agent took no off-card action.
 */
export async function verifyCapability(
  card: VerifyTarget,
  actions: VerifyTarget[],
  trustRoots?: TrustRootsBundle | TrustRootInput[],
): Promise<CapabilityVerifyResult> {
  const cardJson = await normalizeToJson(card);
  const actionJsons = await Promise.all((actions ?? []).map(normalizeToJson));
  // Each normalized action is a JSON object; assemble them into a JSON array.
  const actionsJson = `[${actionJsons.join(',')}]`;
  const wasm = await loadWasm();
  return JSON.parse(
    wasm.verify_capability(cardJson, actionsJson, serializeTrustRoots(trustRoots)),
  );
}

/** One certificate in a resolution bundle's chain. */
export interface ResolutionCert {
  artifact_id: string;
  /** An `agent_cert.v1` DSSE envelope object. */
  envelope: Record<string, unknown>;
}

/**
 * A resolution bundle: the signed bytes needed to decide whether an agent's
 * current card is trustworthy. This is the same shape the Hub serves and the
 * CLI re-verifies — assemble it from a `resolve` response.
 */
export interface ResolutionBundleInput {
  agent: string;
  /** The agent's current `agent_card.v1` DSSE envelope object. */
  card: Record<string, unknown>;
  certs?: ResolutionCert[];
  /** `agent_card_revocation.v1` DSSE envelope objects. */
  revocations?: Record<string, unknown>[];
}

/** Result of {@link verifyResolution}. Mirrors the WASM JSON output. */
export interface ResolutionVerdict {
  /** Card signature verified against your roots (directly or via the chain). */
  sig_ok: boolean;
  /** Card is key-bound: signer pinned under AgentCert, or chain-certified. */
  key_bound: boolean;
  /** If verified via the certificate chain, the cert artifact that vouched. */
  chain_cert_id: string | null;
  /** An authorized, verifying revocation was found. */
  revoked: boolean;
  revocation_reason: string | null;
  error_code?: string;
  message?: string;
}

/**
 * Verify an agent resolution bundle in the browser — the same `resolve --hub`
 * trust decision the CLI makes, via shared Rust logic
 * (`treeship_core::verify::resolution`). Verifies the card by direct leaf pin
 * or certificate-chain walk, then honors an authorized revocation.
 *
 * `trustRoots` is required for `key_bound` to be true; with none, the bundle
 * fails closed. `now` defaults to the current time (used for cert validity
 * windows in the chain walk).
 */
export async function verifyResolution(
  bundle: ResolutionBundleInput,
  trustRoots?: TrustRootsBundle | TrustRootInput[],
  now?: Date | string,
): Promise<ResolutionVerdict> {
  const nowStr =
    now === undefined
      ? new Date().toISOString()
      : now instanceof Date
        ? now.toISOString()
        : now;
  const wasm = await loadWasm();
  return JSON.parse(
    wasm.verify_resolution(
      JSON.stringify(bundle),
      serializeTrustRoots(trustRoots),
      nowStr,
    ),
  );
}

/** The challenge-response outcome within a presentation. */
export interface PresentationChallenge {
  outcome:
    | 'not_requested'
    | 'present_but_unchecked'
    | 'no_response'
    | 'no_established_key'
    | 'verified'
    | 'failed';
  /** Bearer-signed timestamp, when `outcome` is `verified`. */
  signed_at: string | null;
  /** Failure reason, when `outcome` is `failed`. */
  reason: string | null;
}

/** The staple portion of a presentation verdict. */
export interface PresentationStaple {
  verified: boolean;
  status:
    | 'no_staple'
    | 'unparseable'
    | 'signer_not_trusted'
    | 'inclusion_invalid'
    | 'verified';
  checkpoint_index: number | null;
  age_secs: number | null;
}

/** Result of {@link verifyPresentation}. Mirrors the WASM JSON output. */
export interface PresentationVerdict {
  agent: string;
  card_id: string;
  /** Card signature verified against your roots (directly or via the chain). */
  sig_ok: boolean;
  key_bound: boolean;
  via_chain: boolean;
  revoked: string | null;
  challenge: PresentationChallenge;
  challenge_ok: boolean;
  staple: PresentationStaple;
  /** Roll-up: not revoked, key-bound, and (if requested) challenge verified.
   * Freshness (`--max-staple-age`) is your own policy over `staple.age_secs`. */
  ok: boolean;
  error_code?: string;
  message?: string;
}

/**
 * Verify an agent presentation in the browser — the same `verify-presentation`
 * trust decision the CLI makes, via shared Rust logic
 * (`treeship_core::verify::presentation`). Verifies the card (direct pin or
 * chain), honors an authorized revocation, checks challenge liveness (when
 * `nonce` is given), and verifies the staple.
 *
 * `trustRoots` is required for `key_bound`; with none, the presentation fails
 * closed. `nonce` is the challenge nonce YOU issued (omit to skip liveness).
 * `now` defaults to the current time.
 */
export async function verifyPresentation(
  presentation: Record<string, unknown>,
  trustRoots?: TrustRootsBundle | TrustRootInput[],
  opts?: { nonce?: string; now?: Date | string },
): Promise<PresentationVerdict> {
  const now = opts?.now;
  const nowStr =
    now === undefined
      ? new Date().toISOString()
      : now instanceof Date
        ? now.toISOString()
        : now;
  const wasm = await loadWasm();
  return JSON.parse(
    wasm.verify_presentation(
      JSON.stringify(presentation),
      serializeTrustRoots(trustRoots),
      opts?.nonce ?? '',
      nowStr,
    ),
  );
}
