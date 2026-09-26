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
  verify_envelope: (envelope: string, trustedKeys: string) => string;
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

/**
 * The JSON API URL for a receipt URL a person pasted.
 *
 * `/receipt/<id>` (the human page) becomes `/v1/receipt/<id>`; `/v1/receipt/<id>`
 * and the site's `/api/receipt/<id>` mirror are already the API and are kept.
 * The host is never rewritten, a trailing slash is dropped, the query string
 * is kept and the fragment dropped. Anything else throws rather than being
 * fetched. Through 0.31.9 this was a blind `replace('/receipt/', …)`, which
 * turned the documented `https://api.treeship.dev/v1/receipt/<id>` into
 * `/v1/v1/receipt/<id>` and a 404. The rule is shared with the CLI
 * (`receipt_api_url` in verify_external.rs) through
 * `tests/vectors/receipt-urls.json`; change both or neither.
 *
 * @internal Exported for the shared-vector test; not part of the package's
 * supported API.
 */
export function receiptApiUrl(raw: string): string {
  const refuse = () =>
    new Error(
      `not a receipt URL: ${raw} (expected …/receipt/<session id> or …/v1/receipt/<session id>)`,
    );
  const schemeEnd = raw.indexOf('://');
  if (schemeEnd < 0) throw refuse();
  const scheme = raw.slice(0, schemeEnd).toLowerCase();
  if (scheme !== 'http' && scheme !== 'https') throw refuse();
  const afterScheme = raw.slice(schemeEnd + 3);
  const slash = afterScheme.indexOf('/');
  const host = slash < 0 ? afterScheme : afterScheme.slice(0, slash);
  const pathAndQuery = slash < 0 ? '' : afterScheme.slice(slash);
  // Userinfo (`treeship.dev@evil.example`) reads as one host and fetches
  // another; a pasted receipt link never carries it.
  if (host.length === 0 || host.includes('@')) throw refuse();
  const noFragment = pathAndQuery.split('#')[0];
  const q = noFragment.indexOf('?');
  const query = q < 0 ? null : noFragment.slice(q + 1);
  const path = (q < 0 ? noFragment : noFragment.slice(0, q)).replace(/\/+$/, '');

  // The id is whatever follows the receipt segment: exactly one path
  // segment of id characters, so `..`, `%2F` and friends never reach the
  // request.
  const idAfter = (marker: string): [number, string] | null => {
    const i = path.indexOf(marker);
    if (i < 0) return null;
    const id = path.slice(i + marker.length);
    return /^[A-Za-z0-9_-]+$/.test(id) ? [i, id] : null;
  };

  let apiPath: string;
  if (idAfter('/v1/receipt/')) apiPath = path;
  else if (idAfter('/api/receipt/')) apiPath = path;
  else {
    const hit = idAfter('/receipt/');
    if (!hit) throw refuse();
    apiPath = `${path.slice(0, hit[0])}/v1/receipt/${hit[1]}`;
  }
  return `${scheme}://${host}${apiPath}${query === null ? '' : `?${query}`}`;
}

async function normalizeToJson(target: VerifyTarget): Promise<string> {
  if (typeof target === 'object' && !(target instanceof URL)) {
    return JSON.stringify(target);
  }
  const raw = target instanceof URL ? target.toString() : target;
  if (raw.startsWith('http://') || raw.startsWith('https://')) {
    const apiUrl = receiptApiUrl(raw);
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

// ---------------------------------------------------------------------------
// Package verification
// ---------------------------------------------------------------------------

/**
 * The files of a `.treeship` package directory, keyed by their path inside
 * it (`receipt.json`, `record.json`, `keys.json`, `artifacts/<id>.json`, ...).
 * Values are the exact bytes; `receipt.json` is hashed as given, so pass file
 * contents unmodified. A map containing only `receipt.json` is valid input and
 * verifies structure only.
 */
export type PackageFiles = Record<string, string | Uint8Array>;

export interface VerifyPackageOptions {
  /**
   * Keys you trust, by key id: `{ key_...: 'ed25519:<base64url>' }` (the bare
   * base64url also works). A signature counts toward `verified` only under a
   * key pinned here. Keys the package carries in keys.json are checked too,
   * but they come from the same place as the signatures, so they can at most
   * give `signatures-pass`.
   */
  pinnedKeys?: Record<string, string>;
}

export interface PackageArtifactResult {
  artifact_id: string;
  payload_type?: string;
  /** `pass`: every signature verifies and the envelope matches the receipt's
   *  id and full digest. `skipped`: a kind signed over its own canonical
   *  bytes (a countersigned room participant) that only the CLI checks. */
  status: 'pass' | 'fail' | 'missing' | 'skipped';
  signers: { keyid: string; key: 'pinned' | 'package' | 'unknown' }[];
  detail?: string;
}

export interface VerifyPackageResult {
  /**
   * Same vocabulary as `treeship package verify`:
   * - `verified`: every envelope and the close record verify under keys you
   *   pinned, every artifact matches the receipt, and the receipt is the one
   *   the close record signed.
   * - `signatures-pass`: the same, but at least one signer is known only
   *   from the package's own keys.json.
   * - `structural-pass`: structure only. Either no envelopes were given
   *   (`scope: 'receipt-only'`), or the package holds artifact kinds whose
   *   rules this library doesn't evaluate (`scope: 'partial'`; run
   *   `treeship package verify` for those).
   * - `failed`: something checkable did not hold.
   */
  verdict: 'verified' | 'signatures-pass' | 'structural-pass' | 'failed';
  scope: 'receipt-only' | 'partial' | 'signatures';
  checks: VerifyCheck[];
  artifacts: PackageArtifactResult[];
  /** Payload kinds present whose semantics are not checked here. */
  unevaluated_kinds: string[];
}

// Kinds whose rules (single-use approvals, endorsement linkage, room
// invitations and countersigns) live in the Rust package verifier and are not
// re-implemented here. A package carrying any of them is capped at
// structural-pass: its signatures can all hold while the set breaks a rule
// (a single-use invitation redeemed twice, for example).
const UNEVALUATED_KINDS = new Set([
  'approval.v1',
  'endorsement.v1',
  'invitation.v1',
  'session-participant.v1',
  'session-liveness.v1',
]);
// Kinds this library evaluates fully: signature, id and digest binding.
const EVALUATED_KINDS = new Set(['action.v1', 'receipt.v1']);
// Kinds not signed as plain DSSE: a room participant carries the joiner's
// signature and the host's countersign over the participant's canonical
// bytes, and its id comes from the pending envelope. Only the CLI checks
// them; here they are skipped, which also caps the verdict.
const SIGNED_ELSEWHERE = new Set(['session-participant.v1']);

interface Envelope {
  payload: string;
  payloadType: string;
  signatures: { keyid: string; sig: string }[];
}

function kindOf(payloadType: string): string {
  return payloadType.replace(/^application\/vnd\.treeship\./, '').replace(/\+json$/, '');
}

function bytesOf(v: string | Uint8Array): Uint8Array {
  return typeof v === 'string' ? new TextEncoder().encode(v) : v;
}

function textOf(v: string | Uint8Array): string {
  return typeof v === 'string' ? v : new TextDecoder().decode(v);
}

async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const d = await crypto.subtle.digest('SHA-256', bytes as BufferSource);
  return Array.from(new Uint8Array(d), (b) => b.toString(16).padStart(2, '0')).join('');
}

function stripKeyPrefix(k: string): string {
  return k.startsWith('ed25519:') ? k.slice('ed25519:'.length) : k;
}

function parseEnvelope(raw: string): Envelope | null {
  try {
    const e = JSON.parse(raw);
    if (
      typeof e?.payload === 'string' &&
      typeof e?.payloadType === 'string' &&
      Array.isArray(e?.signatures) &&
      e.signatures.length > 0 &&
      e.signatures.every(
        (s: unknown) =>
          typeof (s as { keyid?: unknown })?.keyid === 'string' &&
          typeof (s as { sig?: unknown })?.sig === 'string',
      )
    ) {
      return e as Envelope;
    }
  } catch {
    // fall through
  }
  return null;
}

/**
 * Verify a `.treeship` package: every artifact envelope's Ed25519
 * signatures, each envelope's id and full digest against the receipt, and the
 * signed close record (record.json) against the exact bytes of receipt.json.
 * Signature math runs in core-wasm, the same code as the CLI.
 *
 * Given only receipt.json, the result is `structural-pass` with
 * `scope: 'receipt-only'`: no signature was checked.
 */
export async function verifyPackage(
  files: PackageFiles,
  opts: VerifyPackageOptions = {},
): Promise<VerifyPackageResult> {
  const wasm = await loadWasm();
  const checks: VerifyCheck[] = [];
  const artifacts: PackageArtifactResult[] = [];
  const unevaluated = new Set<string>();
  const done = (
    verdict: VerifyPackageResult['verdict'],
    scope: VerifyPackageResult['scope'],
  ): VerifyPackageResult => ({
    verdict,
    scope,
    checks,
    artifacts,
    unevaluated_kinds: [...unevaluated].sort(),
  });
  const failed = () => checks.some((c) => c.status === 'fail');

  // 1. receipt.json and its structure (Merkle root, inclusion proofs).
  const receiptRaw = files['receipt.json'];
  if (receiptRaw === undefined) {
    checks.push({ step: 'receipt.json', status: 'fail', detail: 'missing' });
    return done('failed', 'receipt-only');
  }
  let receipt: {
    session?: { id?: string };
    artifacts?: { artifact_id?: string; digest?: string; payload_type?: string }[];
  };
  try {
    receipt = JSON.parse(textOf(receiptRaw));
  } catch {
    checks.push({ step: 'receipt.json', status: 'fail', detail: 'not JSON' });
    return done('failed', 'receipt-only');
  }
  const structural = JSON.parse(wasm.verify_receipt(textOf(receiptRaw))) as VerifyReceiptResult;
  if (structural.outcome === 'fail' || structural.outcome === 'error') {
    checks.push({
      step: 'structure',
      status: 'fail',
      detail: structural.message ?? 'receipt structure does not verify',
    });
  } else {
    checks.push({ step: 'structure', status: 'pass', detail: 'Merkle root and inclusion proofs hold' });
  }

  // 2. Which envelopes were given. None at all is a receipt-only read (or a
  //    package from before 0.31.2): structure is all there is to check.
  const envelopePaths = Object.keys(files).filter((p) => /^artifacts\/[^/]+\.json$/.test(p));
  if (envelopePaths.length === 0 && files['record.json'] === undefined) {
    checks.push({
      step: 'signatures',
      status: 'warn',
      detail: 'no artifact envelopes given: structure only, no signature was checked',
    });
    return done(failed() ? 'failed' : 'structural-pass', 'receipt-only');
  }

  // 3. Keys: pinned by the caller, or carried by the package.
  const pinned = new Map<string, string>();
  for (const [kid, key] of Object.entries(opts.pinnedKeys ?? {})) pinned.set(kid, stripKeyPrefix(key));
  const packageKeys = new Map<string, string>();
  if (files['keys.json'] !== undefined) {
    try {
      const k = JSON.parse(textOf(files['keys.json'])) as { keys?: Record<string, string> };
      for (const [kid, key] of Object.entries(k.keys ?? {})) packageKeys.set(kid, stripKeyPrefix(key));
    } catch {
      checks.push({ step: 'keys.json', status: 'fail', detail: 'not JSON' });
    }
  }
  for (const [kid, key] of packageKeys) {
    if (pinned.has(kid) && pinned.get(kid) !== key) {
      checks.push({
        step: 'keys.json',
        status: 'fail',
        detail: `keys.json names a different key for ${kid} than the one you pinned`,
      });
    }
  }
  let allPinned = true;
  let anyPinned = false;
  // A signer is its key id AND the key that id resolved to, so a reused
  // key id under a different key is a different signer.
  const signerOf = (env: Envelope): string | null => {
    if (env.signatures.length !== 1) return null;
    const kid = env.signatures[0].keyid;
    const key = pinned.get(kid) ?? packageKeys.get(kid);
    return key ? `${kid}:${key}` : null;
  };
  type Stmt = Record<string, unknown> & {
    action?: string;
    meta?: Record<string, unknown>;
    subject?: { artifactId?: unknown };
  };
  const decode = (env: Envelope): Stmt | null => {
    try {
      const v = JSON.parse(textOf(base64urlDecode(env.payload)));
      return v && typeof v === 'object' ? (v as Stmt) : null;
    } catch {
      return null;
    }
  };
  // Verified artifacts of the kinds evaluated here, for the session rules,
  // and the signed statements of every verified envelope, for chain walks.
  const verifiedStmts = new Map<string, { env: Envelope; stmt: Stmt; kind: string }>();
  const chainStmts = new Map<string, Stmt>();

  // Verify one envelope: every signature must hold under a known key.
  const checkEnvelope = (env: Envelope) => {
    const trusted: Record<string, string> = {};
    const signers: PackageArtifactResult['signers'] = [];
    for (const s of env.signatures) {
      const key = pinned.get(s.keyid) ?? packageKeys.get(s.keyid);
      signers.push({
        keyid: s.keyid,
        key: pinned.has(s.keyid) ? 'pinned' : packageKeys.has(s.keyid) ? 'package' : 'unknown',
      });
      if (key) trusted[s.keyid] = key;
    }
    const r = JSON.parse(wasm.verify_envelope(JSON.stringify(env), JSON.stringify(trusted))) as {
      valid?: boolean;
      artifact_id?: string;
      digest?: string;
      verified_keys?: string[];
      error?: string | null;
    };
    const everySigner = new Set(r.verified_keys ?? []);
    const distinct = new Set(env.signatures.map((s) => s.keyid)).size === env.signatures.length;
    const ok =
      r.valid === true &&
      distinct &&
      (r.verified_keys ?? []).length === env.signatures.length &&
      signers.every((s) => s.key !== 'unknown' && everySigner.has(s.keyid));
    if (ok && signers.some((s) => s.key !== 'pinned')) allPinned = false;
    if (ok && signers.some((s) => s.key === 'pinned')) anyPinned = true;
    return { ok, signers, r };
  };

  // 4. Every artifact the receipt lists: present, signed, and the envelope
  //    that hashes to exactly the listed id and digest.
  const listed = receipt.artifacts ?? [];
  const seen = new Set<string>();
  for (const a of listed) {
    const id = a.artifact_id ?? '';
    if (!/^art_[0-9a-f]{32}$/.test(id)) {
      checks.push({ step: 'artifacts', status: 'fail', detail: `malformed artifact id ${JSON.stringify(id)}` });
      continue;
    }
    if (seen.has(id)) {
      checks.push({ step: 'artifacts', status: 'fail', detail: `${id} is listed more than once` });
      continue;
    }
    seen.add(id);
    const raw = files[`artifacts/${id}.json`];
    if (raw === undefined) {
      artifacts.push({ artifact_id: id, status: 'missing', signers: [], detail: 'envelope not in the package' });
      checks.push({ step: 'artifacts', status: 'fail', detail: `${id}: envelope missing from the package` });
      continue;
    }
    const env = parseEnvelope(textOf(raw));
    if (!env) {
      artifacts.push({ artifact_id: id, status: 'fail', signers: [], detail: 'not a DSSE envelope' });
      checks.push({ step: 'artifacts', status: 'fail', detail: `${id}: not a DSSE envelope` });
      continue;
    }
    const kind = kindOf(env.payloadType);
    if (!EVALUATED_KINDS.has(kind)) unevaluated.add(kind);
    if (SIGNED_ELSEWHERE.has(kind)) {
      artifacts.push({
        artifact_id: id,
        payload_type: env.payloadType,
        status: 'skipped',
        signers: env.signatures.map((s) => ({
          keyid: s.keyid,
          key: pinned.has(s.keyid) ? ('pinned' as const) : packageKeys.has(s.keyid) ? ('package' as const) : ('unknown' as const),
        })),
        detail: 'countersigned over canonical bytes; checked by `treeship package verify`',
      });
      continue;
    }
    const { ok, signers, r } = checkEnvelope(env);
    let detail: string | undefined;
    if (!ok) detail = r.error ?? 'a signature does not verify under a known key';
    else if (r.artifact_id !== id) detail = `envelope hashes to ${r.artifact_id}, not ${id}`;
    else if (r.digest !== a.digest) detail = `envelope digest ${r.digest} does not match the receipt's ${a.digest}`;
    artifacts.push({
      artifact_id: id,
      payload_type: env.payloadType,
      status: detail ? 'fail' : 'pass',
      signers,
      detail,
    });
    if (detail) checks.push({ step: 'artifacts', status: 'fail', detail: `${id}: ${detail}` });
    else {
      const stmt = decode(env);
      if (!stmt) checks.push({ step: 'artifacts', status: 'fail', detail: `${id}: payload is not a JSON statement` });
      else {
        chainStmts.set(id, stmt);
        if (EVALUATED_KINDS.has(kind)) verifiedStmts.set(id, { env, stmt, kind });
      }
    }
  }
  if (!failed() && listed.length > 0) {
    const passed = artifacts.filter((a) => a.status === 'pass').length;
    const skipped = artifacts.length - passed;
    checks.push({
      step: 'artifacts',
      status: 'pass',
      detail:
        `${passed} envelope(s) verify and match the receipt's ids and digests` +
        (skipped ? `; ${skipped} skipped (checked by the CLI only)` : ''),
    });
  }

  // 5. The session: exactly one chain-root session.start and exactly one
  //    session.close for this session, the close chained back to the start
  //    by signed parent ids, and both signed by the same signer. Every
  //    evaluated artifact's signed parent must be in the package.
  const sid = receipt.session?.id;
  const metaSid = (st: Stmt) => (st.meta && typeof st.meta === 'object' ? st.meta.session_id : undefined);
  const parentOf = (st: Stmt): string | null | undefined => {
    // Mirrors treeship_core::verify::signed_parent for the kinds evaluated
    // here: a present parentId decides (non-string = broken); a receipt.v1
    // names its subject; otherwise no parent (a chain root).
    if ('parentId' in st || 'parent_id' in st) {
      const v = st.parentId ?? st.parent_id;
      return typeof v === 'string' ? v : undefined;
    }
    const subj = st.subject?.artifactId;
    if (typeof subj === 'string' && subj.startsWith('art_')) return subj;
    return null;
  };
  let closeId: string | null = null;
  let closeSigner: string | null = null;
  let closeStmt: Stmt | null = null;
  if (verifiedStmts.size > 0) {
    const starts = [...verifiedStmts].filter(([, v]) => v.stmt.action === 'session.start' && metaSid(v.stmt) === sid);
    const closes = [...verifiedStmts].filter(([, v]) => v.stmt.action === 'session.close' && metaSid(v.stmt) === sid);
    if (starts.length !== 1 || parentOf(starts[0][1].stmt) !== null) {
      checks.push({ step: 'session', status: 'fail', detail: `expected one chain-root session.start for ${sid}, found ${starts.length}` });
    } else if (closes.length !== 1) {
      checks.push({ step: 'session', status: 'fail', detail: `expected one session.close for ${sid}, found ${closes.length}` });
    } else {
      const [startId, start] = starts[0];
      const [cId, close] = closes[0];
      const startSigner = signerOf(start.env);
      const cSigner = signerOf(close.env);
      // Walk the close back to the start through signed parents.
      let cur: string | null | undefined = cId;
      const visited = new Set<string>();
      while (cur && cur !== startId && !visited.has(cur)) {
        visited.add(cur);
        const st = chainStmts.get(cur);
        cur = st ? parentOf(st) : undefined;
      }
      if (cur !== startId) {
        checks.push({ step: 'session', status: 'fail', detail: `session.close ${cId} does not chain back to session.start ${startId}` });
      } else if (!startSigner || startSigner !== cSigner) {
        checks.push({ step: 'session', status: 'fail', detail: 'session.close is not signed by the signer of session.start' });
      } else {
        closeId = cId;
        closeSigner = cSigner;
        closeStmt = close.stmt;
      }
    }
    for (const [id, v] of verifiedStmts) {
      const par = parentOf(v.stmt);
      if (par === undefined || (par !== null && !seen.has(par))) {
        checks.push({ step: 'linkage', status: 'fail', detail: `${id}: signed parent ${String(par)} is not in the package` });
      } else if (par === null && !(v.stmt.action === 'session.start' && metaSid(v.stmt) === sid)) {
        checks.push({ step: 'linkage', status: 'fail', detail: `${id}: signs no parent but is not this session's session.start` });
      }
    }
  } else if (envelopePaths.length > 0 || files['record.json'] !== undefined) {
    checks.push({ step: 'session', status: 'fail', detail: 'no verified session artifacts to bind the close record to' });
  }

  // 6. The close record: signed, names this session, and binds the exact
  //    bytes of receipt.json. Without it, nothing binds the receipt body
  //    (timeline, narrative, side effects) to a signature.
  const recordRaw = files['record.json'];
  if (recordRaw === undefined) {
    checks.push({
      step: 'receipt_binding',
      status: 'fail',
      detail: 'record.json (the signed close record) is missing, so nothing binds receipt.json',
    });
  } else {
    const env = parseEnvelope(textOf(recordRaw));
    if (!env) {
      checks.push({ step: 'receipt_binding', status: 'fail', detail: 'record.json is not a DSSE envelope' });
    } else {
      // The record may be signed by the close's signer, or by the record key
      // the close names in its own signed statement, at meta.record_key, in
      // the CLI's encoding (ed25519:<base64url>). A record under that key is
      // checked against the key the close vouches for, never keys.json, and
      // is as trusted as the close's signer, so it adds no signer of its own.
      const rk = closeStmt?.meta?.record_key as
        | { key_id?: unknown; public_key?: unknown }
        | undefined;
      const rkKey =
        rk && typeof rk.key_id === 'string' && typeof rk.public_key === 'string' &&
        /^ed25519:[A-Za-z0-9_-]{43}$/.test(rk.public_key)
          ? { kid: rk.key_id, key: rk.public_key.slice('ed25519:'.length) }
          : null;
      const byRecordKey =
        rkKey !== null && env.signatures.length === 1 && env.signatures[0].keyid === rkKey.kid;
      let ok: boolean;
      if (byRecordKey) {
        const conflict =
          (pinned.has(rkKey!.kid) && pinned.get(rkKey!.kid) !== rkKey!.key) ||
          (packageKeys.has(rkKey!.kid) && packageKeys.get(rkKey!.kid) !== rkKey!.key);
        const r = JSON.parse(
          wasm.verify_envelope(JSON.stringify(env), JSON.stringify({ [rkKey!.kid]: rkKey!.key })),
        ) as { valid?: boolean; verified_keys?: string[] };
        ok = !conflict && r.valid === true && (r.verified_keys ?? []).length === 1;
      } else {
        ok = checkEnvelope(env).ok;
      }
      const stmt = (decode(env) ?? {}) as Stmt & {
        type?: unknown;
        kind?: unknown;
        payload?: { receipt_digest?: string; session_id?: string };
      };
      const actual = `sha256:${await sha256Hex(bytesOf(receiptRaw))}`;
      const recSigner = byRecordKey ? 'record_key' : signerOf(env);
      if (!ok) {
        checks.push({ step: 'receipt_binding', status: 'fail', detail: 'the close record signature does not verify under a known key' });
      } else if (
        env.payloadType !== 'application/vnd.treeship.receipt.v1+json' ||
        stmt.type !== 'treeship/receipt/v1' ||
        stmt.kind !== 'session.v1' ||
        typeof stmt.payload?.receipt_digest !== 'string' ||
        typeof stmt.payload?.session_id !== 'string'
      ) {
        checks.push({ step: 'receipt_binding', status: 'fail', detail: 'record.json is not a session.v1 close record' });
      } else if (!closeId || stmt.subject?.artifactId !== closeId) {
        checks.push({ step: 'receipt_binding', status: 'fail', detail: "the close record does not seal this session's close" });
      } else if (!recSigner || (recSigner !== closeSigner && !byRecordKey)) {
        checks.push({ step: 'receipt_binding', status: 'fail', detail: "the close record is not signed by the session's signer" });
      } else if (stmt.payload?.session_id !== receipt.session?.id) {
        checks.push({
          step: 'receipt_binding',
          status: 'fail',
          detail: `the close record names session ${stmt.payload?.session_id} but this receipt is ${receipt.session?.id}`,
        });
      } else if (stmt.payload?.receipt_digest !== actual) {
        checks.push({
          step: 'receipt_binding',
          status: 'fail',
          detail: `the close record signed receipt digest ${stmt.payload?.receipt_digest} but receipt.json digests to ${actual}`,
        });
      } else {
        checks.push({ step: 'receipt_binding', status: 'pass', detail: `the close record binds receipt.json (${actual})` });
      }
    }
  }

  // Some signers pinned and others only package-known: a pin covers part
  // of the package, so the package as a whole is not what was pinned.
  if (anyPinned && !allPinned) {
    checks.push({ step: 'keys', status: 'fail', detail: 'some signers are pinned and others are known only from keys.json' });
  }

  if (failed()) return done('failed', 'signatures');
  // Approval evidence travels beside the sealed set: use records and grants
  // carried in approvals/ (an approval minted before the session is there,
  // not sealed). Their rules live in the Rust verifier, so their presence
  // caps the verdict like a sealed approval does.
  if (Object.keys(files).some((k) => k.startsWith('approvals/'))) {
    unevaluated.add('approvals/ (use records and carried grants)');
  }
  if (unevaluated.size > 0) {
    checks.push({
      step: 'semantics',
      status: 'warn',
      detail: `not evaluated here: ${[...unevaluated].sort().join(', ')}. Run \`treeship package verify\` for their rules.`,
    });
    return done('structural-pass', 'partial');
  }
  return done(allPinned ? 'verified' : 'signatures-pass', 'signatures');
}

function base64urlDecode(s: string): Uint8Array {
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/');
  const bin = atob(b64 + '='.repeat((4 - (b64.length % 4)) % 4));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}
