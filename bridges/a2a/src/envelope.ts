import { isAbsolute, normalize, relative, resolve, sep } from 'node:path';
import type { GateRefusal } from './gate.js';

/**
 * The `treeship.a2a/v1` file envelope.
 *
 * Grok Bot has no documented RPC, so the transport is a JSON file plus a
 * pointer. That makes every field here attacker-controlled: the sender writes
 * the document, and the receiver acts on it before any identity has been
 * established. Validation is therefore fail-closed on shape AND on paths.
 *
 * This is the shared implementation the spec calls `integrations/a2a-host/
 * envelope.ts`. It lives beside the gate so both are covered by one test suite
 * and there is exactly one parser; hosts import it rather than re-implementing.
 */

export const A2A_SPEC = 'treeship.a2a/v1';

export type EnvelopeKind = 'offer' | 'challenge' | 'present' | 'accept' | 'refuse' | 'handoff';

const KINDS: readonly EnvelopeKind[] = [
  'offer',
  'challenge',
  'present',
  'accept',
  'refuse',
  'handoff',
];

/** Kept in lockstep with `GateRefusal`; the compile-time check below fails if
 * the two ever drift, because a `refuse` envelope carrying a reason no host
 * handles is a silent dead end. */
const REFUSALS = [
  'no_presentation',
  'no_challenge',
  'challenge_failed',
  'untrusted_issuer',
  'revoked',
  'stale',
  'verification_failed',
  'gate_unavailable',
] as const;
type RefusalLiteral = (typeof REFUSALS)[number];
// If GateRefusal gains or loses a member, one of these two lines stops compiling.
const _refusalsCoverGate: RefusalLiteral extends GateRefusal ? true : never = true;
const _gateCoversRefusals: GateRefusal extends RefusalLiteral ? true : never = true;
void _refusalsCoverGate;
void _gateCoversRefusals;

export interface Envelope {
  spec: string;
  kind: EnvelopeKind;
  id: string;
  from: string;
  to: string;
  created_at: string;
  reply_to: string | null;
  body: Record<string, unknown>;
}

export type ParseResult =
  | { ok: true; envelope: Envelope }
  | { ok: false; error: string };

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function isNonEmptyString(v: unknown): v is string {
  return typeof v === 'string' && v.trim().length > 0;
}

/**
 * Parse and validate one envelope document.
 *
 * An unknown `spec` is refused rather than assumed to be v1: accepting a
 * document whose version we do not understand is how a future field with
 * security meaning gets silently ignored.
 */
export function parseEnvelope(text: string): ParseResult {
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch (e) {
    return { ok: false, error: `not JSON: ${(e as Error).message}` };
  }
  if (!isObject(raw)) return { ok: false, error: 'envelope must be a JSON object' };

  if (raw.spec !== A2A_SPEC) {
    return { ok: false, error: `unknown spec ${JSON.stringify(raw.spec)}; expected ${A2A_SPEC}` };
  }
  if (!KINDS.includes(raw.kind as EnvelopeKind)) {
    return { ok: false, error: `unknown kind ${JSON.stringify(raw.kind)}` };
  }
  for (const field of ['id', 'from', 'to', 'created_at'] as const) {
    if (!isNonEmptyString(raw[field])) return { ok: false, error: `${field} must be a non-empty string` };
  }
  if (raw.reply_to !== null && !isNonEmptyString(raw.reply_to)) {
    return { ok: false, error: 'reply_to must be a string or null' };
  }
  if (!isObject(raw.body)) return { ok: false, error: 'body must be an object' };

  if (raw.kind === 'refuse') {
    const refusal = (raw.body as Record<string, unknown>).refusal;
    if (!REFUSALS.includes(refusal as RefusalLiteral)) {
      return { ok: false, error: `refuse.body.refusal ${JSON.stringify(refusal)} is not a known refusal` };
    }
  }
  if (raw.kind === 'challenge') {
    const nonce = (raw.body as Record<string, unknown>).nonce;
    // A receiver never accepts a nonce the sender chose, but a malformed one
    // from our own side is worth catching before it reaches the verifier.
    if (!isNonEmptyString(nonce) || nonce.length < 32) {
      return { ok: false, error: 'challenge.body.nonce must be at least 32 characters' };
    }
  }

  if (/-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(text)) {
    return { ok: false, error: 'envelope contains a private key; envelopes carry no secrets' };
  }

  return { ok: true, envelope: raw as unknown as Envelope };
}

/**
 * Resolve a path the OTHER agent supplied, confined to a directory we chose.
 *
 * The sender names `presentation_path`, and the receiver hands that string to
 * `verify-presentation`. Without confinement that is an arbitrary-file read
 * driven by a party who has not yet proven anything: `../../../.treeship` to
 * probe our own store, or an absolute path to a presentation we minted
 * ourselves. Absolute paths and any traversal that escapes the base are
 * refused; the caller gets null and must treat it as `no_presentation`.
 */
export function resolveSenderPath(baseDir: string, candidate: string): string | null {
  if (!isNonEmptyString(candidate)) return null;
  if (candidate.includes('\0')) return null;
  if (isAbsolute(candidate)) return null;
  const base = resolve(baseDir);
  const target = resolve(base, normalize(candidate));
  const rel = relative(base, target);
  if (rel === '' || rel.startsWith('..') || isAbsolute(rel)) return null;
  if (rel.split(sep).includes('..')) return null;
  return target;
}
