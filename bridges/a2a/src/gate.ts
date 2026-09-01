import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const exec = promisify(execFile);

/**
 * The inbound gate: refuse foreign work until the caller proves live control
 * of a key this ship's trust roots already accept.
 *
 * This module deliberately inverts the rule the attestation path follows.
 * Attestation must never break the agent path, because failing to *record*
 * work is not a reason to refuse work. The gate exists to break the path. A
 * gate that cannot run is a gate that refuses -- "the check did not run" and
 * "the check passed" must never look the same to the caller.
 *
 * No new cryptography lives here. This wires `session mint-challenge` and
 * `verify-presentation --challenge`, which already ship, into a decision the
 * bridge makes *before* the task executes.
 */

/** Why the gate refused, in terms the calling agent can branch on. */
export type GateRefusal =
  | 'no_presentation'
  | 'no_challenge'
  | 'challenge_failed'
  | 'untrusted_issuer'
  | 'revoked'
  | 'stale'
  | 'verification_failed'
  | 'gate_unavailable';

export type GateResult =
  | { allowed: true; unverified?: false; verdict: string }
  /** The explicit opt-out fired. `reason` names what would have refused. */
  | { allowed: true; unverified: true; reason: string }
  | { allowed: false; refusal: GateRefusal; message: string };

/** Alias so consumers can type an `admitTask` result without importing gate internals. */
export type GateResultLike = GateResult;

export type GateInboundOptions = {
  /** Path to the counterparty's presentation file. */
  presentationPath?: string;
  /** The nonce THIS ship minted. Never one the caller supplied. */
  challenge?: string;
  /** Passed through to the verifier, e.g. '1h'. */
  maxStapleAge?: string;
  timeoutMs?: number;
};

/**
 * The CLI's own floor: `answer-challenge` and `countersign` refuse a nonce
 * shorter than 32 characters, because a guessable nonce can be pre-signed and
 * the liveness proof then shows only that a document exists.
 */
const MIN_NONCE_LENGTH = 32;

function errText(err: unknown): string {
  if (!err || typeof err !== 'object') return String(err ?? '');
  const e = err as { stderr?: string; stdout?: string; message?: string };
  return [e.stderr, e.stdout, e.message].filter(Boolean).join(' ').trim();
}

function isCliMissing(err: unknown): boolean {
  if (!err || typeof err !== 'object') return false;
  const e = err as { code?: string; path?: string };
  return e.code === 'ENOENT' && (e.path === 'treeship' || !e.path);
}

/**
 * Map the verifier's output to a refusal the other agent can act on.
 *
 * Unrecognized output is `verification_failed`, never a pass: an unmapped
 * complaint is still a complaint.
 */
export function classifyRefusal(text: string): GateRefusal {
  const t = text.toLowerCase();
  if (t.includes('challenge failed') || t.includes('challenge_failed')) return 'challenge_failed';
  if (t.includes('stale')) return 'stale';
  if (t.includes('untrusted issuer') || t.includes('not trusted') || t.includes('no pinned'))
    return 'untrusted_issuer';
  if (t.includes('revoked')) return 'revoked';
  return 'verification_failed';
}

/** True only for the exact opt-out value, so a stray `0` is not opt-in. */
function optedOutOfVerification(): boolean {
  const v = process.env.TREESHIP_A2A_UNVERIFIED;
  return v === '1' || v?.toLowerCase() === 'true';
}

/**
 * Mint a challenge nonce for one inbound task.
 *
 * Returns null rather than a fallback when the CLI cannot mint one. The gate
 * treats a null nonce as a refusal; inventing a nonce here would produce a
 * liveness check whose freshness this process guessed at.
 */
export async function mintChallenge(timeoutMs = 5000): Promise<string | null> {
  try {
    const { stdout } = await exec(
      'treeship',
      ['session', 'mint-challenge', '--format', 'json'],
      { timeout: timeoutMs },
    );
    const parsed = JSON.parse(stdout) as { challenge?: string };
    const nonce = parsed.challenge;
    if (typeof nonce !== 'string' || nonce.length < MIN_NONCE_LENGTH) return null;
    return nonce;
  } catch {
    return null;
  }
}

/**
 * Decide whether to execute inbound foreign work.
 *
 * Call this BEFORE running the task. On `allowed: false` the bridge must not
 * execute; return the refusal to the caller so the sending agent learns what
 * to fix. On `allowed: true` with `unverified: true`, execute but record that
 * the gate was skipped -- a silent skip is a bug.
 */
export async function gateInbound(opts: GateInboundOptions): Promise<GateResult> {
  const refuse = (refusal: GateRefusal, message: string): GateResult => {
    if (optedOutOfVerification()) {
      return { allowed: true, unverified: true, reason: `${refusal}: ${message}` };
    }
    return { allowed: false, refusal, message };
  };

  if (!opts.presentationPath) {
    return refuse('no_presentation', 'inbound work carried no presentation to verify');
  }
  if (!opts.challenge || opts.challenge.length < MIN_NONCE_LENGTH) {
    return refuse(
      'no_challenge',
      `no live challenge for this task (nonce must be >= ${MIN_NONCE_LENGTH} chars)`,
    );
  }

  const args = [
    'verify-presentation',
    opts.presentationPath,
    '--challenge',
    opts.challenge,
    '--format',
    'json',
  ];
  if (opts.maxStapleAge) args.push('--max-staple-age', opts.maxStapleAge);

  try {
    const { stdout } = await exec('treeship', args, { timeout: opts.timeoutMs ?? 10000 });
    return { allowed: true, verdict: stdout.trim() };
  } catch (err) {
    if (isCliMissing(err)) {
      return refuse(
        'gate_unavailable',
        'treeship CLI not found on PATH; refusing foreign work because the gate could not run. ' +
          'Install it (curl -fsSL treeship.dev/install | sh) or set TREESHIP_A2A_UNVERIFIED=1 to accept unverified work.',
      );
    }
    const text = errText(err);
    return refuse(classifyRefusal(text), text || 'presentation verification failed');
  }
}
