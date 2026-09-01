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

/** The shape `verify-presentation --format json` returns. Fields are optional
 * because a partial document must not be read as a pass. */
type VerifyOutput = {
  ok?: boolean;
  key_bound?: boolean;
  challenge_ok?: boolean;
  challenge_checked?: boolean;
  signature?: string;
  revocation?: string;
  staple?: { stale?: boolean; verified?: boolean };
  verdict?: string;
};

/** Pull the JSON document out of output that may also carry warning lines. */
export function parseVerifyOutput(text: string): VerifyOutput | null {
  const start = text.indexOf('{');
  const end = text.lastIndexOf('}');
  if (start === -1 || end <= start) return null;
  try {
    const parsed = JSON.parse(text.slice(start, end + 1)) as unknown;
    return parsed && typeof parsed === 'object' ? (parsed as VerifyOutput) : null;
  } catch {
    return null;
  }
}

/**
 * Classify from the verifier's structured fields, in root-cause order.
 *
 * The verdict STRING is not enough. An unpinned issuer and a replayed nonce
 * both print `CHALLENGE FAILED`, because a card that never verified key-bound
 * has no established key to check a response against -- the challenge failure
 * is a consequence, not the cause. Telling a sender its challenge failed when
 * we simply never pinned its issuer sends it to fix the wrong thing, so trust
 * failures are classified before challenge failures.
 *
 * See test/fixtures/ for the real outputs these rules were derived from.
 */
function classifyStructured(out: VerifyOutput): GateRefusal {
  const signature = (out.signature ?? '').toLowerCase();
  if (out.key_bound === false || signature.includes('unverified') || signature.includes('not in your trust roots')) {
    return 'untrusted_issuer';
  }
  const revocation = (out.revocation ?? '').toLowerCase();
  if (revocation.includes('revoked') && !revocation.includes('none included')) return 'revoked';
  if (out.staple?.stale === true) return 'stale';
  if (out.challenge_ok === false) return 'challenge_failed';
  return 'verification_failed';
}

/**
 * Map the verifier's output to a refusal the other agent can act on.
 *
 * Prefers the structured document; falls back to substrings only when the
 * output is not JSON. Unrecognized output is `verification_failed`, never a
 * pass: an unmapped complaint is still a complaint.
 */
export function classifyRefusal(text: string): GateRefusal {
  const structured = parseVerifyOutput(text);
  if (structured) return classifyStructured(structured);

  const t = text.toLowerCase();
  if (t.includes('untrusted issuer') || t.includes('not trusted') || t.includes('no pinned'))
    return 'untrusted_issuer';
  if (t.includes('revoked')) return 'revoked';
  if (t.includes('stale')) return 'stale';
  if (t.includes('challenge failed') || t.includes('challenge_failed')) return 'challenge_failed';
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
    // The CLI emits `nonce` (128 bits, 32 hex chars). It is NOT `challenge`;
    // see test/fixtures/mint-challenge.json for the real document.
    const parsed = JSON.parse(stdout) as { nonce?: string };
    const nonce = parsed.nonce;
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
    // Exit 0 is necessary, not sufficient. A verifier that returns Ok for the
    // wrong reason is worse than one that crashes, so the document has to
    // agree with the exit code before foreign work runs.
    const out = parseVerifyOutput(stdout);
    if (out && out.ok !== true) {
      return refuse(classifyStructured(out), out.verdict ?? stdout.trim());
    }
    return { allowed: true, verdict: (out?.verdict ?? stdout).trim() };
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
