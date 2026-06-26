import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import type { AttestActionParams, AttestReceiptParams } from './types.js';

const exec = promisify(execFile);

/** One-time guard so a missing CLI prints exactly one actionable warning per process. */
let cliMissingWarned = false;

function isCliMissing(err: unknown): boolean {
  if (!err || typeof err !== 'object') return false;
  const e = err as { code?: string; errno?: number; path?: string };
  // execFile reports ENOENT when the binary is not found on PATH.
  return e.code === 'ENOENT' && (e.path === 'treeship' || !e.path);
}

function warnOnce(context: string, err: unknown): void {
  if (isCliMissing(err)) {
    if (!cliMissingWarned) {
      cliMissingWarned = true;
      process.stderr.write(
        '[treeship/a2a] treeship CLI not found on PATH. ' +
          'A2A attestation is disabled until you install it:\n' +
          '  curl -fsSL treeship.dev/install | sh   # recommended\n' +
          '  npm install -g treeship                # alternative\n' +
          '  treeship init\n' +
          'Set TREESHIP_DISABLE=1 to silence this warning if running without attestation is intentional.\n',
      );
    }
    return;
  }
  if (process.env.TREESHIP_DEBUG === '1') {
    const msg = err instanceof Error ? err.message : String(err);
    process.stderr.write(`[treeship/a2a] ${context} failed: ${msg}\n`);
  }
}

/**
 * Provision a per-agent signing key for this middleware's actor, so the
 * receipts it already emits become key-bound and the actor verifies as
 * `proven (key-bound)` instead of `asserted`. The `attest action --actor`
 * calls below already pass the actor; per-actor signing (shipped) signs with
 * the agent's own key the moment that key exists, so this is provisioning,
 * not rewiring.
 *
 * Idempotent and best-effort, mirrors the MCP bridge: `--own-key` reuses an
 * existing per-agent key (no pile-up across restarts), `--quiet` writes no
 * on-disk `.agent` package, and any failure (CLI missing, no `treeship init`)
 * is swallowed so attestation never breaks the agent path -- receipts just
 * fall back to the shared key until the key exists.
 */
export async function provisionAgentKey(actor: string): Promise<void> {
  if (process.env.TREESHIP_DISABLE === '1') return;
  const name = actor.replace(/^agent:\/\//, '');
  if (!name) return;
  try {
    await exec('treeship', ['agent', 'register', '--own-key', '--quiet', '--name', name], {
      timeout: 5000,
    });
  } catch (err) {
    warnOnce(`provisionAgentKey(${actor})`, err);
  }
}

/**
 * Invoke `treeship attest action` and return the resulting artifact ID.
 * Failures are swallowed. Treeship attestation must never break the agent path.
 */
export async function attestAction(params: AttestActionParams): Promise<string | undefined> {
  if (process.env.TREESHIP_DISABLE === '1') return undefined;

  const args = ['attest', 'action', '--actor', params.actor, '--action', params.action, '--format', 'json'];

  if (params.parentId) args.push('--parent', params.parentId);
  if (params.approvalNonce) args.push('--approval-nonce', params.approvalNonce);

  const cleanMeta: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(params.meta ?? {})) {
    if (v !== undefined && v !== null) cleanMeta[k] = v;
  }
  if (Object.keys(cleanMeta).length > 0) {
    args.push('--meta', JSON.stringify(cleanMeta));
  }

  try {
    const { stdout } = await exec('treeship', args, { timeout: 5000 });
    const result = JSON.parse(stdout);
    return result.id || result.artifact_id;
  } catch (err) {
    warnOnce(`attestAction(${params.action})`, err);
    return undefined;
  }
}

/** Invoke `treeship attest receipt` and return the resulting artifact ID. */
export async function attestReceipt(params: AttestReceiptParams): Promise<string | undefined> {
  if (process.env.TREESHIP_DISABLE === '1') return undefined;

  const args = ['attest', 'receipt', '--system', params.system, '--kind', params.kind, '--format', 'json'];

  if (params.subject) args.push('--subject', params.subject);
  if (params.payload && Object.keys(params.payload).length > 0) {
    args.push('--payload', JSON.stringify(params.payload));
  }

  try {
    const { stdout } = await exec('treeship', args, { timeout: 5000 });
    const result = JSON.parse(stdout);
    return result.id || result.artifact_id;
  } catch (err) {
    warnOnce(`attestReceipt(${params.kind})`, err);
    return undefined;
  }
}

/**
 * Invoke `treeship attest handoff` to record an A2A delegation boundary.
 * The CLI returns a JSON object containing the artifact ID.
 */
export async function attestHandoff(opts: {
  from: string;
  to: string;
  taskId: string;
  context?: string;
  messageId?: string;
}): Promise<string | undefined> {
  if (process.env.TREESHIP_DISABLE === '1') return undefined;

  const args = [
    'attest',
    'handoff',
    '--from',
    opts.from,
    '--to',
    opts.to,
    '--task-id',
    opts.taskId,
    '--format',
    'json',
  ];
  if (opts.context) args.push('--context', opts.context);
  if (opts.messageId) args.push('--a2a-message-id', opts.messageId);

  try {
    const { stdout } = await exec('treeship', args, { timeout: 5000 });
    const result = JSON.parse(stdout);
    return result.id || result.artifact_id;
  } catch (err) {
    warnOnce(`attestHandoff(${opts.from} -> ${opts.to})`, err);
    return undefined;
  }
}

/**
 * Read the current Treeship session ID from the environment, if any.
 * Set by `treeship session start` so wrapped commands inherit it.
 */
export function currentSessionId(): string | undefined {
  return process.env.TREESHIP_SESSION_ID || undefined;
}

/** Test-only: reset the one-time warning latch. */
export function __resetCliMissingWarning(): void {
  cliMissingWarned = false;
}
