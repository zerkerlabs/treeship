import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import type { AttestParams, AttestReceiptParams } from './types.js';

const exec = promisify(execFile);

/**
 * A signing failure is never silent. The CLI's own stderr (no active
 * session, no workspace, bad input) is the useful part, so it is printed
 * verbatim; with TREESHIP_STRICT=1 the failure is rethrown so a caller can
 * refuse to proceed without a receipt (audit 2026-09, AUD-33).
 */
function reportFailure(what: string, err: unknown): void {
  const e = err as { stderr?: string; message?: string } | undefined;
  const detail = (e?.stderr ?? e?.message ?? String(err)).toString().trim().split('\n')[0];
  process.stderr.write(`[treeship] ${what} failed: ${detail}\n`);
  if (process.env.TREESHIP_STRICT === '1') {
    throw err instanceof Error ? err : new Error(`${what} failed: ${detail}`);
  }
}

/**
 * Emit a structured session event so tool calls appear in the receipt
 * timeline. This bridges the gap between signed artifacts (which are
 * Merkle-proven) and the session event log (which populates the
 * receipt's timeline, agent graph, and side effects).
 *
 * Best-effort by default: returns after printing the CLI's error to stderr.
 * With TREESHIP_STRICT=1 the error is thrown instead.
 */
export async function emitSessionEvent(params: {
  type: string;
  tool?: string;
  actor: string;
  agentName?: string;
  durationMs?: number;
  exitCode?: number;
  artifactId?: string;
  meta?: Record<string, unknown>;
}): Promise<void> {
  const args = [
    'session', 'event',
    '--type', params.type,
  ];

  if (params.tool) args.push('--tool', params.tool);
  if (params.actor) args.push('--actor', params.actor);
  if (params.agentName) args.push('--agent-name', params.agentName);
  if (params.durationMs != null) args.push('--duration-ms', String(params.durationMs));
  if (params.exitCode != null) args.push('--exit-code', String(params.exitCode));
  if (params.artifactId) args.push('--artifact-id', params.artifactId);

  if (params.meta && Object.keys(params.meta).length > 0) {
    const clean: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(params.meta)) {
      if (v !== undefined && v !== null) clean[k] = v;
    }
    if (Object.keys(clean).length > 0) {
      args.push('--meta', JSON.stringify(clean));
    }
  }

  try {
    await exec('treeship', args, { timeout: 3000 });
  } catch (e) {
    reportFailure(`session event ${params.type}`, e);
  }
}

export async function attestAction(params: AttestParams): Promise<string | undefined> {
  const args = [
    'attest', 'action',
    '--actor', params.actor,
    '--action', params.action,
    '--format', 'json',
  ];

  if (params.parentId) {
    args.push('--parent', params.parentId);
  }

  if (params.approvalNonce) {
    args.push('--approval-nonce', params.approvalNonce);
  }

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
  } catch (e) {
    reportFailure(`attestAction ${params.action}`, e);
    return undefined;
  }
}

export async function attestReceipt(params: AttestReceiptParams): Promise<string | undefined> {
  const args = [
    'attest', 'receipt',
    '--system', params.system,
    '--kind', params.kind,
    '--format', 'json',
  ];

  if (params.subject) {
    args.push('--subject', params.subject);
  }

  if (params.payload && Object.keys(params.payload).length > 0) {
    args.push('--payload', JSON.stringify(params.payload));
  }

  try {
    const { stdout } = await exec('treeship', args, { timeout: 5000 });
    const result = JSON.parse(stdout);
    return result.id || result.artifact_id;
  } catch (e) {
    reportFailure(`attestReceipt ${params.kind}`, e);
    return undefined;
  }
}
