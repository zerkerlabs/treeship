import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import type { AttestParams, AttestReceiptParams } from './types.js';

const exec = promisify(execFile);

/**
 * Emit a structured session event so tool calls appear in the receipt
 * timeline. This bridges the gap between signed artifacts (which are
 * Merkle-proven) and the session event log (which populates the
 * receipt's timeline, agent graph, and side effects).
 *
 * Best-effort: never throws. If no session is active, the CLI prints
 * an error and we silently ignore it.
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
  } catch {
    // Best-effort: no active session or CLI not installed.
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
  } catch {
    if (process.env.TREESHIP_DEBUG === '1') {
      process.stderr.write(`[treeship] attestAction failed: ${params.action}\n`);
    }
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
    if (process.env.TREESHIP_DEBUG === '1') {
      process.stderr.write(`[treeship] attestReceipt failed: ${params.kind}\n`);
    }
    return undefined;
  }
}
