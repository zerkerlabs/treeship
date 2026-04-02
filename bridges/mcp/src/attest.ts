import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import type { AttestParams, AttestReceiptParams } from './types.js';

const exec = promisify(execFile);

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
