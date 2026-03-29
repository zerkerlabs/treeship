import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
const exec = promisify(execFile);
export async function attestAction(params) {
    const args = [
        'attest', 'action',
        '--actor', params.actor,
        '--action', params.action,
        '--format', 'json',
    ];
    if (params.parentId) {
        args.push('--parent', params.parentId);
    }
    const cleanMeta = {};
    for (const [k, v] of Object.entries(params.meta ?? {})) {
        if (v !== undefined && v !== null)
            cleanMeta[k] = v;
    }
    if (Object.keys(cleanMeta).length > 0) {
        args.push('--meta', JSON.stringify(cleanMeta));
    }
    try {
        const { stdout } = await exec('treeship', args, { timeout: 5000 });
        const result = JSON.parse(stdout);
        return result.id || result.artifact_id;
    }
    catch {
        if (process.env.TREESHIP_DEBUG === '1') {
            process.stderr.write(`[treeship] attestAction failed: ${params.action}\n`);
        }
        return undefined;
    }
}
