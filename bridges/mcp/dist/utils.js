import { createHash } from 'node:crypto';
export function hashPayload(content) {
    return 'sha256:' + createHash('sha256').update(content).digest('hex');
}
