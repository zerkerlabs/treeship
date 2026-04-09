import { createHash } from 'node:crypto';

/** Returns `sha256:<hex>` for arbitrary string content. */
export function hashPayload(content: string): string {
  return 'sha256:' + createHash('sha256').update(content).digest('hex');
}

/** Stable JSON stringify for digest computation. Preserves object key order. */
export function stableStringify(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) {
    return '[' + value.map(stableStringify).join(',') + ']';
  }
  const keys = Object.keys(value as Record<string, unknown>).sort();
  return (
    '{' +
    keys
      .map(
        (k) => JSON.stringify(k) + ':' + stableStringify((value as Record<string, unknown>)[k]),
      )
      .join(',') +
    '}'
  );
}
