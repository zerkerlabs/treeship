import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { receiptApiUrl } from '../src/index.js';

// The same vectors the CLI runs (packages/cli/src/commands/verify_external.rs).
// Two implementations of one rule drift silently; the file is the rule.
const here = dirname(fileURLToPath(import.meta.url));
const vectors = JSON.parse(
  readFileSync(join(here, '..', '..', '..', 'tests', 'vectors', 'receipt-urls.json'), 'utf8'),
) as { cases: { name: string; input: string; expect: string | null }[] };

describe('receiptApiUrl (shared vectors)', () => {
  it('has the vectors', () => {
    expect(vectors.cases.length).toBeGreaterThanOrEqual(15);
  });

  for (const c of vectors.cases) {
    it(c.name, () => {
      if (c.expect === null) {
        expect(() => receiptApiUrl(c.input)).toThrow(/not a receipt URL/);
      } else {
        expect(receiptApiUrl(c.input)).toBe(c.expect);
      }
    });
  }

  it('the documented API form is fetched as given, not as /v1/v1/', () => {
    expect(receiptApiUrl('https://api.treeship.dev/v1/receipt/ssn_x')).toBe(
      'https://api.treeship.dev/v1/receipt/ssn_x',
    );
  });
});
