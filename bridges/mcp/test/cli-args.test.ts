import { describe, expect, it } from 'vitest';
import { sessionReportCommands, verifyArgs } from '../src/cli-args.js';

describe('CLI argument contracts', () => {
  it('uses default chain verification and opts out explicitly', () => {
    expect(verifyArgs('art_test')).toEqual(['verify', 'art_test']);
    expect(verifyArgs('art_test', true)).toEqual(['verify', 'art_test']);
    expect(verifyArgs('art_test', false)).toEqual(['verify', 'art_test', '--no-chain']);
  });

  it('moves summaries to session close before publishing the report', () => {
    expect(sessionReportCommands()).toEqual([['session', 'report']]);
    expect(sessionReportCommands('done')).toEqual([
      ['session', 'close', '--summary', 'done'],
      ['session', 'report'],
    ]);
  });
});
