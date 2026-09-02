import { describe, expect, it } from 'vitest';
import { attestHandoffArgs, mintChallengeArgs, presentArgs, sessionReportCommands, verifyArgs, verifyPresentationArgs } from '../src/cli-args.js';

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

describe('handshake args match the CLI surface', () => {
  // These were verified against `treeship <cmd> --help` on 0.26.0. The first
  // draft passed `attest handoff --verified`, which does not exist; clap
  // rejects the whole invocation, so a wrong flag here breaks the tool
  // entirely rather than degrading.

  it('mints a challenge as JSON', () => {
    expect(mintChallengeArgs()).toEqual(['session', 'mint-challenge', '--format', 'json']);
  });

  it('presents against a challenge the counterparty minted', () => {
    expect(presentArgs('agent://mcp', 'n'.repeat(32))).toEqual([
      'present',
      'agent://mcp',
      '--challenge',
      'n'.repeat(32),
      '--format',
      'json',
    ]);
  });

  it('always passes a challenge when verifying a presentation', () => {
    // A presentation verified without a challenge proves a document exists,
    // not that the bearer holds the key, so there is no no-challenge path.
    const args = verifyPresentationArgs('peer.json', 'c'.repeat(32));
    expect(args).toContain('--challenge');
    expect(args).not.toContain('--max-staple-age');
  });

  it('passes staple freshness only when asked', () => {
    expect(verifyPresentationArgs('peer.json', 'c'.repeat(32), '1h')).toEqual([
      'verify-presentation',
      'peer.json',
      '--challenge',
      'c'.repeat(32),
      '--format',
      'json',
      '--max-staple-age',
      '1h',
    ]);
  });

  it('joins handoff artifacts the way the CLI parses them', () => {
    expect(attestHandoffArgs('agent://a', 'agent://b', ['art_1', 'art_2'])).toEqual([
      'attest',
      'handoff',
      '--from',
      'agent://a',
      '--to',
      'agent://b',
      '--artifacts',
      'art_1,art_2',
      '--format',
      'json',
    ]);
  });

  it('records a verified handoff only as the --verified/--challenge pair', () => {
    expect(
      attestHandoffArgs('agent://grok', 'agent://claude', ['art_1'], {
        verified: 'inbox/grok.presentation.json',
        challenge: 'n'.repeat(32),
        maxStapleAge: '1h',
        closeLoop: 'ssn_1',
      }),
    ).toEqual([
      'attest',
      'handoff',
      '--from',
      'agent://grok',
      '--to',
      'agent://claude',
      '--artifacts',
      'art_1',
      '--verified',
      'inbox/grok.presentation.json',
      '--challenge',
      'n'.repeat(32),
      '--max-staple-age',
      '1h',
      '--close-loop',
      'ssn_1',
      '--format',
      'json',
    ]);
  });

  it('never emits --verified without the challenge it answered', () => {
    // A static presentation proves the record, not the bearer. Dropping the
    // pair is the honest fallback: the handoff records as asserted.
    const args = attestHandoffArgs('agent://a', 'agent://b', ['art_1'], { verified: 'p.json' });
    expect(args).not.toContain('--verified');
    expect(args).not.toContain('--challenge');
  });

  it('records a same-computer handoff as asserted with its reason', () => {
    expect(
      attestHandoffArgs('agent://a', 'agent://b', ['art_1'], { custodyReason: 'same_computer' }),
    ).toContain('--custody-reason');
  });

  it('uses no flag the CLI does not define', () => {
    // Guard against re-introducing `--verified`: slice 3 of the A2A spec adds
    // it, and until the CLI grows it this must not appear.
    const all = [
      ...mintChallengeArgs(),
      ...presentArgs('agent://a', 'x'.repeat(32)),
      ...verifyPresentationArgs('f', 'x'.repeat(32), '1h'),
      ...attestHandoffArgs('agent://a', 'agent://b', ['art_1'], {
        verified: 'p.json',
        challenge: 'x'.repeat(32),
        maxStapleAge: '1h',
        closeLoop: 'ssn_1',
      }),
      ...attestHandoffArgs('agent://a', 'agent://b', ['art_1'], { custodyReason: 'same_computer' }),
    ].filter((a) => a.startsWith('--'));
    // Every flag `treeship attest handoff --help` defines as of 0.27.0.
    const known = new Set([
      '--format',
      '--challenge',
      '--max-staple-age',
      '--from',
      '--to',
      '--artifacts',
      '--verified',
      '--custody-reason',
      '--close-loop',
    ]);
    for (const flag of all) expect(known.has(flag)).toBe(true);
  });
});
