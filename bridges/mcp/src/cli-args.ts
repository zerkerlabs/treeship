export function verifyArgs(artifactId: string, chain?: boolean): string[] {
  const args = ['verify', artifactId];
  if (chain === false) args.push('--no-chain');
  return args;
}

export function sessionReportCommands(summary?: string): string[][] {
  if (summary) {
    return [
      ['session', 'close', '--summary', summary],
      ['session', 'report'],
    ];
  }
  return [['session', 'report']];
}

// --- handshake -------------------------------------------------------------
//
// Kept here rather than inline in the tool handlers so the flags are testable.
// The first version of this wired `attest handoff --verified` before the CLI
// had the flag, and nothing would have caught it until a host tried a handoff
// and clap rejected the whole invocation. The flag exists now (0.27.0); the
// test in cli-args.test.ts still pins every flag emitted here to the CLI's
// definition so that cannot happen again unnoticed.

export function mintChallengeArgs(): string[] {
  return ['session', 'mint-challenge', '--format', 'json'];
}

export function presentArgs(actor: string, challenge: string): string[] {
  return ['present', actor, '--challenge', challenge, '--format', 'json'];
}

export function verifyPresentationArgs(
  file: string,
  challenge: string,
  maxStapleAge?: string,
): string[] {
  const args = ['verify-presentation', file, '--challenge', challenge, '--format', 'json'];
  if (maxStapleAge) args.push('--max-staple-age', maxStapleAge);
  return args;
}

export interface HandoffCustodyArgs {
  /** Presentation file this host verified with `verify-presentation --challenge`. */
  verified?: string;
  /** The nonce THIS host minted that the presentation answers. Required with `verified`. */
  challenge?: string;
  maxStapleAge?: string;
  /** Record `custody: asserted` with this reason instead (e.g. `same_computer`). */
  custodyReason?: string;
  /** A sealed local session id to bind as close-loop evidence. */
  closeLoop?: string;
}

export function attestHandoffArgs(
  from: string,
  to: string,
  artifacts: string[],
  custody: HandoffCustodyArgs = {},
): string[] {
  const args = [
    'attest',
    'handoff',
    '--from',
    from,
    '--to',
    to,
    '--artifacts',
    artifacts.join(','),
  ];
  // `--verified` without `--challenge` is a clap error, and a static
  // presentation must never become `custody: live`; emit the pair or neither.
  if (custody.verified && custody.challenge) {
    args.push('--verified', custody.verified, '--challenge', custody.challenge);
    if (custody.maxStapleAge) args.push('--max-staple-age', custody.maxStapleAge);
  } else if (custody.custodyReason) {
    args.push('--custody-reason', custody.custodyReason);
  }
  if (custody.closeLoop) args.push('--close-loop', custody.closeLoop);
  args.push('--format', 'json');
  return args;
}
