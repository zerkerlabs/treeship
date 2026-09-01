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
// The first version of this wired `attest handoff --verified`, a flag the CLI
// does not have, and nothing would have caught it until a host tried a handoff
// and clap rejected the whole invocation.

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

export function attestHandoffArgs(from: string, to: string, artifacts: string[]): string[] {
  return [
    'attest',
    'handoff',
    '--from',
    from,
    '--to',
    to,
    '--artifacts',
    artifacts.join(','),
    '--format',
    'json',
  ];
}
