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
