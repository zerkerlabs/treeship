// Treeship npm wrapper -- preinstall platform guard.
//
// We only ship binaries for darwin-arm64, darwin-x64, and linux-x64 at v0.9.3.
// Without this guard, a Windows user running `npm install -g treeship` would
// successfully install the wrapper, then hit a confusing "binary not found"
// error the first time they ran `treeship`. Fail loud, fail early.

if (process.platform === 'win32') {
  process.stderr.write(
    '\n' +
    'Treeship v' + require('../package.json').version + ' does not support Windows natively yet.\n' +
    '\n' +
    'Use WSL (Windows Subsystem for Linux), or wait for v0.10.0 which adds a\n' +
    'native Windows binary and a PowerShell setup path.\n' +
    '\n' +
    'See https://github.com/zerkerlabs/treeship for status.\n' +
    '\n'
  );
  process.exit(1);
}
