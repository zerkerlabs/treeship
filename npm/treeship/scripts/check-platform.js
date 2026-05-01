// Treeship npm wrapper -- preinstall platform guard.
//
// We ship prebuilt binaries for darwin-arm64, darwin-x64, and linux-x64.
// As of v0.10.1 the Linux binary is statically linked against musl, so it
// runs on every glibc and musl distribution we know of (Ubuntu, Debian,
// Fedora, RHEL/Rocky, Amazon Linux, Alpine, distroless, busybox).
//
// Without this guard, a Windows user running `npm install -g treeship` would
// install the wrapper, then hit a confusing "binary not found" error the
// first time they ran `treeship`. Fail loud, fail early on Windows.

if (process.platform === 'win32') {
  process.stderr.write(
    '\n' +
    'Treeship v' + require('../package.json').version + ' does not support Windows natively.\n' +
    '\n' +
    'Use WSL (Windows Subsystem for Linux). A native Windows binary is not on\n' +
    'the current roadmap; if you need one, please open an issue describing\n' +
    'your use case at https://github.com/zerkerlabs/treeship/issues.\n' +
    '\n'
  );
  process.exit(1);
}
