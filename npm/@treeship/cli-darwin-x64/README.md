# @treeship/cli-darwin-x64

Platform-specific binary for the Treeship CLI on Intel Macs (macOS x86_64).

This package is **not meant to be installed directly**. It is automatically downloaded when you run:

```sh
npm install -g treeship
```

The main `treeship` package detects your platform and pulls the correct binary.

## Binary integrity

The package ships a single-line `expected-checksum.txt` with the SHA-256 of the binary it downloads from the matching GitHub Release. The postinstall script:

1. Reads the expected hash from the package (delivered via npm).
2. Downloads the binary from `https://github.com/zerkerlabs/treeship/releases/download/v<version>/treeship-darwin-x86_64`.
3. Verifies the downloaded bytes match the expected hash.
4. Atomically renames the partial download into place only on match. On mismatch, the partial file is deleted and install fails (exit 1).

Because the hash is delivered via npm and the binary is delivered via GitHub Releases, an attacker would need to compromise *both* trust roots simultaneously to slip a tampered binary past install. A compromise of either alone produces a verification failure.

If the package was published without `expected-checksum.txt`, the postinstall refuses to install. That's intentional: a binary with no published checksum is unverifiable.

## Repository

[github.com/zerkerlabs/treeship](https://github.com/zerkerlabs/treeship)
