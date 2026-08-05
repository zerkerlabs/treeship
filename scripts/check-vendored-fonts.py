#!/usr/bin/env python3
"""Keep vendored crate assets byte-identical to their source of truth.

Two crates embed the Fraunces webfont with `include_bytes!`. The font's home is
`design/fonts/`, but a crate may only embed files under its own root: `cargo
package` tarballs the crate directory and nothing above it, so an
`include_bytes!("../../../../design/fonts/...")` compiles locally, passes CI,
and then fails to build once published.

That is not hypothetical. It is how `treeship-core` missed crates.io in v0.22.0
while npm and PyPI published normally -- a partial release that no version check
could have caught, because every version was correct.

So each crate keeps its own copy, and this script fails if a copy drifts from
`design/fonts/`. Run in the docs-drift job.
"""

import hashlib
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "design" / "fonts"

# crate asset dir -> files that must match SOURCE byte for byte
VENDORED = [
    ROOT / "packages" / "core" / "assets" / "fonts",
    ROOT / "packages" / "cli" / "assets" / "fonts",
]

FILES = ["fraunces-latin-var.woff2", "Fraunces-OFL.txt"]


def digest(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def main() -> int:
    errors = []

    if not SOURCE.is_dir():
        print(f"  err   source of truth missing: {SOURCE.relative_to(ROOT)}")
        return 1

    for name in FILES:
        src = SOURCE / name
        if not src.is_file():
            errors.append(f"source file missing: {src.relative_to(ROOT)}")
            continue
        want = digest(src)

        for vendor_dir in VENDORED:
            copy = vendor_dir / name
            rel = copy.relative_to(ROOT)
            if not copy.is_file():
                errors.append(f"vendored copy missing: {rel}")
                continue
            if digest(copy) != want:
                errors.append(
                    f"vendored copy drifted from design/fonts/{name}: {rel}"
                )

    # The bug this exists to prevent is an include reaching out of the crate,
    # so check for that shape directly rather than only for drift.
    #
    # Scoped to crates the release actually publishes -- today just
    # treeship-core. `treeship-cli` ships as prebuilt binaries and is never
    # `cargo publish`ed, so its several out-of-crate includes (zk verifying
    # keys, TREESHIP.md) are fine where they are. Flagging them would be noise,
    # and a check that cries wolf is a check people learn to skip. Add a crate
    # here the moment it starts publishing.
    PUBLISHED_CRATES = ["core"]
    for crate in PUBLISHED_CRATES:
        for rs in (ROOT / "packages" / crate / "src").rglob("*.rs"):
            text = rs.read_text(encoding="utf-8", errors="ignore")
            if 'include_bytes!("../../../' in text or 'include_str!("../../../' in text:
                errors.append(
                    f"{rs.relative_to(ROOT)} embeds a file from outside the crate root; "
                    f"cargo package will not ship it"
                )

    if errors:
        for e in errors:
            print(f"  err   {e}")
        print(f"\n{len(errors)} problem(s). Vendored assets must live under the crate root.")
        return 1

    print("  ✓ vendored crate fonts match design/fonts/ and stay inside their crate")
    return 0


if __name__ == "__main__":
    sys.exit(main())
