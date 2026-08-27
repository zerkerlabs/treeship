#!/usr/bin/env python3
"""Update a lockfile's declared dependency range without touching the network.

`npm install --package-lock-only` still resolves against the registry. At
`release.sh prepare` time the version being released does not exist yet, so
that command cannot succeed -- it fails ETARGET on the very pin it is meant
to write:

    npm error notarget No matching version found for @treeship/core-wasm@0.25.1

which is how the 0.25.1 prepare died. The lockfile step added after v0.25.0
shipped out-of-sync lockfiles was itself unrunnable during a release, so the
bug it existed to prevent was still one forgotten manual step away.

This writes the one field `npm ci` compares against package.json:

    packages[""].dependencies[<name>]

The resolved entry (`packages["node_modules/<name>"]`) keeps its old version,
`resolved` and `integrity`. That is deliberate. Those three describe a tarball
that has been fetched and hashed; the new one does not exist yet, so there is
no honest value to write. Inventing one, or copying the previous release's
hash forward, would put a wrong integrity hash in a lockfile -- the failure
this repo cares about most.

The resulting lockfile is deliberately incomplete, and `npm ci` rejects it:

    npm error Invalid: lock file's @treeship/core-wasm@0.25.0
              does not satisfy @treeship/core-wasm@0.25.1

That is not a side effect to tolerate -- it is the point. The alternative is
a lockfile that claims to pin a version while resolving to a different one,
which installs the wrong bytes quietly. Refusing loudly is correct.

But it means the tree between `prepare` and publish does not build for JS,
so `release.sh refresh-lockfiles` is a required step of the release and not
a cleanup task. Run it as soon as the packages are on the registry; it
rewrites the resolved entries with real hashes of tarballs that exist.

(An earlier version of this comment claimed npm accepted the intermediate
state, on the strength of a pre-publish test that returned ETARGET. The
ETARGET came from registry resolution and masked the EUSAGE underneath;
once the version was published, the EUSAGE surfaced and broke `npm ci` in
every JS package on main. Testing the failure path proved nothing about the
success path.)
"""

import json
import sys
from pathlib import Path


def main(argv):
    if len(argv) != 3:
        print("usage: lockfile-pin.py <package-dir> <version>", file=sys.stderr)
        return 2
    pkg_dir, version = Path(argv[1]), argv[2]
    lock_path = pkg_dir / "package-lock.json"
    if not lock_path.is_file():
        print(f"  err   {lock_path} does not exist", file=sys.stderr)
        return 1

    with open(lock_path, encoding="utf-8") as f:
        text = f.read()
    lock = json.loads(text)

    root = lock.get("packages", {}).get("")
    if root is None:
        print(f"  err   {lock_path} has no root package entry", file=sys.stderr)
        return 1

    # Every workspace-internal package releases at one version -- that is what
    # check-release-versions.py enforces across its 43 sites. So the pin to
    # rewrite is any @treeship/* dep, not one hardcoded name. Hardcoding
    # @treeship/core-wasm is how three runtime-acceptance lockfiles sat five
    # releases behind on @treeship/verify without anything noticing.
    moved = []
    for section in ("dependencies", "peerDependencies"):
        deps = root.get(section)
        if not isinstance(deps, dict):
            continue
        for name in deps:
            if name.startswith("@treeship/") and deps[name] != version:
                moved.append(f"{name} {deps[name]} -> {version}")
                deps[name] = version

    if not moved:
        return 0

    # Match npm's own formatting so the diff is one line, not the whole file.
    indent = 2
    trailing = "\n" if text.endswith("\n") else ""
    with open(lock_path, "w", encoding="utf-8") as f:
        json.dump(lock, f, indent=indent)
        f.write(trailing)
    for m in moved:
        print(f"  ✓ {pkg_dir}/package-lock.json: {m} (declared range only)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
