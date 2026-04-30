"""
``python -m treeship_sdk.bootstrap_cli`` — agent-friendly CLI bootstrap.

Resolves a working ``treeship`` binary on the current machine and
prints a stable JSON result. Designed for shell scripts and AI agents
that need to bootstrap Treeship before they have a Python SDK
instance.

Examples
--------

Resolve and print the JSON result::

    python -m treeship_sdk.bootstrap_cli --json

Resolve and print just the binary path (text mode)::

    python -m treeship_sdk.bootstrap_cli

Resolve without falling back to network installs::

    python -m treeship_sdk.bootstrap_cli --no-install

Pin to a specific version when downloading from the GitHub Release::

    python -m treeship_sdk.bootstrap_cli --json --version 0.9.11

The ``--agent`` flag is accepted (and a no-op) for compatibility with
the agent-native idiom; the JSON output already carries everything an
agent needs.
"""

from __future__ import annotations

import argparse
import json
import sys

from treeship_sdk.bootstrap import (
    BootstrapResult,
    TreeshipBootstrapError,
    default_cache_dir,
    ensure_cli,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m treeship_sdk.bootstrap_cli",
        description="Resolve a working treeship CLI binary; output a stable JSON result.",
    )
    parser.add_argument("--json", action="store_true",
        help="Output JSON instead of the binary path. Required for AI-agent use.")
    parser.add_argument("--no-install", action="store_true",
        help="Disable network fallbacks (npm install, GitHub Release). Fail if the binary isn't already present.")
    parser.add_argument("--version", "-V", default=None,
        help="When falling back to GitHub Release download, pin to this version. Default: latest.")
    parser.add_argument("--cache-dir", default=None,
        help="Override the default per-user cache directory.")
    parser.add_argument("--agent", action="store_true",
        help="Agent-native idiom flag. Accepted for compatibility; the JSON output is already agent-readable.")
    args = parser.parse_args(argv)

    cache = None
    if args.cache_dir:
        from pathlib import Path
        cache = Path(args.cache_dir).expanduser()

    try:
        result: BootstrapResult = ensure_cli(
            cache_dir=cache,
            pinned_version=args.version,
            allow_install=not args.no_install,
        )
    except TreeshipBootstrapError as exc:
        if args.json:
            print(json.dumps(exc.to_dict(), indent=2))
        else:
            print(f"treeship-bootstrap: {exc}", file=sys.stderr)
            print("attempted: " + ", ".join(exc.attempted), file=sys.stderr)
        return 1

    if args.json:
        # Add `cache_dir` separately when it wasn't filled in by the
        # successful path (env / path resolutions don't write to the
        # cache).
        payload = result.to_dict()
        if payload.get("cache_dir") is None:
            payload["cache_dir"] = str(default_cache_dir())
        print(json.dumps(payload, indent=2))
    else:
        print(result.binary)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
