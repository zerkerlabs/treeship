"""Tiny dispatcher used by the cross-SDK roundtrip script (run from
tests/cross-sdk/roundtrip.sh). Imports the in-tree Python SDK from
the workspace path and exposes two operations on stdin/stdout:

    python3 _sdk_helper.py attest-action <actor> <action>
        -> stdout: artifact id (no newline, no JSON)

    python3 _sdk_helper.py verify <artifact_id>
        -> stdout: outcome string ("pass" | "fail" | "error")

Exits non-zero on any unexpected error.
"""
from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent.parent
sys.path.insert(0, str(REPO_ROOT / "packages" / "sdk-python"))

from treeship_sdk import Treeship  # noqa: E402


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print("usage: _sdk_helper.py <op> [args...]", file=sys.stderr)
        return 2

    op = argv[1]
    ts = Treeship()

    if op == "attest-action":
        if len(argv) != 4:
            print("usage: _sdk_helper.py attest-action <actor> <action>", file=sys.stderr)
            return 2
        r = ts.attest_action(actor=argv[2], action=argv[3])
        sys.stdout.write(r.artifact_id)
        return 0

    if op == "verify":
        if len(argv) != 3:
            print("usage: _sdk_helper.py verify <artifact_id>", file=sys.stderr)
            return 2
        r = ts.verify(argv[2])
        sys.stdout.write(r.outcome)
        return 0

    print(f"unknown op: {op}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
