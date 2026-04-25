"""Python runner for the cross-SDK contract suite.

Reads tests/cross-sdk/corpus.json (written by gen-vectors.sh), verifies
every vector through the treeship_sdk public surface, and emits one JSON
line per vector to stdout. The orchestrator (run.sh) diffs this against
the TypeScript runner's output and fails on any divergence.

Output format (one per line, JSON, no embedded newlines):
    {"runner": "py", "name": "<vector-name>", "outcome": "pass", "chain": 1}
    {"runner": "py", "name": "<vector-name>", "outcome": "fail", "chain": 0}
    {"runner": "py", "name": "<vector-name>", "outcome": "error", "error": "..."}

Exits 0 if every observed outcome matches the corpus's expected_outcome;
non-zero if any vector failed expectations or raised.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
CORPUS_PATH = HERE / "corpus.json"
REPO_ROOT = HERE.parent.parent


def find_treeship_bin() -> str:
    """Match the binary-discovery rule used by gen-vectors.sh."""
    env = os.environ.get("TREESHIP_BIN")
    if env:
        return env
    for candidate in (
        REPO_ROOT / "target" / "release" / "treeship",
        REPO_ROOT / "target" / "debug" / "treeship",
    ):
        if candidate.exists() and os.access(candidate, os.X_OK):
            return str(candidate)
    raise SystemExit("no treeship binary found; build with cargo first")


def run_verify(binary: str, config_path: str, artifact_id: str) -> dict:
    """Run `treeship verify` and return the parsed JSON outcome.

    The CLI exits 1 on fail but still emits a structured JSON outcome on
    stdout; we capture both regardless of returncode.
    """
    proc = subprocess.run(
        [
            binary,
            "--config", config_path,
            "--format", "json",
            "verify", artifact_id,
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )
    if not proc.stdout.strip():
        raise RuntimeError(
            f"empty stdout from verify (exit={proc.returncode}, stderr={proc.stderr.strip()[:200]})"
        )
    parsed = json.loads(proc.stdout)
    return {
        "outcome": str(parsed.get("outcome")),
        "chain": int(parsed.get("passed", parsed.get("total", 0))),
    }


def main() -> int:
    corpus = json.loads(CORPUS_PATH.read_text())
    binary = find_treeship_bin()
    config_path = corpus["config_path"]

    mismatches = 0
    for v in corpus["vectors"]:
        line: dict = {"runner": "py", "name": v["name"]}
        try:
            result = run_verify(binary, config_path, v["artifact_id"])
            line["outcome"] = result["outcome"]
            line["chain"] = result["chain"]
            if result["outcome"] != v["expected_outcome"]:
                mismatches += 1
                line["expected_outcome"] = v["expected_outcome"]
                line["error"] = (
                    f"expected outcome={v['expected_outcome']}, got {result['outcome']}"
                )
        except Exception as e:
            mismatches += 1
            line["outcome"] = "error"
            line["error"] = str(e)

        print(json.dumps(line))

    return 0 if mismatches == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
