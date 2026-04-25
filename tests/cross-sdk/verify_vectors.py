"""Python runner for the cross-SDK contract suite.

Loads tests/cross-sdk/corpus.json (written by gen-vectors.sh), points the
treeship_sdk at the corpus's scratch keystore via TREESHIP_CONFIG, then
verifies every vector through Treeship().verify(id) -- the actual SDK
public surface, NOT a private CLI bypass. Emits one JSON line per vector
to stdout.

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
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
CORPUS_PATH = HERE / "corpus.json"
REPO_ROOT = HERE.parent.parent


def find_binary_dir() -> Path:
    """Match the binary-discovery rule used by gen-vectors.sh, return its parent dir."""
    env = os.environ.get("TREESHIP_BIN")
    if env:
        p = Path(env)
        if p.exists() and os.access(p, os.X_OK):
            return p.parent
    # Prefer debug over release: the orchestrator rebuilds debug each run,
    # so a stale release binary from a prior `cargo build --release` won't
    # silently shadow it. TREESHIP_BIN above still wins for explicit callers.
    for candidate in (
        REPO_ROOT / "target" / "debug" / "treeship",
        REPO_ROOT / "target" / "release" / "treeship",
    ):
        if candidate.exists() and os.access(candidate, os.X_OK):
            return candidate.parent
    raise SystemExit("no treeship binary found; build with cargo first")


def main() -> int:
    corpus = json.loads(CORPUS_PATH.read_text())

    # Put the test binary on PATH and bind the SDK to the scratch keystore.
    # The SDK spawns `treeship` from PATH and inherits this process's env,
    # so these two assignments are everything we need to redirect every
    # SDK-issued CLI invocation at the corpus instead of the user's
    # default keystore.
    binary_dir = find_binary_dir()
    os.environ["PATH"] = f"{binary_dir}{os.pathsep}{os.environ.get('PATH', '')}"
    os.environ["TREESHIP_CONFIG"] = corpus["config_path"]

    # Import the SDK from source. The package is at packages/sdk-python/,
    # rooted at the workspace; adding it to sys.path makes `treeship_sdk`
    # importable without requiring a pip install in CI.
    sys.path.insert(0, str(REPO_ROOT / "packages" / "sdk-python"))
    from treeship_sdk import Treeship, TreeshipError  # noqa: E402

    ts = Treeship()
    mismatches = 0
    for v in corpus["vectors"]:
        line: dict = {"runner": "py", "name": v["name"]}
        try:
            result = ts.verify(v["artifact_id"])
            line["outcome"] = result.outcome
            line["chain"] = result.chain
            errors = []
            if result.outcome != v["expected_outcome"]:
                errors.append(f"expected outcome={v['expected_outcome']}, got {result.outcome}")
            # expected_chain is optional -- if set, both SDKs must agree
            # on it too. Without this assertion both SDKs could silently
            # regress to the same wrong chain count and the suite would
            # still exit 0 (Codex finding #4 in the v0.9.5 review).
            expected_chain = v.get("expected_chain")
            if expected_chain is not None and result.chain != expected_chain:
                errors.append(f"expected chain={expected_chain}, got {result.chain}")
            if errors:
                mismatches += 1
                line["expected_outcome"] = v["expected_outcome"]
                if expected_chain is not None:
                    line["expected_chain"] = expected_chain
                line["error"] = "; ".join(errors)
        except TreeshipError as e:
            mismatches += 1
            line["outcome"] = "error"
            line["error"] = str(e)
        except Exception as e:
            mismatches += 1
            line["outcome"] = "error"
            line["error"] = f"{type(e).__name__}: {e}"

        print(json.dumps(line))

    return 0 if mismatches == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
