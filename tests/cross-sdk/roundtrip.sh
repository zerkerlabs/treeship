#!/usr/bin/env bash
# Phase B of the cross-SDK contract suite.
#
# Vector-based verify parity (Phase A in run.sh) catches drift in HOW
# both SDKs interpret the same CLI output. This script catches a deeper
# class of drift: an artifact ATTESTED by SDK A must verify cleanly under
# SDK B, and vice versa. If TS produces an artifact whose envelope shape,
# digest scheme, or signature encoding diverges from what Python expects
# to verify, Phase B fails.
#
# Both SDKs share the same scratch keystore via TREESHIP_CONFIG (set by
# the caller -- run.sh exports it before invoking this script).
#
# Output: one JSON line per leg of the roundtrip, then a final OK / FAIL.
# Exit 0 only when all four legs pass.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ -z "${TREESHIP_CONFIG:-}" ]]; then
  echo "error: TREESHIP_CONFIG must be set (run.sh sets it before calling this)" >&2
  exit 2
fi

leg() {
  printf '{"phase":"B","leg":"%s","outcome":"%s"' "$1" "$2"
  shift 2
  while (( $# >= 2 )); do
    printf ',"%s":"%s"' "$1" "$2"
    shift 2
  done
  printf '}\n'
}

# 1. TS attest -> artifact_id_ts
TS_ID=$(node "$SCRIPT_DIR/_sdk-helper.mjs" attest-action "agent://roundtrip-ts" "tool.call")
if [[ -z "$TS_ID" ]]; then
  leg "ts-attest" "error" "error" "empty artifact id"
  exit 1
fi
leg "ts-attest" "pass" "artifact_id" "$TS_ID"

# 2. Python verifies the TS-attested artifact
PY_VERIFY_TS=$(python3 "$SCRIPT_DIR/_sdk_helper.py" verify "$TS_ID")
if [[ "$PY_VERIFY_TS" != "pass" ]]; then
  leg "py-verifies-ts" "fail" "expected" "pass" "got" "$PY_VERIFY_TS"
  exit 1
fi
leg "py-verifies-ts" "pass"

# 3. Python attest -> artifact_id_py
PY_ID=$(python3 "$SCRIPT_DIR/_sdk_helper.py" attest-action "agent://roundtrip-py" "tool.call")
if [[ -z "$PY_ID" ]]; then
  leg "py-attest" "error" "error" "empty artifact id"
  exit 1
fi
leg "py-attest" "pass" "artifact_id" "$PY_ID"

# 4. TS verifies the Python-attested artifact
TS_VERIFY_PY=$(node "$SCRIPT_DIR/_sdk-helper.mjs" verify "$PY_ID")
if [[ "$TS_VERIFY_PY" != "pass" ]]; then
  leg "ts-verifies-py" "fail" "expected" "pass" "got" "$TS_VERIFY_PY"
  exit 1
fi
leg "ts-verifies-py" "pass"

echo "  ok -- TS and Python attest+verify each other's artifacts"
