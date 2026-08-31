#!/usr/bin/env bash
# trust-fabric.sh — end-to-end acceptance suite for the v0.9.6 trust-fabric
# guarantees. Each test exercises a release-breaking property of the
# capture-normalize-verify chain.
#
# Run locally:
#   ./tests/acceptance/trust-fabric.sh
#
# Run a single test:
#   ./tests/acceptance/trust-fabric.sh smoke
#
# Run from CI: see .github/workflows/acceptance.yml.
#
# Each test runs in its own tmpdir with a fresh keystore; nothing leaks to the
# user's ~/.treeship.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CLI="${TREESHIP_CLI:-${REPO_ROOT}/target/debug/treeship}"
PASS=0
FAIL=0
FAILED_TESTS=()

# ---------- harness ----------

setup_workspace() {
  # Each test gets a fresh tmpdir and a fresh keystore so tests can't pollute
  # each other's state. CONFIG points the CLI at this isolated tree.
  WORKSPACE="$(mktemp -d -t treeship-acceptance.XXXXXX)"
  export CONFIG="${WORKSPACE}/.treeship/config.json"
  cd "${WORKSPACE}"
  "${CLI}" init --config "${CONFIG}" --name "acceptance-test" >/dev/null
}

teardown_workspace() {
  rm -rf "${WORKSPACE}"
}

run_test() {
  local name="$1"
  local fn="$2"
  if [[ $# -ge 3 && -n "$3" && "$3" != "$name" ]]; then
    return 0  # filter mismatch
  fi
  echo "── ${name} ──"
  setup_workspace
  if "${fn}"; then
    echo "   ✓ ${name}"
    PASS=$((PASS + 1))
  else
    echo "   ✗ ${name}" >&2
    FAIL=$((FAIL + 1))
    FAILED_TESTS+=("${name}")
  fi
  teardown_workspace
  echo
}

assert_contains() {
  local haystack="$1"
  local needle="$2"
  if ! echo "${haystack}" | grep -Fq "${needle}"; then
    echo "   expected to find: ${needle}" >&2
    echo "   in output:" >&2
    echo "${haystack}" | sed 's/^/     /' >&2
    return 1
  fi
}

assert_not_contains() {
  local haystack="$1"
  local needle="$2"
  if echo "${haystack}" | grep -Fq "${needle}"; then
    echo "   expected NOT to find: ${needle}" >&2
    echo "   in output:" >&2
    echo "${haystack}" | sed 's/^/     /' >&2
    return 1
  fi
}

# ---------- tests ----------

# T0 (smoke): A complete session round-trip exercises the full chain we care
# about for release: keystore generation, session start, command capture, file
# write recording, session close, package emission, package verify. If any
# of these regress, every other test in this suite would also fail —
# fail-fast on the smoke test gives a fast clear error.
test_smoke_session_roundtrip() {
  local out
  out="$("${CLI}" session start --config "${CONFIG}" --name smoke 2>&1)"
  assert_contains "${out}" "session" || return 1

  echo "hello" > note.txt
  "${CLI}" wrap --config "${CONFIG}" --action smoke.write -- \
    sh -c 'echo "from acceptance" > artifact.txt' >/dev/null 2>&1 || return 1

  out="$("${CLI}" session close --config "${CONFIG}" --summary "smoke ok" 2>&1)"
  assert_contains "${out}" "session" || return 1

  # Find the package the close emitted and verify it.
  local pkg
  pkg="$(find .treeship/sessions -name 'ssn_*.treeship' -print -quit 2>/dev/null || true)"
  if [[ -z "${pkg}" ]]; then
    echo "   no .treeship session package was emitted" >&2
    return 1
  fi
  out="$("${CLI}" package verify --config "${CONFIG}" "${pkg}" 2>&1)"
  assert_contains "${out}" "verif" || return 1
  return 0
}

# ---------- T1-T9 placeholders ----------
#
# The full v0.9.6 acceptance suite covers nine release-critical invariants
# documented in the v0.9.6 CHANGELOG. Each one needs to be ported from the
# manual run notes that proved the v0.9.6 trust-fabric chain green:
#
#   T1. Claude built-ins authorization
#       Session uses Read, Write/Edit, Bash; cert/card declares only read_file.
#       Expect actual=[bash, read_file, write_file], unauthorized=[bash, write_file].
#
#   T2. Claude built-ins happy path
#       Cert/card declares all three; unauthorized list is empty.
#
#   T3. Read → Bash modifies same file
#       Bash/sed mutates a file already Read'd. files_written records the
#       change; tool_usage stays honest (no double-count from git-reconcile).
#
#   T4. MCP write_file
#       MCP bridge emits write_file with file_path + content. files_written
#       has the path; raw content is absent from the receipt.
#
#   T5. MCP command privacy
#       MCP bridge sees command/cmd carrying a Bearer token. The recorded
#       invocation must omit the raw command from meta/tool_input/receipt.
#
#   T6. Source provenance
#       Sources hook, mcp, git-reconcile, session-event-cli, daemon-atime,
#       and unknown-custom keep their honest labels in the receipt; unknown
#       labels never collapse to "hook".
#
#   T7. git mv old.rs new.rs
#       files_written records new.rs only, not old.rs.
#
#   T8. Malformed event before/after a valid write
#       Valid writes either side are recorded; the malformed line is logged
#       as event_log_skipped; package verify warns/fails per --strict.
#
#   T9. Package verify
#       Fully-formed package verifies; expected warnings (eg. unscoped
#       approval, package-local replay) are explicit, not silent.
#
# Each test should follow the same pattern as test_smoke_session_roundtrip:
# stand up an isolated workspace, drive the CLI to produce the artifact under
# test, and assert on the package/verify output. Add new run_test() lines in
# main() once each test function lands.

# T1: The Claude Code PostToolUse hook must record a human's answer, and must
# NOT invent an approver.
#
# Background: AskUserQuestion used to fall through to the generic branch, so a
# session where an operator authorized an irreversible publish recorded only
# {"type":"agent.called_tool","tool_name":"AskUserQuestion"} -- the most
# consequential moment in the run, stored with the least detail.
#
# Two properties are release-breaking here and both are asserted:
#
#   1. Without TREESHIP_APPROVER, no approval artifact is minted. The hook can
#      see that someone answered; it cannot see who. Deriving an approver from
#      $USER or git config would manufacture an identity claim the evidence
#      does not support. Fail-closed: no configured approver, no artifact.
#   2. With TREESHIP_APPROVER, exactly one approval artifact is minted and it
#      verifies, carrying the configured approver.
#
# A regression on (1) is the dangerous direction: it would put a fabricated
# human identity into a signed, publishable record.
test_askuserquestion_approval_capture() {
  local hook payload before after out
  hook="${REPO_ROOT}/integrations/claude-code-plugin/scripts/post-tool-use.sh"
  [[ -x "${hook}" || -f "${hook}" ]] || { echo "   hook not found: ${hook}" >&2; return 1; }

  payload='{"tool_name":"AskUserQuestion","tool_input":{"questions":[{"question":"Publish to npm? Irreversible.","header":"Release"}]},"tool_response":{"answers":{"Publish to npm?":"Yes, publish"}}}'

  # The hook resolves `treeship` from PATH and the project from cwd, and it
  # exits early unless a session is open -- it is a session recorder, so no
  # session means nothing to record against.
  export PATH="$(dirname "${CLI}"):${PATH}"
  export TREESHIP_PROJECT_ROOT="${WORKSPACE}"
  "${CLI}" session start --config "${CONFIG}" --name approval-capture >/dev/null 2>&1 || true

  count_artifacts() {
    find "${WORKSPACE}/.treeship/artifacts" -name 'art_*.json' 2>/dev/null | wc -l | tr -d ' '
  }

  # (1) approver unset -> no artifact minted
  before="$(count_artifacts)"
  printf '%s' "${payload}" | env -u TREESHIP_APPROVER sh "${hook}" >/dev/null 2>&1 || true
  after="$(count_artifacts)"
  if [[ "${before}" != "${after}" ]]; then
    echo "   minted an approval with no TREESHIP_APPROVER set (${before} -> ${after})" >&2
    echo "   the hook must never invent an approver identity" >&2
    return 1
  fi

  # (2) approver set -> exactly one artifact, and it verifies
  printf '%s' "${payload}" | TREESHIP_APPROVER="human://acceptance" sh "${hook}" >/dev/null 2>&1 || true
  after="$(count_artifacts)"
  if [[ "${after}" != "$((before + 1))" ]]; then
    echo "   expected exactly one new approval artifact (${before} -> ${after})" >&2
    return 1
  fi

  # Verify every approval artifact in the store and require that one of them
  # names the configured approver. Selecting "the newest file" is not stable
  # across filesystems, and a test that verifies the wrong artifact would go
  # green for the wrong reason.
  local found=0 art_id
  while IFS= read -r art_path; do
    [[ -n "${art_path}" ]] || continue
    art_id="$(basename "${art_path}" .json)"
    out="$("${CLI}" verify --config "${CONFIG}" "${art_id}" 2>&1 || true)"
    if echo "${out}" | grep -Fq "human://acceptance"; then
      found=1
      break
    fi
  done < <(find "${WORKSPACE}/.treeship/artifacts" -name 'art_*.json' 2>/dev/null)

  if [[ "${found}" -ne 1 ]]; then
    echo "   no minted artifact verified with approver human://acceptance" >&2
    return 1
  fi
}

# ---------- runner ----------

main() {
  if [[ ! -x "${CLI}" ]]; then
    echo "::error::CLI not built at ${CLI}; run 'cargo build --bin treeship' first" >&2
    exit 1
  fi

  local filter="${1:-}"
  run_test "smoke"   test_smoke_session_roundtrip "${filter}"
  run_test "approval-capture" test_askuserquestion_approval_capture "${filter}"

  echo "================================"
  echo "  passed: ${PASS}    failed: ${FAIL}"
  echo "================================"
  if [[ ${FAIL} -gt 0 ]]; then
    printf '  failed tests:\n'
    printf '    - %s\n' "${FAILED_TESTS[@]}"
    exit 1
  fi
}

main "$@"
