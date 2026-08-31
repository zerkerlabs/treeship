#!/bin/sh
# Treeship Claude Code plugin -- PostToolUse hook
#
# Dispatches on tool_name to emit the correct Treeship session event so the
# receipt's side-effects buckets populate properly:
#
#   Claude Code tool   ->  Emitted Treeship event
#   ---------------------  --------------------------------------
#   Read               ->  agent.read_file --file <path>
#   Write              ->  agent.wrote_file --file <path>
#   Edit               ->  agent.wrote_file --file <path>
#   MultiEdit          ->  agent.wrote_file --file <path>
#   NotebookEdit       ->  agent.wrote_file --file <path>
#   Bash               ->  agent.completed_process --tool <cmd> --exit-code <N>
#   WebFetch           ->  agent.connected_network --destination <host>
#   AskUserQuestion    ->  agent.called_tool + the question and the operator's
#                          answer, and (opt-in) a signed approval artifact
#   *                  ->  agent.called_tool --tool <name>
#
# Without the dispatch, every tool was emitted as agent.called_tool only, so
# the receipt's files_read[], files_written[], and processes[] lists stayed
# at length 0 even when Claude was reading and writing files all session.
#
# The Treeship MCP server captures every MCP-routed tool call automatically
# via @treeship/mcp; this hook covers Claude Code's BUILT-IN tools (Read,
# Write, Edit, Bash, Grep, Glob, etc.) which bypass MCP entirely.

set -e

INPUT=$(cat 2>/dev/null || true)
[ -z "$INPUT" ] && exit 0

if ! command -v treeship >/dev/null 2>&1; then
  exit 0
fi

# Locate the project. Honor TREESHIP_PROJECT_ROOT when it points at a real
# .treeship dir (matches the kimi plugin, and lets the hook work when invoked
# from a different cwd), otherwise require a .treeship in the cwd or $HOME.
if [ -n "${TREESHIP_PROJECT_ROOT:-}" ] && [ -d "${TREESHIP_PROJECT_ROOT}/.treeship" ]; then
  cd "${TREESHIP_PROJECT_ROOT}"
elif [ ! -d "./.treeship" ] && [ ! -d "${HOME}/.treeship" ]; then
  exit 0
fi

# No active session means no place to record this event.
if ! treeship session status --check >/dev/null 2>&1; then
  exit 0
fi

# ----------------------------------------------------------------------------
# JSON field extractor: jq -> python3 -> node fallback chain.
#
# Takes a dotted path (e.g. "tool_input.file_path") and prints the matching
# string value from $INPUT, or empty if absent. Field name is passed via
# argv to each interpreter so the shell never tries to interpolate it into
# script source -- that prevents quoting bugs and avoids injection if a
# later refactor ever passes user-controlled field paths.
# ----------------------------------------------------------------------------

extract() {
  field="$1"
  out=""
  if command -v jq >/dev/null 2>&1; then
    out=$(printf '%s' "$INPUT" | jq -r --arg f "$field" '
      ($f | split(".")) as $path
      | reduce $path[] as $k (.; if type == "object" then .[$k] else empty end)
      | if (. == null or . == false) then "" else (if type == "string" then . else tojson end) end
    ' 2>/dev/null)
  fi
  if [ -z "$out" ] && command -v python3 >/dev/null 2>&1; then
    out=$(printf '%s' "$INPUT" | python3 -c "
import json, sys
field = sys.argv[1]
try:
    d = json.load(sys.stdin)
    for p in field.split('.'):
        if isinstance(d, dict): d = d.get(p)
        else: d = None; break
    if d is None: print('')
    elif isinstance(d, str): print(d)
    else: print(json.dumps(d))
except Exception:
    pass
" "$field" 2>/dev/null)
  fi
  if [ -z "$out" ] && command -v node >/dev/null 2>&1; then
    out=$(printf '%s' "$INPUT" | node -e '
      let buf = "";
      process.stdin.on("data", c => buf += c);
      process.stdin.on("end", () => {
        try {
          let v = JSON.parse(buf);
          for (const k of process.argv[1].split(".")) {
            if (v == null || typeof v !== "object") { v = null; break; }
            v = v[k];
          }
          if (v == null) console.log("");
          else if (typeof v === "string") console.log(v);
          else console.log(JSON.stringify(v));
        } catch { console.log(""); }
      });
    ' "$field" 2>/dev/null)
  fi
  printf '%s' "$out"
}

TOOL_NAME=$(extract tool_name)
[ -z "$TOOL_NAME" ] || [ "$TOOL_NAME" = "null" ] && TOOL_NAME="unknown"

# ----------------------------------------------------------------------------
# Helper: emit a generic agent.called_tool event. Used as the fall-through
# for tools we don't have a specialized event type for, AND as the safety
# net when a specialized emit can't extract its required field.
# ----------------------------------------------------------------------------
emit_called_tool() {
  treeship session event \
    --type "agent.called_tool" \
    --tool "$TOOL_NAME" \
    --agent-name "claude-code" \
    >/dev/null 2>&1 || true
}

# AUD-26: redact secret-bearing tokens from a command string before it is
# recorded in the session timeline, which can be PUBLISHED to a no-auth URL via
# `session report`. Removes the values of env-assignment secrets (FOO_KEY=,
# TOKEN=, ...), secret CLI flags (--token=, --password, --api-key=), and HTTP
# bearer tokens, keeping the rest of the command readable. Best-effort and
# pattern-based, NOT a guarantee — real secrets belong in env vars, not inline.
# Portable POSIX `sed -E` only (no GNU-only \b or case-insensitive flag).
redact_secrets() {
  printf '%s' "$1" | sed -E \
    -e 's/([A-Z0-9_]*(KEY|TOKEN|SECRET|PASSWORD|PASSWD|PWD|CREDENTIAL|AUTH|APIKEY)[A-Z0-9_]*=)[^[:space:]]*/\1[REDACTED]/g' \
    -e 's/(--?(token|secret|password|passwd|api[-_]?key|apikey|auth|bearer)[=[:space:]])[^[:space:]]*/\1[REDACTED]/g' \
    -e 's/([Bb]earer[[:space:]]+)[A-Za-z0-9._~+/=-]+/\1[REDACTED]/g'
}

# ----------------------------------------------------------------------------
# Dispatch on tool name.
# ----------------------------------------------------------------------------
case "$TOOL_NAME" in
  Read)
    FILE=$(extract tool_input.file_path)
    if [ -n "$FILE" ]; then
      treeship session event \
        --type "agent.read_file" \
        --file "$FILE" \
        --agent-name "claude-code" \
        >/dev/null 2>&1 || emit_called_tool
    else
      emit_called_tool
    fi
    ;;
  Write|Edit|MultiEdit)
    FILE=$(extract tool_input.file_path)
    if [ -n "$FILE" ]; then
      treeship session event \
        --type "agent.wrote_file" \
        --file "$FILE" \
        --agent-name "claude-code" \
        >/dev/null 2>&1 || emit_called_tool
    else
      emit_called_tool
    fi
    ;;
  NotebookEdit)
    FILE=$(extract tool_input.notebook_path)
    if [ -n "$FILE" ]; then
      treeship session event \
        --type "agent.wrote_file" \
        --file "$FILE" \
        --agent-name "claude-code" \
        >/dev/null 2>&1 || emit_called_tool
    else
      emit_called_tool
    fi
    ;;
  Bash)
    CMD=$(extract tool_input.command)
    # Redact secrets BEFORE truncating (AUD-26), then trim to a sensible
    # process_name. This string can end up in a published, no-auth receipt.
    PROC_NAME=$(redact_secrets "${CMD:-bash}" | cut -c1-120)
    # PostToolUse fires AFTER the command exits. The exit code is in the
    # tool_response payload (Claude Code uses tool_response.exit_code OR
    # the tool_response.is_error boolean depending on Bash variant).
    EXIT_CODE=$(extract tool_response.exit_code)
    if [ -z "$EXIT_CODE" ]; then
      IS_ERROR=$(extract tool_response.is_error)
      if [ "$IS_ERROR" = "true" ]; then EXIT_CODE=1; else EXIT_CODE=0; fi
    fi
    treeship session event \
      --type "agent.completed_process" \
      --tool "$PROC_NAME" \
      --exit-code "$EXIT_CODE" \
      --agent-name "claude-code" \
      >/dev/null 2>&1 || emit_called_tool
    ;;
  WebFetch)
    URL=$(extract tool_input.url)
    if [ -n "$URL" ]; then
      # Strip scheme + path -> just the host. Sed-only so no extra deps.
      HOST=$(printf '%s' "$URL" | sed -E 's|^https?://||' | cut -d/ -f1 | cut -d: -f1)
      if [ -n "$HOST" ]; then
        treeship session event \
          --type "agent.connected_network" \
          --destination "$HOST" \
          --agent-name "claude-code" \
          >/dev/null 2>&1 || emit_called_tool
      else
        emit_called_tool
      fi
    else
      emit_called_tool
    fi
    ;;
  AskUserQuestion)
    # The one place a human's judgement enters the session. Previously this
    # fell through to the catch-all, so a session in which an operator
    # approved an irreversible action recorded exactly:
    #
    #   {"type": "agent.called_tool", "tool_name": "AskUserQuestion"}
    #
    # -- no question, no answer, no approver. The decision that mattered most
    # in the run was the one the receipt said least about.
    #
    # Two things happen here, and they claim very different amounts.
    QUESTION=$(extract tool_input.questions)
    ANSWERS=$(extract tool_response.answers)
    [ -z "$ANSWERS" ] && ANSWERS=$(extract tool_response)

    # (a) Always: record the exchange in the timeline. Redacted first --
    #     this string can reach a published, no-auth receipt (AUD-26) -- then
    #     capped, because option descriptions run long and the timeline is not
    #     the place for a full prompt.
    Q_SAFE=$(redact_secrets "${QUESTION:-}" | cut -c1-400)
    A_SAFE=$(redact_secrets "${ANSWERS:-}" | cut -c1-400)
    META=$(python3 -c "
import json, sys
print(json.dumps({'question': sys.argv[1], 'answer': sys.argv[2]}))
" "$Q_SAFE" "$A_SAFE" 2>/dev/null)

    if [ -n "$META" ]; then
      treeship session event \
        --type "agent.called_tool" \
        --tool "$TOOL_NAME" \
        --agent-name "claude-code" \
        --meta "$META" \
        >/dev/null 2>&1 || emit_called_tool
    else
      emit_called_tool
    fi

    # (b) Opt-in only: mint a signed approval artifact.
    #
    # Fail-closed on identity. The hook observes that *someone* at this
    # terminal chose an option; it cannot prove who. Deriving an approver from
    # $USER or a git config would manufacture an identity claim the evidence
    # does not support, which is exactly the failure mode this repo's policy
    # names. So: no configured approver, no artifact. The timeline entry above
    # still records what happened.
    #
    # Setting TREESHIP_APPROVER is the operator asserting "answers I give in
    # this session are mine, and may be recorded as authorization records."
    # That assertion is theirs to make, and it is what the artifact rests on.
    #
    # Note also that AskUserQuestion is a general-purpose question tool, not an
    # approval gate -- most answers authorize nothing. The description below
    # therefore states only what was observed (operator answered X to question
    # Y) and never that the answer authorized any particular action.
    if [ -n "${TREESHIP_APPROVER:-}" ]; then
      DESC=$(printf 'operator answered %s | question: %s' "$A_SAFE" "$Q_SAFE" | cut -c1-500)
      treeship attest approval \
        --approver "$TREESHIP_APPROVER" \
        --description "$DESC" \
        --unscoped \
        --quiet \
        >/dev/null 2>&1 || true
    fi
    ;;

  *)
    # Glob, Grep, Task, TodoWrite, ScheduleWakeup, etc. -- generic call.
    emit_called_tool
    ;;
esac

exit 0
