#!/bin/sh
# Mock `treeship` binary used by integration parity tests.
if [ -n "${MOCK_TREESHIP_LOG:-}" ]; then
  printf '%s\n' "$*" >> "$MOCK_TREESHIP_LOG"
fi
case "$1" in
  halt)
    # An older CLI has no `halt` subcommand: it prints usage and exits 2.
    # The gate must fail open on that, never block a tool call.
    [ -n "${MOCK_TREESHIP_NO_HALT:-}" ] && { echo "error: unrecognized subcommand 'halt'" >&2; exit 2; }
    # The gate asks for active halts; the fixture supplies them.
    case "$*" in
      *"list --format json"*)
        h="${MOCK_TREESHIP_HALTS:-}"
        [ -z "$h" ] && h='{"halts":[]}'
        printf '%s\n' "$h" ;;
    esac
    exit 0 ;;
  session)
    case "$2" in
      status)
        # The gate reads the session actor from JSON status.
        case "$*" in
          *"--format json"*) printf '{"active":true,"actor":"%s","session_id":"ssn_mock"}\n' "${MOCK_TREESHIP_ACTOR:-agent://claude-code}" ;;
        esac
        exit 0 ;;
      event|start|close|report) exit 0 ;;
    esac
    ;;
esac
exit 0
