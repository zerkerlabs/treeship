#!/bin/sh
# Mock `treeship` binary used by integration parity tests.
if [ -n "${MOCK_TREESHIP_LOG:-}" ]; then
  printf '%s\n' "$*" >> "$MOCK_TREESHIP_LOG"
fi
case "$1" in
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
