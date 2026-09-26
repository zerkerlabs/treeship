#!/usr/bin/env bash
# CLI-3 / CLI-18: room_two_ships, then a second ship that pinned the host
# verifies the package under --strict.
# xfail: W1-13 the invitation, participant and liveness record are sealed unchained
# xfail-match: FAIL chain_completeness
STRICT_STRANGER=1 . "$(dirname "$0")/room_two_ships.sh"
