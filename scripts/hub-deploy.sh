#!/usr/bin/env bash
# Deploy the hub to Railway with a real commit in /v1/version.
#
# `railway up` uploads the working tree without .git, so the Dockerfile's
# RAILWAY_GIT_COMMIT_SHA fallback is empty and /v1/version reported
# commit "unknown" (0.31.11 re-test, N-34). Railway passes service variables
# into the Docker build as ARGs the Dockerfile declares, so this sets the
# build info on the service first, then uploads.
#
#   RAILWAY_SERVICE=<service id> [RAILWAY_ENVIRONMENT=production] scripts/hub-deploy.sh
#
# Requires the Railway CLI, logged in and linked to the project
# (`railway link`). Run from a clean checkout of the commit being deployed.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

SERVICE="${RAILWAY_SERVICE:?set RAILWAY_SERVICE to the hub service id}"
ENVIRONMENT="${RAILWAY_ENVIRONMENT:-production}"

if [ -n "$(git status --porcelain -- packages/hub)" ]; then
  echo "packages/hub has uncommitted changes; deploy a commit, not a working tree" >&2
  exit 1
fi

COMMIT="$(git rev-parse --short HEAD)"
BUILT_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
VERSION="$(sed -n 's/^const Release = "\(.*\)"$/\1/p' packages/hub/internal/version/version.go)"
if [ -z "$VERSION" ]; then
  echo "could not read the Release constant from packages/hub/internal/version/version.go" >&2
  exit 1
fi

echo "hub ${VERSION} @ ${COMMIT} (${BUILT_AT}) -> service ${SERVICE}, environment ${ENVIRONMENT}"
railway variables --service "$SERVICE" --environment "$ENVIRONMENT" \
  --set "HUB_VERSION=${VERSION}" \
  --set "HUB_COMMIT=${COMMIT}" \
  --set "HUB_BUILT_AT=${BUILT_AT}" \
  --skip-deploys
railway up . --path-as-root --service "$SERVICE" --environment "$ENVIRONMENT" --detach
echo
echo "when the deploy is live, check: curl -s https://api.treeship.dev/v1/version"
