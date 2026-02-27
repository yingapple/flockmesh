#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${ROOT_DIR}/docs/ui"

mkdir -p "${OUT_DIR}"

node "${ROOT_DIR}/src/server.js" >/tmp/flockmesh-ui-capture.log 2>&1 &
SERVER_PID=$!
cleanup() {
  kill "${SERVER_PID}" 2>/dev/null || true
}
trap cleanup EXIT

sleep 2

npx --yes playwright screenshot \
  --browser=chromium \
  --wait-for-timeout=1400 \
  --viewport-size="1440,900" \
  "http://127.0.0.1:8080" \
  "${OUT_DIR}/control-plane-hero.png"

npx --yes playwright screenshot \
  --browser=chromium \
  --wait-for-timeout=1800 \
  --viewport-size="1440,900" \
  --full-page \
  "http://127.0.0.1:8080" \
  "${OUT_DIR}/control-plane-overview.png"

npx --yes playwright screenshot \
  --browser=chromium \
  --wait-for-timeout=1800 \
  --viewport-size="390,844" \
  --full-page \
  "http://127.0.0.1:8080" \
  "${OUT_DIR}/control-plane-mobile.png"

echo "UI screenshots written to ${OUT_DIR}"
