#!/usr/bin/env bash
# Stops early with a clear message when something the demo needs is missing.
# Usage: check-prereqs.sh setup|demo
set -uo pipefail
cd "$(dirname "$0")/.."

stage="${1:-demo}"
problems=0

fail() {
  echo "  - $1" >&2
  problems=1
}

if ! command -v node >/dev/null; then
  fail "Node.js 22.18 or newer is required. Get it from https://nodejs.org"
elif ! node -e '
  const [major, minor] = process.versions.node.split(".").map(Number);
  process.exit((major === 22 && minor >= 18) || (major === 23 && minor >= 6) || major >= 24 ? 0 : 1);
'; then
  fail "Node.js 22.18 or newer is required, and you have $(node --version). Get it from https://nodejs.org"
fi

if ! command -v go >/dev/null; then
  fail "Go 1.21 or newer is required. Get it from https://go.dev/dl"
elif ! (cd backend && go list -m >/dev/null 2>&1); then
  fail "Go could not load the Go 1.26 toolchain this project needs. Install Go 1.26 from https://go.dev/dl, or unset GOTOOLCHAIN=local so Go can download it."
fi

if ! command -v curl >/dev/null; then
  fail "curl is required."
fi

if [ ! -d node_modules/snarkjs ] || [ ! -d node_modules/.bin ]; then
  fail "Packages are not installed. Run: make install"
elif [ "$stage" = "demo" ]; then
  if [ ! -f build/circuit/verification_key.json ] || [ ! -f frontend/public/zk/presentation_final.zkey ]; then
    fail "The circuit is not set up yet. Run: make setup"
  fi
fi

if [ "$problems" -ne 0 ]; then
  echo "Fix the above, then try again." >&2
  exit 1
fi
