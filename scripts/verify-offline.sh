#!/usr/bin/env bash
# Verifies the latest accepted proof inside an empty network namespace, where no
# packet can leave the process. unshare is Linux-only, so other systems run the
# same verifier without that isolation.
set -euo pipefail
cd "$(dirname "$0")/.."

if [ ! -x bin/verify ] || [ ! -f data/site-a/last-presentation.json ]; then
  echo "No proof to check yet. Run 'make demo', and wait for 'Ready.' first." >&2
  exit 1
fi

CMD=(bin/verify --proof data/site-a/last-presentation.json --mirror data/mirror --origin http://localhost:8083)

if ! command -v unshare >/dev/null; then
  echo "unshare isn't available here, so this run isn't network-isolated. Turn off your network to show the same result."
  exec "${CMD[@]}"
fi
if unshare -rn true 2>/dev/null; then
  exec unshare -rn "${CMD[@]}"
fi
echo "This system blocks unprivileged network namespaces, so unshare needs sudo."
exec sudo unshare -n "${CMD[@]}"
