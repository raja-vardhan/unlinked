#!/usr/bin/env bash
# Starts every role as its own process, then seeds the crowd of synthetic holders.
set -euo pipefail
cd "$(dirname "$0")/.."

for port in 8080 8081 8082 8083 8084 8085 8086; do
  if (exec 3<>"/dev/tcp/localhost/$port") 2>/dev/null; then
    echo "Port $port is already in use. Is another copy of the demo running?" >&2
    exit 1
  fi
done

mkdir -p data/mirror logs
cp build/circuit/verification_key.json data/mirror/verification_key.json
# Sites check the mirror's revocation list against the issuer, so start clean.
rm -f data/mirror/revocation.json data/mirror/issuer.json

pids=()
cleanup() {
  kill "${pids[@]}" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

start() {
  bin/unlinked --role="$1" > "logs/$1.log" 2>&1 &
  pids+=("$!")
}

start trustee
start mirror
start state
start wallet
start site-a
start site-b
start console

wait_for() {
  for _ in $(seq 1 50); do
    if curl -fsS -o /dev/null "$1"; then return 0; fi
    sleep 0.2
  done
  echo "Timed out waiting for $1" >&2
  exit 1
}

wait_for http://localhost:8085/pubkey
wait_for http://localhost:8082/revocation.json
wait_for http://localhost:8083/config.json
wait_for http://localhost:8084/config.json
wait_for http://localhost:8086/config.json
# Sites poll the mirror once a second; let them load it before seeding.
sleep 1.5

echo "Seeding synthetic holders…"
node --disable-warning=ExperimentalWarning scripts/seed.mjs "${HOLDERS:-30}"

cat <<EOF

Ready.
  Wallet           http://localhost:8080
  Pinecrest Apps   http://localhost:8083  (18+)
  Red Rock Cellar  http://localhost:8084  (21+, Utah)
  Attacker console http://localhost:8086

Press Ctrl+C to stop.
EOF
wait
