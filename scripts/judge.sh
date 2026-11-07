#!/usr/bin/env bash
# Checks a skeptical judge can run while the demo is running. Each one tests a
# specific suspicion about the demo, using standard tools wherever possible, so
# the judge doesn't have to take this project's own code on trust.
set -uo pipefail
cd "$(dirname "$0")/.."

STATE=http://localhost:8081
SITE_A=http://localhost:8083
SITE_B=http://localhost:8084
SNARKJS="node node_modules/snarkjs/build/cli.cjs"
KIT=judge-kit

require_demo() {
  if ! curl -fsS -o /dev/null --max-time 3 "$SITE_A/api/log"; then
    echo "The demo isn't running. Start it with 'make demo' in another terminal and wait for 'Ready.'" >&2
    exit 1
  fi
}

stop_role() {
  local file="data/pids/$1.pid"
  [ -f "$file" ] || return 0
  local pid
  pid="$(cat "$file")"
  if ps -p "$pid" -o command= 2>/dev/null | grep -q 'unlinked --role'; then
    kill "$pid" 2>/dev/null
  fi
  rm -f "$file"
}

# Runs a command with no network if this system allows it.
no_network() {
  if command -v unshare >/dev/null && unshare -rn true 2>/dev/null; then
    unshare -rn "$@"
  else
    "$@"
  fi
}

# Suspicion: "The servers keep what I typed and look it up later."
# Searches everything the servers hold for a value only the judge knows.
search() {
  local text="${1:-}"
  if [ -z "$text" ]; then
    echo 'Usage: make search TEXT="a made-up name, or a birth date like 1987-02-14"' >&2
    exit 1
  fi
  require_demo

  # The credential stores birth dates as YYYYMMDD, so search for both spellings.
  local compact="${text//-/}"
  count() { # counts matches on stdin for either spelling
    { grep -aoF -e "$text" -e "$compact" || true; } | wc -l | tr -d ' '
  }

  plural() { # "1 match" or "N matches"
    if [ "$1" = "1" ]; then echo "1 match"; else echo "$1 matches"; fi
  }

  echo "Searching every server for: $text"
  printf '  %-34s %s\n' "Pinecrest Apps log" "$(plural "$(curl -fsS "$SITE_A/api/log" | count)")"
  printf '  %-34s %s\n' "Red Rock Cellar log" "$(plural "$(curl -fsS "$SITE_B/api/log" | count)")"
  printf '  %-34s %s\n' "Public mirror files" "$(plural "$(cat data/mirror/* 2>/dev/null | count)")"
  printf '  %-34s %s\n' "Other server files and logs" "$(plural "$(cat data/site-a/* data/site-b/* data/state/* data/trustee/* logs/* 2>/dev/null | count)")"
  local summary
  if summary="$(curl -fsS --max-time 3 "$STATE/debug/summary" 2>/dev/null)"; then
    printf '  %-34s %s\n' "State's records" "$(plural "$(printf '%s' "$summary" | count)")"
  else
    printf '  %-34s %s\n' "State's records" "state is offline"
  fi
  echo
  echo "Expected: 0 everywhere, except that your NAME appears in the state's records"
  echo "beside your encrypted token. That's the escrow, and it also shows this search"
  echo "works. A birth date should appear nowhere: the state sees it once and keeps no copy."
}

# Suspicion: "Verification only works because your servers remember me."
kill_state() {
  stop_role state
  stop_role trustee
  echo "The state and the trustee are stopped. Check for yourself:"
  curl -fsS --max-time 2 -o /dev/null "$STATE/debug/summary" 2>&1 | sed 's/^/  /' || true
  echo "Now verify on Pinecrest Apps. Your wallet and the site don't need either of them."
}

fresh_site() {
  stop_role site-a
  rm -f data/site-a/last-presentation.json
  # Give the port a moment to close.
  sleep 0.3
  nohup bin/unlinked --role=site-a > logs/site-a.log 2>&1 &
  echo "$!" > data/pids/site-a.pid
  disown
  for _ in $(seq 1 25); do
    if curl -fsS -o /dev/null --max-time 1 "$SITE_A/config.json"; then break; fi
    sleep 0.2
  done
  # The site loads the public keys from the mirror once a second.
  sleep 1.2
  echo "Pinecrest Apps restarted with empty memory. It now holds:"
  curl -fsS "$SITE_A/api/log" | node -e "
    let raw = ''; process.stdin.on('data', (d) => (raw += d)).on('end', () => {
      console.log('  ' + JSON.parse(raw).entries.length + ' log entries');
    });"
  echo "Reload the page and verify. A process that has never seen you will check your proof."
}

# Suspicion: "The verifier just says yes."
# Verifies with snarkjs, not this project's Go code, using only three public files.
check_proof() {
  local source="data/site-a/last-presentation.json"
  if [ ! -f "$source" ]; then
    echo "No proof yet. Verify on Pinecrest Apps first." >&2
    exit 1
  fi
  mkdir -p "$KIT"
  cp data/mirror/verification_key.json "$KIT/verification_key.json"
  node -e '
    const fs = require("fs");
    const { proof, publicSignals } = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
    fs.writeFileSync(process.argv[2] + "/proof.json", JSON.stringify(proof, null, 2));
    fs.writeFileSync(process.argv[2] + "/public.json", JSON.stringify(publicSignals, null, 2));
  ' "$source" "$KIT"

  local names=(pseudonym issuerAx issuerAy cutoffDate today requireUtah revRoot scope nonce wantPseudonym)
  echo "Everything the verifier gets besides the opaque proof, from $KIT/public.json:"
  node -e '
    const names = process.argv.slice(1);
    const values = JSON.parse(require("fs").readFileSync("'"$KIT"'/public.json", "utf8"));
    values.forEach((v, i) => console.log("  " + names[i].padEnd(14) + (v.length > 24 ? v.slice(0, 10) + "…" + v.slice(-10) : v)));
  ' "${names[@]}"
  echo

  verify_kit() { # verify_kit <public file>
    no_network $SNARKJS groth16 verify "$KIT/verification_key.json" "$1" "$KIT/proof.json" 2>&1 \
      | grep -oE 'OK!|Invalid proof' | head -1
  }

  echo "Verifying with snarkjs and no network:"
  printf '  %-44s %s\n' "The proof as issued" "$(verify_kit "$KIT/public.json")"

  # Index 3 is cutoffDate, 7 is scope, 8 is nonce.
  tamper() { # tamper <index> <new value> <label>
    node -e '
      const fs = require("fs");
      const values = JSON.parse(fs.readFileSync(process.argv[1] + "/public.json", "utf8"));
      values[Number(process.argv[2])] = process.argv[3];
      fs.writeFileSync(process.argv[1] + "/tampered.json", JSON.stringify(values));
    ' "$KIT" "$1" "$2"
    printf '  %-44s %s\n' "$3" "$(verify_kit "$KIT/tampered.json")"
  }
  tamper 3 19800101 "Change the question to \"born before 1980\""
  tamper 7 12345 "Say it was made for a different site"
  tamper 8 12345 "Say it was made for a different request"
  rm -f "$KIT/tampered.json"

  echo
  echo "Expected: OK! once, then Invalid proof three times."
  echo "To check it on your own laptop, with none of this project's code, copy the"
  echo "$KIT folder there and run:"
  echo "  cd $KIT && npx snarkjs@0.7.6 groth16 verify verification_key.json public.json proof.json"
}

# Suspicion: "You ran the setup, so you could forge proofs for anyone."
# A forged proof needs every contributor's secret, so one honest contributor is enough.
contribute() {
  local r1cs=build/circuit/presentation.r1cs
  local ptau=build/ptau/pot15.ptau
  local zkey=build/circuit/presentation_final.zkey
  if curl -fsS -o /dev/null --max-time 2 "$SITE_A/config.json" 2>/dev/null; then
    echo "Stop the demo first with 'make stop', because sites pin the old key while they run." >&2
    exit 1
  fi
  local typed="${ENTROPY:-}"
  if [ -z "$typed" ]; then
    read -r -s -p "Mash the keyboard, then press Enter (this isn't saved or shown): " typed
    echo
  fi
  local mixed
  mixed="$typed$(node -e "process.stdout.write(require('crypto').randomBytes(48).toString('base64'))")"
  $SNARKJS zkey contribute "$zkey" "$zkey.next" --name="Judge" -e="$mixed" > /dev/null || exit 1
  unset typed mixed
  echo "Checking the whole setup against the circuit and the public setup file:"
  if ! $SNARKJS zkey verify "$r1cs" "$ptau" "$zkey.next" > "$zkey.log" 2>&1; then
    rm -f "$zkey.next"
    echo "The new key failed verification, so it was discarded." >&2
    tail -5 "$zkey.log" >&2
    exit 1
  fi
  sed -E 's/\x1b\[[0-9;]*m//g' "$zkey.log" | grep -E 'contribution #|ZKey Ok' | sed -E 's/\[INFO\] +snarkJS: /  /'
  mv "$zkey.next" "$zkey"
  rm -f "$zkey.log"
  $SNARKJS zkey export verificationkey "$zkey" build/circuit/verification_key.json > /dev/null
  cp "$zkey" frontend/public/zk/
  cp build/circuit/verification_key.json data/mirror/verification_key.json
  echo "Your randomness is now part of the keys. Unless you share it, nobody can forge a proof."
  echo "Run 'make demo' to continue with the new keys."
}

case "${1:-}" in
  search) search "${2:-}" ;;
  kill-state) kill_state ;;
  fresh-site) fresh_site ;;
  check-proof) check_proof ;;
  contribute) contribute ;;
  *)
    echo "Usage: judge.sh search|kill-state|fresh-site|check-proof|contribute" >&2
    exit 1
    ;;
esac
