#!/usr/bin/env bash
# Compiles the circuit and runs the Groth16 setup.
#
# Phase 1 is PSE's public Perpetual Powers of Tau file. Phase 2 is per-circuit
# and has three contributors, simulated here on one machine. A corrupted setup
# could allow forged proofs, and it stays safe if any one contributor is honest,
# so a real deployment must run these on independent machines and not let the
# state run them alone.
set -euo pipefail
cd "$(dirname "$0")/.."

SNARKJS="node node_modules/snarkjs/build/cli.cjs"
PTAU=build/ptau/pot15.ptau
OUT=build/circuit
entropy() { node -e "process.stdout.write(require('crypto').randomBytes(48).toString('base64'))"; }
mkdir -p "$OUT" data/mirror frontend/public/zk

if [ ! -f "$PTAU" ]; then
  mkdir -p build/ptau
  curl -sS -o "$PTAU" https://pse-trusted-setup-ppot.s3.eu-central-1.amazonaws.com/pot28_0080/ppot_0080_15.ptau
fi

echo "==> Compiling circuit"
node node_modules/circom2/cli.js circuits/presentation.circom --r1cs --wasm --sym -o "$OUT" -l node_modules
$SNARKJS r1cs info "$OUT/presentation.r1cs"

echo "==> Phase 2: three contributors"
$SNARKJS groth16 setup "$OUT/presentation.r1cs" "$PTAU" "$OUT/p0.zkey" > /dev/null
$SNARKJS zkey contribute "$OUT/p0.zkey" "$OUT/p1.zkey" --name="Contributor A" -e="$(entropy)" > /dev/null
$SNARKJS zkey contribute "$OUT/p1.zkey" "$OUT/p2.zkey" --name="Contributor B" -e="$(entropy)" > /dev/null
$SNARKJS zkey contribute "$OUT/p2.zkey" "$OUT/presentation_final.zkey" --name="Contributor C" -e="$(entropy)" > /dev/null

echo "==> Verifying the setup transcript"
$SNARKJS zkey verify "$OUT/presentation.r1cs" "$PTAU" "$OUT/presentation_final.zkey" | tail -4
$SNARKJS zkey export verificationkey "$OUT/presentation_final.zkey" "$OUT/verification_key.json"
rm -f "$OUT"/p0.zkey "$OUT"/p1.zkey "$OUT"/p2.zkey

echo "==> Publishing artifacts"
cp "$OUT/presentation_js/presentation.wasm" "$OUT/presentation_final.zkey" frontend/public/zk/
cp node_modules/snarkjs/build/snarkjs.min.js frontend/public/zk/
cp "$OUT/verification_key.json" data/mirror/verification_key.json
ls -la frontend/public/zk "$OUT/verification_key.json"
echo "==> Setup complete"
