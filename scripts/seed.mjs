// Creates a crowd of synthetic holders through the real HTTP APIs, so the attack
// console has something to search through. Each holder gets a real credential,
// real proofs, and real verifier checks. No log data is faked.
import * as snarkjs from 'snarkjs';
import {
  buildInput,
  holderCommit,
  randomField,
  standardPresentation,
} from '../frontend/src/lib/core.ts';

const HOLDERS = Number(process.argv[2] ?? 30);
const PARALLEL = 4;
const WASM = 'build/circuit/presentation_js/presentation.wasm';
const ZKEY = 'build/circuit/presentation_final.zkey';

const STATE = 'http://localhost:8081';
const MIRROR = 'http://localhost:8082';
const SITES = ['http://localhost:8083', 'http://localhost:8084'];

async function postJson(url, body) {
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  const out = await res.json();
  if (!res.ok) throw new Error(`${url}: ${out.error ?? res.statusText}`);
  return out;
}

const getJson = async (url) => (await fetch(url, { cache: 'no-store' })).json();

function randomBirthDate() {
  const year = 1950 + Math.floor(Math.random() * 50);
  const month = 1 + Math.floor(Math.random() * 12);
  const day = 1 + Math.floor(Math.random() * 28);
  return year * 10000 + month * 100 + day;
}

async function submit(site, mode, nonce, presentation) {
  const result = await postJson(`${site}/api/verify`, { mode, nonce, presentation });
  if (!result.ok) throw new Error(`${site} rejected a ${mode} presentation: ${result.reason}`);
}

async function presentZk(cred, site, query = '') {
  const snapshot = await getJson(`${MIRROR}/revocation.json`);
  const request = await getJson(`${site}/api/request${query}`);
  const built = await buildInput(cred, request, site, snapshot);
  if (built.problem) throw new Error(`${cred.name}: ${built.problem}`);
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(built.input, WASM, ZKEY);
  await submit(site, 'zk', request.nonce, { proof, publicSignals });
}

async function runHolder(index) {
  const name = `Synthetic Holder ${String(index).padStart(2, '0')}`;
  const holderSecret = randomField().toString();
  const issued = await postJson(`${STATE}/issue`, {
    name,
    dob: randomBirthDate(),
    isUtah: true,
    holderCommit: holderCommit(holderSecret),
  });
  const cred = { ...issued, name, holderSecret };

  for (const site of SITES) {
    await presentZk(cred, site);
    // Every third holder also opens an account, so the attack has pseudonyms to try.
    if (index % 3 === 0) await presentZk(cred, site, '?account=1');

    const stdRequest = await getJson(`${site}/api/request`);
    await submit(site, 'standard', stdRequest.nonce, standardPresentation(cred, stdRequest));
  }
}

const started = Date.now();
let next = 1;
let done = 0;
await Promise.all(
  Array.from({ length: PARALLEL }, async () => {
    while (next <= HOLDERS) {
      const index = next++;
      await runHolder(index);
      done++;
      if (done % 5 === 0) console.log(`  ${done}/${HOLDERS} holders`);
    }
  }),
);
console.log(`Seeded ${HOLDERS} holders in ${Math.round((Date.now() - started) / 1000)}s`);
await globalThis.curve_bn128?.terminate();
process.exit(0);
