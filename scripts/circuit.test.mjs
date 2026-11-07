// Tests the circuit against the real Go signer and verifier, so a mismatch
// between Go, JavaScript and Circom fails here rather than on stage.
import { after, test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { writeFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import * as snarkjs from 'snarkjs';
import {
  buildInput,
  buildRevocationTree,
  checkIssuer,
  checkQuestion,
  credentialHash,
  holderCommit,
  nonMembershipWitness,
  randomField,
  revocationHandle,
  scopeOf,
} from '../frontend/src/lib/core.ts';

const WASM = 'build/circuit/presentation_js/presentation.wasm';
const ZKEY = 'build/circuit/presentation_final.zkey';
const VKEY = 'build/circuit/verification_key.json';
const DEVSIGN = 'bin/devsign';

// snarkjs leaves worker threads running, which would keep the process alive.
after(async () => {
  await globalThis.curve_bn128?.terminate();
});

const go = (...args) => execFileSync(DEVSIGN, args, { encoding: 'utf8' }).trim();

// Random keys that are guaranteed to fit the demo-sized tree. Two keys sharing
// their low 19 path bits can't be separated within 20 levels, which fully random
// keys would hit about once in 670 runs for a set of 40.
function randomKeys(count) {
  const paths = new Set();
  const keys = [];
  while (keys.length < count) {
    const key = randomField();
    const path = key & ((1n << 19n) - 1n);
    if (!paths.has(path)) {
      paths.add(path);
      keys.push(key.toString());
    }
  }
  return keys;
}

const TODAY = 20261106;
const ORIGIN = 'http://localhost:8083';

function makeCredential({ dob = 19900101, isUtah = true, expiry = 20271106 } = {}) {
  const holderSecret = randomField().toString();
  const revToken = randomField().toString();
  const hash = credentialHash(dob, isUtah, expiry, holderSecret, revToken);
  const signed = JSON.parse(go('sign', hash));
  return {
    name: 'Test Holder',
    dob,
    isUtah,
    expiry,
    holderSecret,
    revToken,
    sig: { r8x: signed.r8x, r8y: signed.r8y, s: signed.s },
    issuerAx: signed.ax,
    issuerAy: signed.ay,
    standard: { claims: [], leaves: [], sig: { r8x: '0', r8y: '0', s: '0' } },
  };
}

function snapshotOf(revoked) {
  return { epoch: 1, revoked, root: buildRevocationTree(revoked).hash.toString(), publishedAt: '' };
}

function request(minAge = 18, requireUtah = false, wantPseudonym = false) {
  return { nonce: '12345', cutoffDate: TODAY - minAge * 10000, today: TODAY, requireUtah, minAge, siteTitle: 'Test', wantPseudonym };
}

async function input(cred, req = request(), snapshot = snapshotOf([])) {
  const built = await buildInput(cred, req, ORIGIN, snapshot);
  assert.equal(built.problem, null);
  return built.input;
}

async function rejects(inp) {
  await assert.rejects(() => snarkjs.wtns.calculate(inp, WASM, { type: 'mem' }));
}

// --- Go and JavaScript must agree before anything else can work.

test('Poseidon matches between Go and JS', () => {
  assert.equal(holderCommit('42'), go('poseidon', '42'));
  assert.equal(
    credentialHash(19900101, true, 20271106, '7', '9'),
    go('poseidon', '19900101', '1', '20271106', holderCommit('7'), revocationHandle('9')),
  );
});

test('site scope matches between Go and JS', async () => {
  assert.equal(await scopeOf(ORIGIN), go('scope', ORIGIN));
});

test('revocation tree roots match between Go and JS', () => {
  const sets = [
    [],
    ['5'],
    ['5', '6'],
    ['1', '3', '5', '7', '9', '11', '13'], // share low bits, forcing deep paths
    ['1', String(1n + (1n << 18n))], // the deepest split the tree allows
    randomKeys(40),
  ];
  for (const keys of sets) {
    assert.equal(buildRevocationTree(keys).hash.toString(), go('smt', ...keys), `set of ${keys.length}`);
  }
});

test('Go and JS both refuse a tree too deep for the circuit', () => {
  const keys = ['1', String(1n + (1n << 19n))]; // share their low 19 path bits
  assert.throws(() => buildRevocationTree(keys), /depth exceeded/);
  assert.throws(() => execFileSync(DEVSIGN, ['smt', ...keys], { stdio: 'pipe' }), /depth exceeded/);
});

test('revocation root does not depend on insertion order', () => {
  const keys = randomKeys(12);
  const shuffled = [...keys].reverse();
  assert.equal(buildRevocationTree(keys).hash, buildRevocationTree(shuffled).hash);
});

// --- Valid proofs.

test('a valid proof verifies in both snarkjs and the Go verifier', async () => {
  const inp = await input(makeCredential());
  const start = performance.now();
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(inp, WASM, ZKEY);
  console.log(`      proving took ${Math.round(performance.now() - start)} ms in Node`);

  const vkey = JSON.parse((await import('node:fs')).readFileSync(VKEY, 'utf8'));
  assert.equal(await snarkjs.groth16.verify(vkey, publicSignals, proof), true);

  const dir = mkdtempSync(join(tmpdir(), 'unlinked-'));
  const file = join(dir, 'presentation.json');
  writeFileSync(file, JSON.stringify({ proof, publicSignals }));
  assert.equal(go('verify', file, VKEY), 'valid');

  // Public signal order must match backend/internal/core PublicSignalNames.
  assert.deepEqual(publicSignals, [
    '0', inp.issuerAx, inp.issuerAy, inp.cutoffDate, inp.today, inp.requireUtah, inp.revRoot, inp.scope, inp.nonce, '0',
  ]);

  // Tampering with any public signal must break the proof in Go too.
  for (let index = 0; index < publicSignals.length; index++) {
    const tampered = [...publicSignals];
    tampered[index] = String(BigInt(tampered[index]) + 1n);
    writeFileSync(file, JSON.stringify({ proof, publicSignals: tampered }));
    assert.throws(() => go('verify', file, VKEY), undefined, `signal ${index} should be bound`);
  }
});

test('the witness is valid with empty, single-entry and populated revocation lists', async () => {
  const lists = [
    [],
    [randomField().toString()],
    randomKeys(25),
  ];
  for (const revoked of lists) {
    const inp = await input(makeCredential(), request(), snapshotOf(revoked));
    await snarkjs.wtns.calculate(inp, WASM, { type: 'mem' });
  }
});

test('someone exactly 18 today passes, and one day younger fails', async () => {
  await snarkjs.wtns.calculate(await input(makeCredential({ dob: TODAY - 180000 })), WASM, { type: 'mem' });
  const inp = await input(makeCredential({ dob: TODAY - 180000 }));
  inp.cutoffDate = String(TODAY - 180000 - 1);
  await rejects(inp);
});

// --- Every attack must fail inside the circuit, not just in wallet code.

test('rejects an underage holder', async () => {
  const inp = await input(makeCredential({ dob: 19900101 }));
  inp.cutoffDate = '19800101';
  await rejects(inp);
});

test('rejects a holder who lies about their birth date', async () => {
  const inp = await input(makeCredential({ dob: 20100101 }), { ...request(), cutoffDate: 20200101 });
  inp.dob = '19900101';
  inp.cutoffDate = String(TODAY - 180000);
  await rejects(inp);
});

test('rejects an expired credential', async () => {
  const inp = await input(makeCredential({ expiry: 20271106 }));
  inp.today = '20280101';
  await rejects(inp);
});

test('rejects a forged issuer signature', async () => {
  const cred = makeCredential();
  const inp = await input(cred);
  inp.sigS = String(BigInt(inp.sigS) + 1n);
  await rejects(inp);
});

test('rejects a credential signed by a different issuer key', async () => {
  const inp = await input(makeCredential());
  inp.issuerAx = '5299619240641551281634865583518297030282874472190772894086521144482721001553';
  inp.issuerAy = '16950150798460657717958625567821834550301663161624707787222815936182638968203';
  await rejects(inp);
});

test('rejects a wrong holder secret', async () => {
  const inp = await input(makeCredential());
  inp.holderSecret = randomField().toString();
  await rejects(inp);
});

test('rejects a non-resident when residency is required', async () => {
  const inp = await input(makeCredential({ isUtah: false }));
  inp.requireUtah = '1';
  await rejects(inp);
});

test('allows a non-resident when residency is not required', async () => {
  const inp = await input(makeCredential({ isUtah: false }));
  await snarkjs.wtns.calculate(inp, WASM, { type: 'mem' });
});

test('rejects a revoked credential, even with a forged witness', async () => {
  const cred = makeCredential();
  const others = randomKeys(6);
  const handle = revocationHandle(cred.revToken);
  const revoked = [...others, handle];
  const tree = buildRevocationTree(revoked);

  assert.equal(nonMembershipWitness(tree, BigInt(handle)), null);

  // Build a witness against the clean list, then point it at the list that
  // contains this credential. The root no longer matches, so it must fail.
  const inp = await input(cred, request(), snapshotOf(others));
  inp.revRoot = tree.hash.toString();
  await rejects(inp);

  // The wallet also refuses before attempting a proof.
  const built = await buildInput(cred, request(), ORIGIN, snapshotOf(revoked));
  assert.match(built.problem, /revoked/);
});

// --- Per-site pseudonyms.

async function pseudonymOf(cred, origin, want = true) {
  const built = await buildInput(cred, request(18, false, want), origin, snapshotOf([]));
  const { publicSignals } = await snarkjs.groth16.fullProve(built.input, WASM, ZKEY);
  return publicSignals[0];
}

test('plain age checks carry no pseudonym, so they stay boolean-only', async () => {
  assert.equal(await pseudonymOf(makeCredential(), ORIGIN, false), '0');
});

test('a pseudonym is stable at one site and different at another', async () => {
  const cred = makeCredential();
  const first = await pseudonymOf(cred, ORIGIN);
  assert.notEqual(first, '0');
  assert.equal(await pseudonymOf(cred, ORIGIN), first);
  assert.notEqual(await pseudonymOf(cred, 'http://localhost:8084'), first);
});

test('two holders get different pseudonyms at the same site', async () => {
  assert.notEqual(await pseudonymOf(makeCredential(), ORIGIN), await pseudonymOf(makeCredential(), ORIGIN));
});

test('a pseudonym needs the holder secret, which the state only saw hashed', async () => {
  const cred = makeCredential();
  const scope = await scopeOf(ORIGIN);
  assert.equal(await pseudonymOf(cred, ORIGIN), go('poseidon', cred.holderSecret, scope));
  assert.notEqual(await pseudonymOf(cred, ORIGIN), go('poseidon', holderCommit(cred.holderSecret), scope));
});

// --- Wallet policy.

test('wallet refuses a credential signed with an unpublished issuer key', () => {
  const published = { ax: '1', ay: '2' };
  assert.equal(checkIssuer({ issuerAx: '1', issuerAy: '2' }, published), null);
  assert.match(checkIssuer({ issuerAx: '9', issuerAy: '2' }, published), /tag you/);
});

test('wallet refuses non-standard age questions', () => {
  const now = new Date(Date.UTC(2026, 10, 6));
  assert.equal(checkQuestion({ today: TODAY, cutoffDate: TODAY - 180000 }, now), null);
  assert.equal(checkQuestion({ today: TODAY, cutoffDate: TODAY - 210000 }, now), null);
  assert.match(checkQuestion({ today: TODAY, cutoffDate: 19750101 }, now), /16 questions/);
  assert.match(checkQuestion({ today: 20200101, cutoffDate: 20020101 }, now), /different day/);
});
