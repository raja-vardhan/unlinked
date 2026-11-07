// Wallet-side cryptography. Must stay byte-compatible with
// backend/internal/core/core.go and circuits/presentation.circom.
// Uses only erasable TypeScript so the Node seed script and tests can import it directly.
import { poseidon1, poseidon2, poseidon3, poseidon5 } from 'poseidon-lite';

export const REV_LEVELS = 20;

export type Sig = { r8x: string; r8y: string; s: string };

export type StandardClaim = { name: string; value: string; salt: string };

// What a conventional selective-disclosure credential looks like: salted claim
// hashes under one signature, modelled on ISO mdoc and SD-JWT.
export type StandardCredential = { claims: StandardClaim[]; leaves: string[]; sig: Sig };

export type Credential = {
  name: string;
  dob: number;
  isUtah: boolean;
  expiry: number;
  holderSecret: string;
  revToken: string;
  sig: Sig;
  issuerAx: string;
  issuerAy: string;
  standard: StandardCredential;
};

export type ProofRequest = {
  nonce: string;
  cutoffDate: number;
  today: number;
  requireUtah: boolean;
  minAge: number;
  siteTitle: string;
  wantPseudonym: boolean;
};

export type IssuerKey = { ax: string; ay: string };

export type Snapshot = {
  epoch: number;
  revoked: string[];
  root: string;
  publishedAt: string;
};

export function randomField(): bigint {
  const bytes = crypto.getRandomValues(new Uint8Array(31));
  return BigInt('0x' + [...bytes].map((b) => b.toString(16).padStart(2, '0')).join(''));
}

export function holderCommit(holderSecret: string): string {
  return poseidon1([BigInt(holderSecret)]).toString();
}

export function revocationHandle(revToken: string): string {
  return poseidon1([BigInt(revToken)]).toString();
}

export async function scopeOf(origin: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(origin));
  const hex = [...new Uint8Array(digest)]
    .slice(0, 31)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
  return BigInt('0x' + hex).toString();
}

export function dateInt(d: Date): number {
  return d.getUTCFullYear() * 10000 + (d.getUTCMonth() + 1) * 100 + d.getUTCDate();
}

const DAY_MS = 86_400_000;
const ALLOWED_AGES = [18, 21];

// Refuses any age question other than the standard policies. Without this, a
// site could change the cutoff on each request and binary-search a birth date
// in about 16 questions, even though every individual answer is only yes or no.
export function checkQuestion(
  req: Pick<ProofRequest, 'cutoffDate' | 'today'>,
  now: Date = new Date(),
): string | null {
  const days = [-1, 0, 1].map((offset) => dateInt(new Date(now.getTime() + offset * DAY_MS)));
  if (!days.includes(req.today)) {
    return 'The request is dated for a different day than this device.';
  }
  const allowed = ALLOWED_AGES.some((age) => req.cutoffDate === req.today - age * 10000);
  if (!allowed) {
    return `Cutoff ${req.cutoffDate} is not a standard ${ALLOWED_AGES.join(' or ')}+ check. Answering arbitrary cutoffs would let a site find your birth date in about 16 questions.`;
  }
  return null;
}

// The issuer key is a public signal, so a cheating state could tag someone by
// issuing them a key of their own: every site would then see a per-person value.
// Wallets only use a key that matches the one published for everybody.
export function checkIssuer(cred: Pick<Credential, 'issuerAx' | 'issuerAy'>, published: IssuerKey): string | null {
  return cred.issuerAx === published.ax && cred.issuerAy === published.ay
    ? null
    : 'This credential was signed with a key that differs from the published issuer key, which could be used to tag you.';
}

type TreeNode =
  | { kind: 'empty'; hash: bigint }
  | { kind: 'leaf'; key: bigint; hash: bigint }
  | { kind: 'mid'; left: TreeNode; right: TreeNode; hash: bigint };

const EMPTY: TreeNode = { kind: 'empty', hash: 0n };

function bit(key: bigint, depth: number): bigint {
  return (key >> BigInt(depth)) & 1n;
}

function subtree(keys: bigint[], depth: number): TreeNode {
  if (keys.length === 0) return EMPTY;
  if (keys.length === 1) {
    return { kind: 'leaf', key: keys[0], hash: poseidon3([keys[0], 1n, 1n]) };
  }
  if (depth >= REV_LEVELS - 1) throw new Error('revocation tree depth exceeded');
  const left = subtree(keys.filter((k) => bit(k, depth) === 0n), depth + 1);
  const right = subtree(keys.filter((k) => bit(k, depth) === 1n), depth + 1);
  return { kind: 'mid', left, right, hash: poseidon2([left.hash, right.hash]) };
}

// Same tree as RevocationRoot in Go. The result depends only on the set of keys.
export function buildRevocationTree(revoked: string[]): TreeNode {
  return subtree(revoked.map(BigInt), 0);
}

export type NonMembership = {
  siblings: string[];
  oldKey: string;
  oldValue: string;
  isOld0: string;
};

// Builds the non-inclusion witness locally. Returns null if the key IS in the
// tree, because no valid witness exists for a revoked credential.
export function nonMembershipWitness(tree: TreeNode, key: bigint): NonMembership | null {
  const siblings: string[] = [];
  let node = tree;
  let depth = 0;
  while (node.kind === 'mid') {
    const goRight = bit(key, depth) === 1n;
    siblings.push((goRight ? node.left : node.right).hash.toString());
    node = goRight ? node.right : node.left;
    depth++;
  }
  if (node.kind === 'leaf' && node.key === key) return null;
  while (siblings.length < REV_LEVELS) siblings.push('0');
  return node.kind === 'leaf'
    ? { siblings, oldKey: node.key.toString(), oldValue: '1', isOld0: '0' }
    : { siblings, oldKey: '0', oldValue: '0', isOld0: '1' };
}

export type ProveResult = {
  input: Record<string, string | string[]> | null;
  problem: string | null;
};

// Turns a credential and request into circuit input, or explains why no proof
// can exist. The explanation stays on the device: the site only hears "declined".
export async function buildInput(
  cred: Credential,
  req: ProofRequest,
  origin: string,
  snapshot: Snapshot,
  options: { skipWalletChecks?: boolean } = {},
): Promise<ProveResult> {
  const tree = buildRevocationTree(snapshot.revoked);
  if (tree.hash.toString() !== snapshot.root) {
    return { input: null, problem: 'The revocation list failed its integrity check.' };
  }
  const handle = BigInt(revocationHandle(cred.revToken));
  const witness = nonMembershipWitness(tree, handle);
  if (!witness) return { input: null, problem: 'This credential has been revoked.' };
  // The cheat test skips these to show the circuit enforces them too.
  if (!options.skipWalletChecks) {
    if (cred.dob > req.cutoffDate) {
      return { input: null, problem: `You do not meet the ${req.minAge}+ requirement, so no valid proof exists.` };
    }
    if (req.today > cred.expiry) return { input: null, problem: 'This credential has expired.' };
    if (req.requireUtah && !cred.isUtah) {
      return { input: null, problem: 'This site requires Utah residency, which your credential does not show.' };
    }
  }
  return {
    problem: null,
    input: {
      dob: String(cred.dob),
      isUtah: cred.isUtah ? '1' : '0',
      expiry: String(cred.expiry),
      holderSecret: cred.holderSecret,
      revToken: cred.revToken,
      sigR8x: cred.sig.r8x,
      sigR8y: cred.sig.r8y,
      sigS: cred.sig.s,
      revSiblings: witness.siblings,
      revOldKey: witness.oldKey,
      revOldValue: witness.oldValue,
      revIsOld0: witness.isOld0,
      issuerAx: cred.issuerAx,
      issuerAy: cred.issuerAy,
      cutoffDate: String(req.cutoffDate),
      today: String(req.today),
      requireUtah: req.requireUtah ? '1' : '0',
      revRoot: snapshot.root,
      scope: await scopeOf(origin),
      nonce: req.nonce,
      wantPseudonym: req.wantPseudonym ? '1' : '0',
    },
  };
}

// Conventional selective disclosure: reveals only the requested claims, but the
// signature and every salted hash go to the site unchanged.
export function standardPresentation(cred: Credential, req: ProofRequest) {
  const wanted = new Set([`ageOver${req.minAge}`, ...(req.requireUtah ? ['isUtah'] : [])]);
  return {
    disclosed: cred.standard.claims.filter((c) => wanted.has(c.name)),
    leaves: cred.standard.leaves,
    sig: cred.standard.sig,
  };
}

export function claimLeaf(value: string, salt: string): string {
  return poseidon2([BigInt(value), BigInt(salt)]).toString();
}

export function credentialHash(
  dob: number,
  isUtah: boolean,
  expiry: number,
  holderSecret: string,
  revToken: string,
): string {
  return poseidon5([
    BigInt(dob),
    isUtah ? 1n : 0n,
    BigInt(expiry),
    BigInt(holderCommit(holderSecret)),
    BigInt(revocationHandle(revToken)),
  ]).toString();
}
