pragma circom 2.1.6;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/eddsaposeidon.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/smt/smtverifier.circom";

// Proves, without revealing the credential or its signature:
//   1. the wallet holds a credential the issuer signed            Utah Code 63A-20-301(1)(b)
//   2. the birth date is on or before a public cutoff             63A-20-301(1)(e)(ii)
//   3. the credential has not expired
//   4. the holder is a Utah resident, only if the site asks       63A-20-301(1)(e)(i)
//   5. the credential is not on the public revocation list        63A-20-301(5), 301(3)
//   6. optionally, a per-site account ID, only if the holder agrees
//
// The signature, credential hash and revocation handle stay private. That is
// what stops sites, or the state, from matching presentations to each other.
template Presentation(revLevels) {
    // Private: the credential.
    signal input dob;           // YYYYMMDD
    signal input isUtah;        // 0 or 1
    signal input expiry;        // YYYYMMDD
    signal input holderSecret;
    signal input revToken;
    signal input sigR8x;
    signal input sigR8y;
    signal input sigS;

    // Private: witness that the revocation handle is absent from the tree.
    signal input revSiblings[revLevels];
    signal input revOldKey;
    signal input revOldValue;
    signal input revIsOld0;

    // Public: identical for every holder asked the same question that day,
    // except scope and nonce, which identify the site and the request.
    signal input issuerAx;
    signal input issuerAy;
    signal input cutoffDate;    // YYYYMMDD
    signal input today;         // YYYYMMDD
    signal input requireUtah;   // 0 or 1
    signal input revRoot;
    signal input scope;         // hash of the requesting site's origin
    signal input nonce;         // single-use, chosen by the site
    signal input wantPseudonym; // 0 or 1

    // Hash of the holder's secret and this site's scope, or 0 when not requested.
    // Stable at one site, different at every other, and the state can't compute
    // it because it only ever saw a hash of the secret.
    signal output pseudonym;

    // Range checks, so the date comparisons below cannot wrap around the field.
    component dobBits = Num2Bits(32);
    dobBits.in <== dob;
    component expiryBits = Num2Bits(32);
    expiryBits.in <== expiry;
    component cutoffBits = Num2Bits(32);
    cutoffBits.in <== cutoffDate;
    component todayBits = Num2Bits(32);
    todayBits.in <== today;
    isUtah * (isUtah - 1) === 0;
    requireUtah * (requireUtah - 1) === 0;
    wantPseudonym * (wantPseudonym - 1) === 0;

    // Rebuild the signed credential hash from its private parts.
    component holderCommit = Poseidon(1);
    holderCommit.inputs[0] <== holderSecret;

    component revHandle = Poseidon(1);
    revHandle.inputs[0] <== revToken;

    component credHash = Poseidon(5);
    credHash.inputs[0] <== dob;
    credHash.inputs[1] <== isUtah;
    credHash.inputs[2] <== expiry;
    credHash.inputs[3] <== holderCommit.out;
    credHash.inputs[4] <== revHandle.out;

    // 1. The issuer signed exactly this credential.
    component sig = EdDSAPoseidonVerifier();
    sig.enabled <== 1;
    sig.Ax <== issuerAx;
    sig.Ay <== issuerAy;
    sig.R8x <== sigR8x;
    sig.R8y <== sigR8y;
    sig.S <== sigS;
    sig.M <== credHash.out;

    // 2. Old enough. YYYYMMDD integers sort the same way dates do.
    component oldEnough = LessEqThan(32);
    oldEnough.in[0] <== dob;
    oldEnough.in[1] <== cutoffDate;
    oldEnough.out === 1;

    // 3. Not expired.
    component notExpired = LessEqThan(32);
    notExpired.in[0] <== today;
    notExpired.in[1] <== expiry;
    notExpired.out === 1;

    // 4. Residency is checked only when the site requests it.
    requireUtah * (isUtah - 1) === 0;

    // 5. The revocation handle is NOT in the tree (fnc = 1: non-inclusion).
    component notRevoked = SMTVerifier(revLevels);
    notRevoked.enabled <== 1;
    notRevoked.fnc <== 1;
    notRevoked.root <== revRoot;
    for (var i = 0; i < revLevels; i++) {
        notRevoked.siblings[i] <== revSiblings[i];
    }
    notRevoked.oldKey <== revOldKey;
    notRevoked.oldValue <== revOldValue;
    notRevoked.isOld0 <== revIsOld0;
    notRevoked.key <== revHandle.out;
    notRevoked.value <== 0;

    // 6. Plain age checks stay boolean-only: the pseudonym is 0 unless requested.
    component siteAccount = Poseidon(2);
    siteAccount.inputs[0] <== holderSecret;
    siteAccount.inputs[1] <== scope;
    pseudonym <== wantPseudonym * siteAccount.out;

    // Tie scope and nonce into the constraint system so a proof made for one
    // site and one request cannot be presented anywhere else.
    signal scopeSquared <== scope * scope;
    signal nonceSquared <== nonce * nonce;
}

component main {public [issuerAx, issuerAy, cutoffDate, today, requireUtah, revRoot, scope, nonce, wantPseudonym]} = Presentation(20);
