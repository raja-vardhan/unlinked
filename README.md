# Unlinked

Prove you're 18 or older to a website without telling that website, or the government, anything else.

Unlinked is a browser wallet that uses zero-knowledge proofs to answer "are you old enough?" with only a yes. It's modeled on Utah's [State-Endorsed Digital Identity law](https://le.utah.gov/xcode/Title63A/Chapter20/C63A-20-S301_2026050620260506.html) (Utah Code 63A-20). A live attacker console pools every log it can get and tries to link people across sites.

| Attack on the pooled logs | Standard credential | Unlinked ZK proof |
|---|---|---|
| Presentations linked across two sites | All of them | None |
| People named when the state cheats and keeps everything | All of them | None |

Those results come from real logs generated through real HTTP APIs, including your own presentations. Run it and check them.

This is a hackathon model. It isn't a compliant SEDI wallet and isn't affiliated with the State of Utah. Identity checks are simulated and the site names are fictional.

## Run it

This takes about two minutes the first time, and everything runs on your machine.

```bash
git clone https://github.com/raja-vardhan/unlinked.git
cd unlinked
make install   # installs npm packages and Go modules
make setup     # downloads a 38 MB setup file, compiles the circuit, runs the Groth16 setup
make demo      # builds, starts every role, seeds 30 synthetic holders
```

Wait for `Ready.`, then open these in a browser and **allow pop-ups for the two sites**, because the wallet opens in its own window:

| Role | URL |
|---|---|
| Wallet (start here) | http://localhost:8080 |
| Pinecrest Apps (18+) | http://localhost:8083 |
| Red Rock Cellar (21+, Utah residents) | http://localhost:8084 |
| Attacker console | http://localhost:8086 |

Press `Ctrl+C` in the terminal to stop. Next time, `make demo` is all you need. Then follow the [three-minute demo](#three-minute-demo).

### What you need

| Tool | Version | Notes |
|---|---|---|
| Node.js | 22.18 or newer | Older versions can't run the TypeScript the scripts import |
| Go | 1.21 or newer | Downloads the Go 1.26 toolchain this project needs on its own |
| make, curl, bash | Any | Already on most Linux and macOS machines |
| Browser | A recent Chromium-based one | Chrome, Edge or Brave. Others are untested |

You need internet access for the first run, and ports 8080 to 8086 must be free. `make setup` and `make demo` check these tools and tell you what's missing. Keys are generated on your machine in `data/`, which git ignores.

This has been tested on Ubuntu with Chromium. macOS should work but is untested, and there `make offline` runs without network isolation because `unshare` is Linux-only. On Windows, use WSL2 (also untested).

### Other commands

```bash
make test     # Go tests, then 23 circuit tests against the real Go signer and verifier
make offline  # verifies the latest proof from Pinecrest Apps with no network interfaces
make clean    # deletes generated keys and logs, keeping the circuit setup
```

### If something goes wrong

| What you see | What to do |
|---|---|
| `Port 8080 is already in use` | Another copy is running. Stop it with `Ctrl+C`, or free ports 8080 to 8086 |
| Your browser blocked the wallet window | Allow pop-ups for `localhost:8083` and `localhost:8084`, then click again |
| The wallet says the key "differs from the published issuer key" | You ran `make clean`, which replaces the keys. Click **Erase from this device** and request a new credential |
| The wallet says your credential is revoked | Click **Erase from this device** and request a new one, or restart `make demo` to clear the list |
| A site says "out-of-date revocation list" | The list changed while proving. Verify again |
| `make offline` says `REJECTED` after you revoked something | Expected: the saved proof predates the new list. Restart `make demo` to reset |
| `make offline` asks for your password | Your system blocks unprivileged network namespaces, so `unshare` needs `sudo` |
| Pages don't work from another machine | The demo runs on `localhost` only, because each role's address is fixed and browsers restrict crypto to secure origins |
| Attack results look odd after midnight UTC | Restart `make demo`, so the seeded crowd shares your date |

Restarting `make demo` resets every site log and the revocation list, but keeps your credential valid.

## Why a ZK proof is needed

Selective disclosure alone doesn't stop tracking. ISO mdoc and SD-JWT hide the claims you don't share, but they show every site the issuer's signature. That signature works like a tracking cookie: sites can match it with each other, and the state can match it to the person it issued it to. Batches of one-time credentials help between sites, but not when the state pools logs with them.

A ZK proof shows "I hold a validly signed credential and my birth date is before this cutoff" without revealing the signature. Nothing per-person reaches the site, so there's nothing to match.

## Three-minute demo

1. **Issue.** In the wallet, request a credential. Point out the revocation code, which is the holder's own way to revoke.
2. **Prove.** On Pinecrest Apps, click **Verify with a ZK proof** and send it. Show "Everything this site received": no name, no birth date, no signature.
3. **Prove elsewhere.** Do the same on Red Rock Cellar, which asks a different question. Then click **Compare: standard credential** on both sites.
4. **Attack.** In the console, the standard credential links everyone and the ZK proof links no one. Tick **State cheats** and run it again: the standard credential names people and the ZK column stays at 0.
5. **Cut the network.** Run `make offline`. It reports 0 network interfaces and a valid proof.
6. **Probe.** Click **Attack: probe for a birth date**. The wallet refuses, because an arbitrary cutoff would let a site find a birth date in about 16 yes-or-no questions.
7. **Moderate.** Click **Open an anonymous account** twice to see one stable ID and a visit count, then **Ban this account**. The next attempt is rejected without anyone learning who it was. Red Rock Cellar gets a different ID.
8. **Revoke.** Click **Revoke at my request** in the wallet, then try to verify. No proof can be made, and the site hears only "declined". The state's request log shows no verification traffic.

## How it works

Each role is its own process and web origin, so the boundaries are real. The wallet's storage is unreadable from the sites because the browser enforces it.

```
:8080 wallet    React and the prover; secrets stay in this origin
:8081 state     issues once, forgets, signs revocation lists
:8082 mirror    public copy of keys and revocation lists
:8083 site-a    Pinecrest Apps
:8084 site-b    Red Rock Cellar
:8085 trustee   holds the only key that opens the fraud escrow
:8086 console   the attacker: pools logs and tries to link them
```

Sites have no address for the state and import nothing from it. Check with `cd backend && go list -deps ./internal/site | grep unlinked`.

### The circuit

[circuits/presentation.circom](circuits/presentation.circom) has 23,419 constraints. A proof took about 1 second in Chromium on the development laptop.

```
private: dob, isUtah, expiry, holderSecret, revToken, signature, revocation witness
public:  issuerKey, cutoffDate, today, requireUtah, revRoot, scope, nonce, wantPseudonym
output:  pseudonym (0 unless the site asks and the holder agrees)

credHash = Poseidon(dob, isUtah, expiry, Poseidon(holderSecret), Poseidon(revToken))
verify EdDSA(issuerKey, signature, credHash)
dob <= cutoffDate                    // YYYYMMDD integers, calendar-exact
today <= expiry
requireUtah * (isUtah - 1) === 0
Poseidon(revToken) is not in revRoot
pseudonym = wantPseudonym * Poseidon(holderSecret, scope)
```

### How the state forgets holders

The state must be able to revoke for fraud under 301(5), but it shouldn't keep a list of who holds what. So:

1. The wallet sends only a hash of its secret. The state checks the applicant, creates a revocation token, signs the credential and returns it.
2. The state keeps one record per person: their name beside the token, encrypted to an independent trustee's key. It can't open the token.
3. For compromise or a holder request, the holder uses their printed code. The state needs no lookup.
4. For fraud or issuance error, the trustee decrypts the token against a court order reference. Revocation adds a hash to a public list and says nothing about the holder's past use.
5. To check status, the wallet downloads the whole list from the mirror and builds its witness locally. Asking the state about one entry would be a phone-home by another name.

Nobody outside can prove the state really deleted anything. That's why the attack console also models a state that keeps everything: the signature and credential hash it kept never appear in a proof, so it gains nothing it can match against. The "shadow" record in [state.go](backend/internal/state/state.go) exists only to give that attack real data, and an honest issuer wouldn't write it.

### Attacks it handles

| Attack | Defense | Where it's enforced |
|---|---|---|
| Lying about your birth date | Credential hash won't match the signature | Circuit |
| Forged or wrong-issuer credential | EdDSA check against the public issuer key | Circuit and site |
| Using a revoked credential | Non-membership proof against the current root | Circuit and site |
| Replay of an old proof | Single-use nonces that expire after 5 minutes | Site |
| Relay to another site | Scope is hashed from the origin the browser reports | Wallet, circuit and site |
| Finding a birth date with varied cutoffs | Only standard 18+ and 21+ questions are answered | Wallet |
| Tagging someone with a personal issuer key | Key must match the published one | Wallet and site |
| Mirror swapping keys or rolling back the list | Keys pinned on first load; older epochs rejected | Site |
| Mirror dropping a revoked entry | Issuer signature covers the root and epoch | Site |

## Utah framework map

Sections refer to Utah Code 63A-20. The console shows this same table.

| Section | Requirement | This demo | Status |
|---|---|---|---|
| 301(1)(e)(ii) | Show a minimum age without disclosing age or birth date | The proof answers only yes or no | Shown live |
| 301(3) | No mechanism for the department to monitor or track presentations | Sites have no state address; zero state requests from verification; verifies with no network | Shown live |
| 301(5) | Revoke only for compromise, error or fraud, or holder request | API accepts only those grounds and records which was used | Shown live |
| 303(1)(d) | Endorsement reflects a point in time, without monitoring or tracking | Credential carries its own expiry; state isn't contacted again | Shown live |
| 301(1)(a) | Cross-context correlation protections | No join at the log level; IP and timing need network-level protection | Partly |
| 301(4) | Limits on using, keeping and disclosing data | State keeps one encrypted token per person; the trustee only checks that an order reference exists | Partly |
| 301(1)(e)(i) | Selectively disclose attributes | Residency is a separate yes or no; name, image and address aren't modeled | Partly |
| 301(1)(d) | Online and offline presentation | Verifies offline, but has no QR or NFC channel to hand over a proof | Partly |
| 301(1)(a) | Compromise detection and recovery | Printed code revokes; detection and reissue aren't built | Partly |
| 301(2)(e) | Open standards free of fees and patents | Published open-source schemes, not reviewed for patents, and not ISO mdoc | Partly |
| 301(1)(f) | Holder chooses a conforming wallet | One wallet here; nothing in the protocol ties a credential to it | Not modeled |
| 301(2)(c) | Infrastructure in a state-controlled, in-state data center | Runs on one machine | Not modeled |
| 301(2)(g)(iii) | Digital guardians | Not built | Not modeled |

Beyond the statute, Utah's [draft implementation guide](https://sedi.utah.gov/implementation-guide/part-3/) asks that age proofs produce only a boolean and that revocation not reveal presentation patterns. Both hold here, because pseudonyms are off unless requested. The guide is a v0.1.0 draft, and we found no final standards or launch date, so this can't claim conformance.

## Known limits

- **The state still sees your attributes once.** 301(2)(f) requires it to verify and endorse them. Privacy here means it can't see your use of the credential.
- **A corrupted setup could forge proofs.** Groth16 needs a per-circuit setup. It's built on PSE's public Powers of Tau, plus three contributors simulated on one machine. Real use needs independent contributors, and the state must not run it alone. It shouldn't expose holder data if wallets verify the setup. [Longfellow](https://eid-privacy.github.io/wp0/2025/11/28/crescent-longfellow-showdown.html) needs no setup and is the likely production path.
- **The state can mint fake adults.** It's the issuer, and a single signer can forge credentials. Threshold issuance would address that.
- **Credentials can be copied or lent.** The holder secret sits in browser memory while proving. Real device binding needs a hardware key checked inside the proof, which is expensive in Circom. Nothing stops an adult lending an unlocked phone.
- **Network data isn't hidden.** IP addresses and timing can still correlate people. Sites and mirrors see them, so production needs relays or similar.
- **The mirror sees when wallets fetch.** Fetching on a schedule, separate from presenting, would break that link.
- **Split views are possible.** A cheating state could sign different revocation lists for different wallets, making the root a tag. Wallets don't yet check the list's signature, and real use needs a public transparency log.
- **Revocation epochs narrow the crowd.** Everyone presenting after a new list shares its root, so a rarely used root reveals more. Publishing on a fixed schedule keeps that crowd large. The attack reports these fields but doesn't count them as personal links.
- **Pseudonyms are per credential, not per human.** One-account-per-person needs the issuer to limit active credentials.
- **The revocation tree is demo-sized.** At 20 levels, collisions become likely around a thousand entries. Production needs more levels, at more constraints. Grinding revocation codes could also fill it, so a real issuer must reject codes it never issued, for example by authenticating them.
- **The credential format isn't ISO mdoc.** It uses BabyJubJub EdDSA and Poseidon, chosen to be cheap in a circuit.
- **Demo shortcuts.** CORS is wide open, `/debug/summary` exposes the state's records so the console can read them, and anyone can click ban.

## Project layout

```
circuits/presentation.circom   the statement being proved
backend/internal/core          shared cryptography and proof checking
backend/internal/state         issuer, escrow and revocation
backend/internal/site          relying website and verifier
backend/internal/trustee       fraud escrow key holder
backend/internal/console       the linking attack
backend/cmd/verify             offline verifier
frontend/src/lib/core.ts       wallet cryptography, shared with the seed script and tests
scripts/circuit.test.mjs       circuit tests against the real Go code
```

## License

[MIT](LICENSE).
