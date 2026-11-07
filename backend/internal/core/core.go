// Package core holds the cryptography shared by every role: Poseidon hashing,
// the revocation tree, date handling and proof verification. It must stay
// byte-compatible with frontend/src/lib/core.ts and circuits/presentation.circom.
package core

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/iden3/go-iden3-crypto/constants"
	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/iden3/go-rapidsnark/types"
	"github.com/iden3/go-rapidsnark/verifier"
)

// PublicSignalNames is the order of the circuit's public signals: its output first, then its public inputs.
var PublicSignalNames = []string{
	"pseudonym", "issuerAx", "issuerAy", "cutoffDate", "today", "requireUtah", "revRoot", "scope", "nonce", "wantPseudonym",
}

// Poseidon hashes field elements. Panics only on programmer error (bad arity or out-of-field input).
func Poseidon(in ...*big.Int) *big.Int {
	h, err := poseidon.Hash(in)
	if err != nil {
		panic(fmt.Sprintf("poseidon: %v", err))
	}
	return h
}

// ParseField parses a decimal string and rejects anything outside the BN254 scalar field.
func ParseField(s string) (*big.Int, error) {
	n, ok := new(big.Int).SetString(s, 10)
	if !ok {
		return nil, fmt.Errorf("not a decimal number: %q", s)
	}
	if n.Sign() < 0 || n.Cmp(constants.Q) >= 0 {
		return nil, errors.New("value is outside the field")
	}
	return n, nil
}

// RandomField returns a uniformly random 248-bit value, which always fits in the field.
func RandomField() *big.Int {
	buf := make([]byte, 31)
	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}
	return new(big.Int).SetBytes(buf)
}

// ScopeOf maps a site origin to a field element: the first 31 bytes of its SHA-256.
func ScopeOf(origin string) *big.Int {
	sum := sha256.Sum256([]byte(origin))
	return new(big.Int).SetBytes(sum[:31])
}

// DateInt formats a time as a YYYYMMDD integer in UTC.
func DateInt(t time.Time) int {
	t = t.UTC()
	return t.Year()*10000 + int(t.Month())*100 + t.Day()
}

// Cutoff returns the latest birth date that meets minAge on the given day.
// Subtracting whole years from a YYYYMMDD integer keeps its calendar ordering.
func Cutoff(today, minAge int) int {
	return today - minAge*10000
}

// ValidDate reports whether a YYYYMMDD integer is a real calendar date.
func ValidDate(d int) bool {
	y, m, day := d/10000, d/100%100, d%100
	if y < 1900 || y > 2200 {
		return false
	}
	t := time.Date(y, time.Month(m), day, 0, 0, 0, 0, time.UTC)
	return t.Year() == y && int(t.Month()) == m && t.Day() == day
}

// RevLevels is the depth of the revocation tree, matching the circuit parameter.
const RevLevels = 20

var (
	one  = big.NewInt(1)
	zero = big.NewInt(0)
)

// RevocationRoot computes the root of the sparse Merkle tree over the revoked
// handles. Each key sits at the shallowest depth that separates it from the
// others, so the root depends only on the set of keys and not on insert order.
// Matches circomlib's SMTVerifier: leaf = Poseidon(key, 1, 1), node = Poseidon(l, r),
// path bits taken from the key's least significant bit upward.
func RevocationRoot(keys []*big.Int) (*big.Int, error) {
	return subtree(keys, 0)
}

func subtree(keys []*big.Int, depth int) (*big.Int, error) {
	switch len(keys) {
	case 0:
		return zero, nil
	case 1:
		return Poseidon(keys[0], one, one), nil
	}
	if depth >= RevLevels-1 {
		return nil, errors.New("revocation tree depth exceeded")
	}
	var left, right []*big.Int
	for _, k := range keys {
		if k.Bit(depth) == 0 {
			left = append(left, k)
		} else {
			right = append(right, k)
		}
	}
	l, err := subtree(left, depth+1)
	if err != nil {
		return nil, err
	}
	r, err := subtree(right, depth+1)
	if err != nil {
		return nil, err
	}
	return Poseidon(l, r), nil
}

// IssuerKey is the issuer's public key, as published on the mirror.
type IssuerKey struct {
	Ax string `json:"ax"`
	Ay string `json:"ay"`
}

// PublicKey converts the published form to a usable key.
func (k IssuerKey) PublicKey() (*babyjub.PublicKey, error) {
	x, err := ParseField(k.Ax)
	if err != nil {
		return nil, err
	}
	y, err := ParseField(k.Ay)
	if err != nil {
		return nil, err
	}
	return &babyjub.PublicKey{X: x, Y: y}, nil
}

// Sig is an EdDSA signature in JSON-friendly form.
type Sig struct {
	R8x string `json:"r8x"`
	R8y string `json:"r8y"`
	S   string `json:"s"`
}

// SigFrom converts a library signature to its published form.
func SigFrom(s *babyjub.Signature) Sig {
	return Sig{R8x: s.R8.X.String(), R8y: s.R8.Y.String(), S: s.S.String()}
}

// VerifySig checks a signature over a message hash.
func VerifySig(k IssuerKey, msg *big.Int, s Sig) error {
	pub, err := k.PublicKey()
	if err != nil {
		return err
	}
	x, err := ParseField(s.R8x)
	if err != nil {
		return err
	}
	y, err := ParseField(s.R8y)
	if err != nil {
		return err
	}
	sv, ok := new(big.Int).SetString(s.S, 10)
	if !ok {
		return errors.New("bad signature scalar")
	}
	if !pub.VerifyPoseidon(msg, &babyjub.Signature{R8: &babyjub.Point{X: x, Y: y}, S: sv}) {
		return errors.New("signature does not verify")
	}
	return nil
}

// Snapshot is one published revocation epoch. Wallets download all of it and
// build their own witness, so nobody learns which entry a wallet cares about.
type Snapshot struct {
	Epoch       int      `json:"epoch"`
	Revoked     []string `json:"revoked"`
	Root        string   `json:"root"`
	PublishedAt string   `json:"publishedAt"`
	Sig         Sig      `json:"sig"`
}

// SnapshotMessage is the hash the issuer signs for an epoch.
func SnapshotMessage(root *big.Int, epoch int) *big.Int {
	return Poseidon(root, big.NewInt(int64(epoch)))
}

// Verify checks the signature on a snapshot and that its root matches its list.
func (s Snapshot) Verify(k IssuerKey) error {
	keys := make([]*big.Int, 0, len(s.Revoked))
	for _, r := range s.Revoked {
		n, err := ParseField(r)
		if err != nil {
			return err
		}
		keys = append(keys, n)
	}
	root, err := RevocationRoot(keys)
	if err != nil {
		return err
	}
	if root.String() != s.Root {
		return errors.New("snapshot root does not match its list")
	}
	return VerifySig(k, SnapshotMessage(root, s.Epoch), s.Sig)
}

// Presentation is a Groth16 proof in snarkjs JSON form, plus its public signals.
type Presentation struct {
	Proof         *types.ProofData `json:"proof"`
	PublicSignals []string         `json:"publicSignals"`
}

// Named maps public signals to their names.
func (p Presentation) Named() (map[string]string, error) {
	if len(p.PublicSignals) != len(PublicSignalNames) {
		return nil, fmt.Errorf("expected %d public signals, got %d", len(PublicSignalNames), len(p.PublicSignals))
	}
	out := make(map[string]string, len(p.PublicSignals))
	for i, name := range PublicSignalNames {
		out[name] = p.PublicSignals[i]
	}
	return out, nil
}

// Expected lists what a verifier requires the public signals to be.
// Nonce is empty when the caller has no live request to compare against.
type Expected struct {
	Issuer      IssuerKey
	Scope       string
	RevRoot     string
	CutoffDate  string
	Today       string
	RequireUtah string
	Nonce       string
	WantPseudo  string
}

// Check verifies a presentation without contacting anyone. It reports the first
// failure as a short reason that can be shown to a person.
func Check(p Presentation, vkey []byte, want Expected) error {
	if p.Proof == nil {
		return errors.New("no proof supplied")
	}
	got, err := p.Named()
	if err != nil {
		return err
	}
	checks := []struct{ field, have, want, reason string }{
		{"issuerAx", got["issuerAx"], want.Issuer.Ax, "not signed by the recognised issuer"},
		{"issuerAy", got["issuerAy"], want.Issuer.Ay, "not signed by the recognised issuer"},
		{"scope", got["scope"], want.Scope, "proof was made for a different site"},
		{"revRoot", got["revRoot"], want.RevRoot, "proof uses an out-of-date revocation list"},
		{"cutoffDate", got["cutoffDate"], want.CutoffDate, "proof answers a different age question"},
		{"today", got["today"], want.Today, "proof is dated for a different day"},
		{"requireUtah", got["requireUtah"], want.RequireUtah, "proof answers a different residency question"},
		{"nonce", got["nonce"], want.Nonce, "proof was made for a different request"},
		{"wantPseudonym", got["wantPseudonym"], want.WantPseudo, "proof answers a different account question"},
	}
	for _, c := range checks {
		if c.want != "" && c.have != c.want {
			return errors.New(c.reason)
		}
	}
	if err := verifier.VerifyGroth16(types.ZKProof{Proof: p.Proof, PubSignals: p.PublicSignals}, vkey); err != nil {
		return fmt.Errorf("proof is invalid: %w", err)
	}
	return nil
}

// LoadJSON decodes JSON bytes into v, with a clearer error.
func LoadJSON(b []byte, v any) error {
	if err := json.Unmarshal(b, v); err != nil {
		return fmt.Errorf("bad JSON: %w", err)
	}
	return nil
}
