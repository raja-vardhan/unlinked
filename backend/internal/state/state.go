// Package state is the simulated issuer. It verifies an applicant once, signs a
// credential, and keeps no readable link between the person and that credential.
// It never takes part in verification: no site has its address.
package state

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/iden3/go-iden3-crypto/babyjub"
	"golang.org/x/crypto/nacl/box"

	"unlinked/internal/core"
	"unlinked/internal/web"
)

// EscrowRecord is the only thing an honest issuer keeps about a person: their
// revocation token, encrypted so that only the independent trustee can read it.
// Required so that fraud revocation under 63A-20-301(5)(b) remains possible.
type EscrowRecord struct {
	Person     string `json:"person"`
	Ciphertext string `json:"ciphertext"`
	IssuedAt   string `json:"issuedAt"`
}

// ShadowRecord is what a CHEATING issuer would quietly keep. An honest issuer
// never writes this. It exists only so the console's "malicious state" attack
// has real data to try, and to show that retaining everything still does not
// reveal where a ZK credential gets used.
type ShadowRecord struct {
	Person string            `json:"person"`
	Values map[string]string `json:"values"`
}

// Revocation records which statutory ground was used, without saying who it was.
type Revocation struct {
	Ground string `json:"ground"`
	At     string `json:"at"`
	Epoch  int    `json:"epoch"`
}

// Server is the issuer role.
type Server struct {
	mu          sync.Mutex
	key         babyjub.PrivateKey
	issuer      core.IssuerKey
	mirrorDir   string
	trusteeURL  string
	trusteePub  *[32]byte
	revoked     []*big.Int
	epoch       int
	escrow      []EscrowRecord
	shadow      []ShadowRecord
	revocations []Revocation
	issuedCount int
	log         *web.RequestLog
}

// New loads or creates the issuer key and publishes the first revocation epoch.
func New(dataDir, mirrorDir, trusteeURL string, log *web.RequestLog) (*Server, error) {
	s := &Server{mirrorDir: mirrorDir, trusteeURL: trusteeURL, log: log}
	if err := os.MkdirAll(mirrorDir, 0o755); err != nil {
		return nil, err
	}
	if err := s.loadKey(filepath.Join(dataDir, "issuer.key")); err != nil {
		return nil, err
	}
	pub := s.key.Public()
	s.issuer = core.IssuerKey{Ax: pub.X.String(), Ay: pub.Y.String()}
	if err := writeJSON(filepath.Join(mirrorDir, "issuer.json"), s.issuer); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.publishLocked(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Server) loadKey(path string) error {
	if raw, err := os.ReadFile(path); err == nil && len(raw) == len(s.key) {
		copy(s.key[:], raw)
		return nil
	}
	s.key = babyjub.NewRandPrivKey()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, s.key[:], 0o600)
}

// Routes registers the issuer's HTTP API.
func (s *Server) Routes(mux *http.ServeMux) {
	mux.HandleFunc("POST /issue", s.handleIssue)
	mux.HandleFunc("POST /revoke/code", s.handleRevokeCode)
	mux.HandleFunc("POST /revoke/fraud", s.handleRevokeFraud)
	mux.HandleFunc("GET /debug/summary", s.handleSummary)
}

type issueRequest struct {
	Name         string `json:"name"`
	DOB          int    `json:"dob"`
	IsUtah       bool   `json:"isUtah"`
	HolderCommit string `json:"holderCommit"`
}

func (s *Server) handleIssue(w http.ResponseWriter, r *http.Request) {
	var req issueRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		web.Error(w, http.StatusBadRequest, "malformed request")
		return
	}
	if req.Name == "" {
		web.Error(w, http.StatusBadRequest, "name is required")
		return
	}
	if !core.ValidDate(req.DOB) {
		web.Error(w, http.StatusBadRequest, "birth date must be a real date")
		return
	}
	holderCommit, err := core.ParseField(req.HolderCommit)
	if err != nil {
		web.Error(w, http.StatusBadRequest, "invalid holder commitment")
		return
	}

	today := core.DateInt(time.Now())
	expiry := today + 10000 // one year
	isUtah := big.NewInt(0)
	if req.IsUtah {
		isUtah = big.NewInt(1)
	}

	// The state creates the revocation token itself, so the escrowed copy is
	// guaranteed to match the credential without any proof from the wallet.
	revToken := core.RandomField()
	revHandle := core.Poseidon(revToken)
	credHash := core.Poseidon(big.NewInt(int64(req.DOB)), isUtah, big.NewInt(int64(expiry)), holderCommit, revHandle)

	s.mu.Lock()
	defer s.mu.Unlock()

	sig := s.key.SignPoseidon(credHash)
	std, stdDigest := s.signStandard(req.DOB, today, isUtah)
	ciphertext, err := s.sealForTrustee(revToken)
	if err != nil {
		web.Error(w, http.StatusBadGateway, "trustee is unavailable: "+err.Error())
		return
	}

	s.issuedCount++
	s.escrow = append(s.escrow, EscrowRecord{
		Person:     req.Name,
		Ciphertext: hex.EncodeToString(ciphertext),
		IssuedAt:   time.Now().UTC().Format(time.RFC3339),
	})
	coreSig := core.SigFrom(sig)
	s.shadow = append(s.shadow, ShadowRecord{
		Person: req.Name,
		Values: map[string]string{
			"credentialHash":   credHash.String(),
			"holderCommitment": holderCommit.String(),
			"revocationHandle": revHandle.String(),
			"revocationToken":  revToken.String(),
			"signature.r8x":    coreSig.R8x,
			"signature.r8y":    coreSig.R8y,
			"signature.s":      coreSig.S,
			"standard.digest":  stdDigest.String(),
			"standard.sig.r8x": std.Sig.R8x,
			"standard.sig.r8y": std.Sig.R8y,
			"standard.sig.s":   std.Sig.S,
		},
	})

	web.JSON(w, http.StatusOK, map[string]any{
		"dob":      req.DOB,
		"isUtah":   req.IsUtah,
		"expiry":   expiry,
		"revToken": revToken.String(),
		"sig":      coreSig,
		"issuerAx": s.issuer.Ax,
		"issuerAy": s.issuer.Ay,
		"standard": std,
	})
}

type standardClaim struct {
	Name  string `json:"name"`
	Value string `json:"value"`
	Salt  string `json:"salt"`
}

type standardCredential struct {
	Claims []standardClaim `json:"claims"`
	Leaves []string        `json:"leaves"`
	Sig    core.Sig        `json:"sig"`
}

// signStandard issues the comparison credential: salted claim hashes under one
// signature, the way ISO mdoc and SD-JWT work. Selective disclosure hides the
// unselected claims, but the signature itself is the same for every site.
func (s *Server) signStandard(dob, today int, isUtah *big.Int) (standardCredential, *big.Int) {
	flag := func(ok bool) *big.Int {
		if ok {
			return big.NewInt(1)
		}
		return big.NewInt(0)
	}
	values := []struct {
		name string
		val  *big.Int
	}{
		{"ageOver18", flag(dob <= core.Cutoff(today, 18))},
		{"ageOver21", flag(dob <= core.Cutoff(today, 21))},
		{"isUtah", isUtah},
	}
	var cred standardCredential
	leaves := make([]*big.Int, 0, len(values))
	for _, v := range values {
		salt := core.RandomField()
		leaf := core.Poseidon(v.val, salt)
		leaves = append(leaves, leaf)
		cred.Claims = append(cred.Claims, standardClaim{Name: v.name, Value: v.val.String(), Salt: salt.String()})
		cred.Leaves = append(cred.Leaves, leaf.String())
	}
	digest := core.Poseidon(leaves...)
	cred.Sig = core.SigFrom(s.key.SignPoseidon(digest))
	return cred, digest
}

func (s *Server) sealForTrustee(token *big.Int) ([]byte, error) {
	if s.trusteePub == nil {
		pub, err := fetchTrusteeKey(s.trusteeURL)
		if err != nil {
			return nil, err
		}
		s.trusteePub = pub
	}
	return box.SealAnonymous(nil, []byte(token.String()), s.trusteePub, rand.Reader)
}

func fetchTrusteeKey(baseURL string) (*[32]byte, error) {
	resp, err := http.Get(baseURL + "/pubkey")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var out struct {
		PublicKey string `json:"publicKey"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	raw, err := hex.DecodeString(out.PublicKey)
	if err != nil || len(raw) != 32 {
		return nil, errors.New("malformed trustee key")
	}
	var key [32]byte
	copy(key[:], raw)
	return &key, nil
}

// handleRevokeCode covers compromise and holder request, 63A-20-301(5)(a) and (c).
// The printed code is the only input needed, so no holder lookup exists to abuse.
func (s *Server) handleRevokeCode(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Code   string `json:"code"`
		Ground string `json:"ground"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		web.Error(w, http.StatusBadRequest, "malformed request")
		return
	}
	if req.Ground != "compromise" && req.Ground != "holder-request" {
		web.Error(w, http.StatusBadRequest, "ground must be compromise or holder-request")
		return
	}
	token, err := core.ParseField(req.Code)
	if err != nil {
		web.Error(w, http.StatusBadRequest, "invalid revocation code")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.revokeLocked(core.Poseidon(token), req.Ground); err != nil {
		web.Error(w, http.StatusInternalServerError, err.Error())
		return
	}
	web.JSON(w, http.StatusOK, map[string]any{"epoch": s.epoch, "ground": req.Ground})
}

// handleRevokeFraud covers issuance error or fraud, 63A-20-301(5)(b). The state
// cannot read its own escrow: the trustee must decrypt it, and only against a
// court order reference.
func (s *Server) handleRevokeFraud(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Person     string `json:"person"`
		CourtOrder string `json:"courtOrder"`
		Ground     string `json:"ground"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		web.Error(w, http.StatusBadRequest, "malformed request")
		return
	}
	if req.Ground != "fraud" && req.Ground != "error" {
		web.Error(w, http.StatusBadRequest, "ground must be fraud or error")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	revoked := 0
	for _, rec := range s.escrow {
		if rec.Person != req.Person {
			continue
		}
		token, err := s.askTrustee(rec.Ciphertext, req.CourtOrder)
		if err != nil {
			web.Error(w, http.StatusForbidden, err.Error())
			return
		}
		if err := s.revokeLocked(core.Poseidon(token), req.Ground); err != nil {
			web.Error(w, http.StatusInternalServerError, err.Error())
			return
		}
		revoked++
	}
	if revoked == 0 {
		web.Error(w, http.StatusNotFound, "no escrow record for that person")
		return
	}
	web.JSON(w, http.StatusOK, map[string]any{"epoch": s.epoch, "revoked": revoked, "ground": req.Ground})
}

func (s *Server) askTrustee(ciphertext, courtOrder string) (*big.Int, error) {
	body, err := json.Marshal(map[string]string{"ciphertext": ciphertext, "courtOrder": courtOrder})
	if err != nil {
		return nil, err
	}
	resp, err := http.Post(s.trusteeURL+"/decrypt", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("trustee is unavailable: %w", err)
	}
	defer resp.Body.Close()
	var out struct {
		Token string `json:"token"`
		Error string `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("trustee refused: %s", out.Error)
	}
	return core.ParseField(out.Token)
}

func (s *Server) revokeLocked(handle *big.Int, ground string) error {
	for _, existing := range s.revoked {
		if existing.Cmp(handle) == 0 {
			return nil
		}
	}
	// Check the new tree first. Handles that collide too deeply must fail this one
	// request, not leave the list unpublishable for everyone else.
	next := append(append([]*big.Int(nil), s.revoked...), handle)
	if _, err := core.RevocationRoot(next); err != nil {
		return err
	}
	s.revoked = next
	if err := s.publishLocked(); err != nil {
		return err
	}
	s.revocations = append(s.revocations, Revocation{Ground: ground, At: time.Now().UTC().Format(time.RFC3339), Epoch: s.epoch})
	return nil
}

// publishLocked signs a new epoch and writes it to the public mirror directory.
// The state pushes outward and never receives a request about it from a verifier.
func (s *Server) publishLocked() error {
	root, err := core.RevocationRoot(s.revoked)
	if err != nil {
		return err
	}
	s.epoch++
	sig := s.key.SignPoseidon(core.SnapshotMessage(root, s.epoch))
	revoked := make([]string, len(s.revoked))
	for i, h := range s.revoked {
		revoked[i] = h.String()
	}
	return writeJSON(filepath.Join(s.mirrorDir, "revocation.json"), core.Snapshot{
		Epoch:       s.epoch,
		Revoked:     revoked,
		Root:        root.String(),
		PublishedAt: time.Now().UTC().Format(time.RFC3339),
		Sig:         core.SigFrom(sig),
	})
}

func (s *Server) handleSummary(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	web.JSON(w, http.StatusOK, map[string]any{
		"issued":      s.issuedCount,
		"epoch":       s.epoch,
		"escrow":      orEmpty(s.escrow),
		"shadow":      orEmpty(s.shadow),
		"revocations": orEmpty(s.revocations),
		"requests":    orEmpty(s.log.Entries()),
	})
}

// orEmpty makes nil slices encode as [] rather than null, so clients can rely on arrays.
func orEmpty[T any](items []T) []T {
	if items == nil {
		return []T{}
	}
	return items
}

func writeJSON(path string, v any) error {
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
