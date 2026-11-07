// Package site is a relying website that also verifies proofs itself.
//
// It has no address for the state and imports nothing from it. Everything it
// needs (verification key, issuer key, revocation list) comes from a public
// mirror, and verification keeps working if that mirror goes away.
// Check it with: go list -deps ./internal/site | grep unlinked
package site

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"unlinked/internal/core"
	"unlinked/internal/web"
)

// Config describes one site and the question it asks.
type Config struct {
	Role        string
	Title       string
	Origin      string
	MinAge      int
	RequireUtah bool
	MirrorURL   string
	DataDir     string
}

// Entry is one line of the site's log: exactly what the site learned.
type Entry struct {
	Time   string            `json:"time"`
	Mode   string            `json:"mode"`
	Result string            `json:"result"`
	Reason string            `json:"reason,omitempty"`
	Fields map[string]string `json:"fields"`
	Raw    json.RawMessage   `json:"raw,omitempty"`
}

// requestTTL limits how long a holder has to answer a request.
const requestTTL = 5 * time.Minute

type pendingRequest struct {
	Nonce         string `json:"nonce"`
	CutoffDate    int    `json:"cutoffDate"`
	Today         int    `json:"today"`
	RequireUtah   bool   `json:"requireUtah"`
	MinAge        int    `json:"minAge"`
	SiteTitle     string `json:"siteTitle"`
	WantPseudonym bool   `json:"wantPseudonym"`
	createdAt     time.Time
}

// account is everything a site can know about a returning holder: a count.
type account struct {
	Visits int  `json:"visits"`
	Banned bool `json:"banned"`
}

// Server is a site role.
type Server struct {
	cfg      Config
	scope    string
	mu       sync.Mutex
	pending  map[string]pendingRequest
	entries  []Entry
	vkey     []byte
	issuer   core.IssuerKey
	snapshot core.Snapshot
	accounts map[string]*account
}

// New creates a site and starts following the mirror.
func New(cfg Config) *Server {
	s := &Server{
		cfg:      cfg,
		scope:    core.ScopeOf(cfg.Origin).String(),
		pending:  make(map[string]pendingRequest),
		accounts: make(map[string]*account),
	}
	go s.followMirror()
	return s
}

// followMirror keeps the latest public data. If the mirror is unreachable the
// site keeps using what it last fetched, so outages do not stop verification.
func (s *Server) followMirror() {
	for {
		if err := s.refresh(); err != nil {
			log.Printf("%s: mirror: %v", s.cfg.Role, err)
		}
		time.Sleep(time.Second)
	}
}

func (s *Server) refresh() error {
	vkey, err := fetch(s.cfg.MirrorURL + "/verification_key.json")
	if err != nil {
		return err
	}
	rawIssuer, err := fetch(s.cfg.MirrorURL + "/issuer.json")
	if err != nil {
		return err
	}
	var issuer core.IssuerKey
	if err := core.LoadJSON(rawIssuer, &issuer); err != nil {
		return err
	}
	rawSnap, err := fetch(s.cfg.MirrorURL + "/revocation.json")
	if err != nil {
		return err
	}
	var snap core.Snapshot
	if err := core.LoadJSON(rawSnap, &snap); err != nil {
		return err
	}
	if err := snap.Verify(issuer); err != nil {
		return fmt.Errorf("rejecting revocation snapshot: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	// Keys are pinned on first load, so a compromised mirror can't swap them. A
	// real deployment would ship them with the verifier instead of trusting first use.
	if s.vkey != nil {
		if !bytes.Equal(vkey, s.vkey) || issuer != s.issuer {
			return errors.New("mirror changed a pinned key; keeping the original")
		}
		if snap.Epoch < s.snapshot.Epoch {
			return fmt.Errorf("mirror served old list %d after list %d; keeping the newer one", snap.Epoch, s.snapshot.Epoch)
		}
	}
	s.vkey, s.issuer, s.snapshot = vkey, issuer, snap
	return nil
}

func fetch(url string) ([]byte, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s", url, resp.Status)
	}
	return io.ReadAll(resp.Body)
}

// Routes registers the site's HTTP API.
func (s *Server) Routes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/request", s.handleRequest)
	mux.HandleFunc("POST /api/verify", s.handleVerify)
	mux.HandleFunc("GET /api/log", s.handleLog)
	mux.HandleFunc("POST /api/account/ban", s.handleBan)
}

func (s *Server) handleRequest(w http.ResponseWriter, r *http.Request) {
	now := time.Now()
	today := core.DateInt(now)
	req := pendingRequest{
		Nonce:         core.RandomField().String(),
		CutoffDate:    core.Cutoff(today, s.cfg.MinAge),
		Today:         today,
		RequireUtah:   s.cfg.RequireUtah,
		MinAge:        s.cfg.MinAge,
		SiteTitle:     s.cfg.Title,
		WantPseudonym: r.URL.Query().Get("account") == "1",
		createdAt:     now,
	}
	s.mu.Lock()
	for nonce, p := range s.pending {
		if now.Sub(p.createdAt) > requestTTL {
			delete(s.pending, nonce)
		}
	}
	s.pending[req.Nonce] = req
	s.mu.Unlock()
	web.JSON(w, http.StatusOK, req)
}

type verifyRequest struct {
	Mode         string          `json:"mode"`
	Nonce        string          `json:"nonce"`
	Presentation json.RawMessage `json:"presentation"`
}

func (s *Server) handleVerify(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if err != nil {
		web.Error(w, http.StatusBadRequest, "request is too large")
		return
	}
	var req verifyRequest
	if err := json.Unmarshal(body, &req); err != nil {
		web.Error(w, http.StatusBadRequest, "malformed request")
		return
	}

	// Nonces are single-use. Taking it now means a failed attempt also burns it.
	s.mu.Lock()
	pending, known := s.pending[req.Nonce]
	delete(s.pending, req.Nonce)
	s.mu.Unlock()

	entry := Entry{Time: time.Now().UTC().Format(time.RFC3339), Mode: req.Mode, Fields: map[string]string{}}
	var verr error
	switch {
	case !known:
		verr = errors.New("unknown or already-used request")
		s.collectFields(&entry, req)
	case req.Mode == "zk":
		verr = s.verifyZK(&entry, req, pending)
	case req.Mode == "standard":
		verr = s.verifyStandard(&entry, req, pending)
	default:
		verr = errors.New("unknown presentation mode")
	}

	// Accounts are only touched once the proof itself has been accepted.
	var acct *accountView
	if verr == nil && req.Mode == "zk" && pending.WantPseudonym {
		acct, verr = s.recordVisit(entry.Fields["pseudonym"])
	}

	entry.Result = "accepted"
	if verr != nil {
		entry.Result = "rejected"
		entry.Reason = verr.Error()
	}
	entry.Raw = req.Presentation
	s.mu.Lock()
	s.entries = append(s.entries, entry)
	s.mu.Unlock()
	if verr == nil && req.Mode == "zk" {
		s.saveLast(req.Presentation)
	}

	web.JSON(w, http.StatusOK, map[string]any{
		"ok":       verr == nil,
		"reason":   entry.Reason,
		"received": entry.Fields,
		"account":  acct,
	})
}

type accountView struct {
	ID     string `json:"id"`
	Visits int    `json:"visits"`
}

// recordVisit counts a return visit. It is the site's whole view of the holder,
// and a ban takes effect here without anyone learning who the holder is.
func (s *Server) recordVisit(id string) (*accountView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a := s.accounts[id]
	if a == nil {
		a = &account{}
		s.accounts[id] = a
	}
	if a.Banned {
		return nil, errors.New("this anonymous account has been banned from this site")
	}
	a.Visits++
	return &accountView{ID: id, Visits: a.Visits}, nil
}

func (s *Server) handleBan(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		web.Error(w, http.StatusBadRequest, "malformed request")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	a := s.accounts[req.ID]
	if a == nil {
		web.Error(w, http.StatusNotFound, "no such account")
		return
	}
	a.Banned = true
	web.JSON(w, http.StatusOK, map[string]bool{"banned": true})
}

func (s *Server) verifyZK(entry *Entry, req verifyRequest, pending pendingRequest) error {
	var p core.Presentation
	if err := json.Unmarshal(req.Presentation, &p); err != nil {
		return errors.New("malformed presentation")
	}
	recordZK(entry, p)
	s.mu.Lock()
	vkey, issuer, snap := s.vkey, s.issuer, s.snapshot
	s.mu.Unlock()
	if vkey == nil {
		return errors.New("site has not loaded the verification key yet")
	}
	if time.Since(pending.createdAt) > requestTTL {
		return errors.New("this request has expired")
	}
	flag := func(on bool) string {
		if on {
			return "1"
		}
		return "0"
	}
	return core.Check(p, vkey, core.Expected{
		Issuer:      issuer,
		Scope:       s.scope,
		RevRoot:     snap.Root,
		CutoffDate:  strconv.Itoa(pending.CutoffDate),
		Today:       strconv.Itoa(pending.Today),
		RequireUtah: flag(pending.RequireUtah),
		Nonce:       pending.Nonce,
		WantPseudo:  flag(pending.WantPseudonym),
	})
}

func recordZK(entry *Entry, p core.Presentation) {
	if named, err := p.Named(); err == nil {
		for k, v := range named {
			entry.Fields[k] = v
		}
	}
	if p.Proof == nil {
		return
	}
	for i, v := range p.Proof.A {
		entry.Fields[fmt.Sprintf("proof.a[%d]", i)] = v
	}
	for i, row := range p.Proof.B {
		for j, v := range row {
			entry.Fields[fmt.Sprintf("proof.b[%d][%d]", i, j)] = v
		}
	}
	for i, v := range p.Proof.C {
		entry.Fields[fmt.Sprintf("proof.c[%d]", i)] = v
	}
}

type standardPresentation struct {
	Disclosed []struct {
		Name  string `json:"name"`
		Value string `json:"value"`
		Salt  string `json:"salt"`
	} `json:"disclosed"`
	Leaves []string `json:"leaves"`
	Sig    core.Sig `json:"sig"`
}

// verifyStandard checks a conventional credential: disclosed claims must hash to
// signed leaves, and the issuer's signature must cover the leaves.
func (s *Server) verifyStandard(entry *Entry, req verifyRequest, pending pendingRequest) error {
	var p standardPresentation
	if err := json.Unmarshal(req.Presentation, &p); err != nil {
		return errors.New("malformed presentation")
	}
	recordStandard(entry, p)
	s.mu.Lock()
	issuer := s.issuer
	s.mu.Unlock()

	leaves := make([]*big.Int, 0, len(p.Leaves))
	for _, l := range p.Leaves {
		n, err := core.ParseField(l)
		if err != nil {
			return errors.New("malformed leaf")
		}
		leaves = append(leaves, n)
	}
	if len(leaves) != 3 {
		return errors.New("wrong number of leaves")
	}
	if err := core.VerifySig(issuer, core.Poseidon(leaves...), p.Sig); err != nil {
		return errors.New("issuer signature is invalid")
	}
	revealed := map[string]bool{}
	for _, c := range p.Disclosed {
		value, err := core.ParseField(c.Value)
		if err != nil {
			return errors.New("malformed claim")
		}
		salt, err := core.ParseField(c.Salt)
		if err != nil {
			return errors.New("malformed claim")
		}
		leaf := core.Poseidon(value, salt).String()
		matched := false
		for _, l := range p.Leaves {
			if l == leaf {
				matched = true
			}
		}
		if !matched {
			return errors.New("disclosed claim is not covered by the signature")
		}
		revealed[c.Name] = c.Value == "1"
	}
	if !revealed[fmt.Sprintf("ageOver%d", pending.MinAge)] {
		return errors.New("required age claim is missing or false")
	}
	if pending.RequireUtah && !revealed["isUtah"] {
		return errors.New("required residency claim is missing or false")
	}
	return nil
}

func recordStandard(entry *Entry, p standardPresentation) {
	for _, c := range p.Disclosed {
		entry.Fields["claim."+c.Name] = c.Value
		entry.Fields["salt."+c.Name] = c.Salt
	}
	for i, l := range p.Leaves {
		entry.Fields[fmt.Sprintf("leaf[%d]", i)] = l
	}
	entry.Fields["signature.r8x"] = p.Sig.R8x
	entry.Fields["signature.r8y"] = p.Sig.R8y
	entry.Fields["signature.s"] = p.Sig.S
}

// collectFields records what was submitted even when the request was unknown,
// so the site's log shows replay attempts.
func (s *Server) collectFields(entry *Entry, req verifyRequest) {
	if req.Mode != "zk" {
		return
	}
	var p core.Presentation
	if json.Unmarshal(req.Presentation, &p) == nil {
		recordZK(entry, p)
	}
}

// saveLast keeps the latest accepted proof on disk for the offline verifier demo.
func (s *Server) saveLast(raw json.RawMessage) {
	dir := filepath.Join(s.cfg.DataDir, s.cfg.Role)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		log.Printf("%s: %v", s.cfg.Role, err)
		return
	}
	if err := os.WriteFile(filepath.Join(dir, "last-presentation.json"), raw, 0o644); err != nil {
		log.Printf("%s: %v", s.cfg.Role, err)
	}
}

func (s *Server) handleLog(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entries := s.entries
	if entries == nil {
		entries = []Entry{}
	}
	web.JSON(w, http.StatusOK, map[string]any{"title": s.cfg.Title, "entries": entries})
}
