// Package trustee holds the only key that can open the fraud escrow. It stands in
// for an independent party acting on a court order, in line with 63A-20-301(4)(e)(ii).
// A production version would split this key across several independent holders.
package trustee

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/nacl/box"

	"unlinked/internal/web"
)

// Server is the trustee role.
type Server struct {
	pub  [32]byte
	priv [32]byte
}

// New loads or creates the trustee's key pair.
func New(dataDir string) (*Server, error) {
	s := &Server{}
	path := filepath.Join(dataDir, "trustee.key")
	if raw, err := os.ReadFile(path); err == nil && len(raw) == 64 {
		copy(s.pub[:], raw[:32])
		copy(s.priv[:], raw[32:])
		return s, nil
	}
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	s.pub, s.priv = *pub, *priv
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, err
	}
	return s, os.WriteFile(path, append(s.pub[:], s.priv[:]...), 0o600)
}

// Routes registers the trustee's HTTP API.
func (s *Server) Routes(mux *http.ServeMux) {
	mux.HandleFunc("GET /pubkey", func(w http.ResponseWriter, _ *http.Request) {
		web.JSON(w, http.StatusOK, map[string]string{"publicKey": hex.EncodeToString(s.pub[:])})
	})
	mux.HandleFunc("POST /decrypt", s.handleDecrypt)
}

func (s *Server) handleDecrypt(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Ciphertext string `json:"ciphertext"`
		CourtOrder string `json:"courtOrder"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		web.Error(w, http.StatusBadRequest, "malformed request")
		return
	}
	if strings.TrimSpace(req.CourtOrder) == "" {
		web.Error(w, http.StatusForbidden, "a court order reference is required")
		return
	}
	raw, err := hex.DecodeString(req.Ciphertext)
	if err != nil {
		web.Error(w, http.StatusBadRequest, "malformed ciphertext")
		return
	}
	token, ok := box.OpenAnonymous(nil, raw, &s.pub, &s.priv)
	if !ok {
		web.Error(w, http.StatusBadRequest, "ciphertext does not open with this key")
		return
	}
	web.JSON(w, http.StatusOK, map[string]string{"token": string(token)})
}
