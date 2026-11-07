// Package web holds small HTTP helpers shared by every role.
package web

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// JSON writes v as a JSON response.
func JSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// Error writes a JSON error response.
func Error(w http.ResponseWriter, status int, msg string) {
	JSON(w, status, map[string]string{"error": msg})
}

// CORS allows the demo's roles, which run on separate origins, to call each other.
func CORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// RequestEntry is one request seen by a role.
type RequestEntry struct {
	Time   string `json:"time"`
	Method string `json:"method"`
	Path   string `json:"path"`
}

// RequestLog records every request a role receives, excluding its own debug and
// static routes. The console uses the state's copy to show that verification
// generates no traffic to the state.
type RequestLog struct {
	mu      sync.Mutex
	entries []RequestEntry
}

// Entries returns a copy of the log.
func (l *RequestLog) Entries() []RequestEntry {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]RequestEntry(nil), l.entries...)
}

// Middleware records requests to API paths.
func (l *RequestLog) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodOptions && !strings.HasPrefix(r.URL.Path, "/debug") {
			l.mu.Lock()
			l.entries = append(l.entries, RequestEntry{
				Time:   time.Now().UTC().Format(time.RFC3339),
				Method: r.Method,
				Path:   r.URL.Path,
			})
			l.mu.Unlock()
		}
		next.ServeHTTP(w, r)
	})
}

// SPA serves the built frontend, with the role's config at /config.json.
func SPA(mux *http.ServeMux, distDir string, config any) {
	mux.HandleFunc("GET /config.json", func(w http.ResponseWriter, _ *http.Request) {
		JSON(w, http.StatusOK, config)
	})
	files := http.FileServer(http.Dir(distDir))
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		path := filepath.Join(distDir, filepath.Clean(r.URL.Path))
		if info, err := os.Stat(path); err != nil || info.IsDir() {
			http.ServeFile(w, r, filepath.Join(distDir, "index.html"))
			return
		}
		files.ServeHTTP(w, r)
	})
}
