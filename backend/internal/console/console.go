// Package console plays the attacker. It pools the sites' logs, and optionally
// everything a cheating state kept, then tries to work out who is who using only
// real log data over HTTP. It gets no help from the wallet.
package console

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"

	"unlinked/internal/core"
	"unlinked/internal/site"
	"unlinked/internal/web"
)

// Config lists the roles the attacker can read from.
type Config struct {
	SiteAURL string
	SiteBURL string
	StateURL string
}

// Server is the console role.
type Server struct{ cfg Config }

// New creates a console.
func New(cfg Config) *Server { return &Server{cfg: cfg} }

// Routes registers the console's HTTP API.
func (s *Server) Routes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/attack", s.handleAttack)
	mux.HandleFunc("POST /api/replay", s.handleReplay)
	mux.HandleFunc("GET /api/state", s.handleState)
}

type siteLog struct {
	Title   string       `json:"title"`
	Entries []site.Entry `json:"entries"`
}

type shadowRecord struct {
	Person string            `json:"person"`
	Values map[string]string `json:"values"`
}

type summary struct {
	Issued      int                `json:"issued"`
	Epoch       int                `json:"epoch"`
	Escrow      []json.RawMessage  `json:"escrow"`
	Shadow      []shadowRecord     `json:"shadow"`
	Revocations []json.RawMessage  `json:"revocations"`
	Requests    []web.RequestEntry `json:"requests"`
}

func getJSON(url string, v any) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: %s", url, resp.Status)
	}
	return json.NewDecoder(resp.Body).Decode(v)
}

// Link is a pair of presentations the attacker could tie to the same holder.
type Link struct {
	SiteA int    `json:"siteA"`
	SiteB int    `json:"siteB"`
	Field string `json:"field"`
	Value string `json:"value"`
}

// Identified is a presentation the attacker tied to a named person.
type Identified struct {
	Site   string `json:"site"`
	Index  int    `json:"index"`
	Person string `json:"person"`
	Field  string `json:"field"`
}

// FieldRow says how much one logged field helps the attacker.
type FieldRow struct {
	Field     string `json:"field"`
	DistinctA int    `json:"distinctA"`
	DistinctB int    `json:"distinctB"`
	Shared    int    `json:"shared"`
	Verdict   string `json:"verdict"`
}

// Result is the outcome of one attack run.
type Result struct {
	Mode       string       `json:"mode"`
	Malicious  bool         `json:"malicious"`
	EntriesA   int          `json:"entriesA"`
	EntriesB   int          `json:"entriesB"`
	TitleA     string       `json:"titleA"`
	TitleB     string       `json:"titleB"`
	LinkedA    int          `json:"linkedA"`
	Links      []Link       `json:"links"`
	Identified []Identified `json:"identified"`
	Fields     []FieldRow   `json:"fields"`
}

const (
	verdictCrowd  = "same for the whole crowd"
	verdictSite   = "differs by site, not by person"
	verdictUnique = "unique per presentation, never repeats"
	verdictLinks  = "LINKS HOLDERS across sites"
	verdictWindow = "same for everyone presenting in the same time window"
)

// windowFields hold values that are public by design and cannot differ between
// holders who present at the same time. They shrink the crowd to that window
// rather than pointing at a person, so they are reported but not joined on.
// Publishing revocation epochs on a schedule keeps that crowd large.
var windowFields = map[string]bool{"today": true, "revRoot": true, "cutoffDate": true}

func (s *Server) handleAttack(w http.ResponseWriter, r *http.Request) {
	mode := r.URL.Query().Get("mode")
	if mode != "zk" && mode != "standard" {
		web.Error(w, http.StatusBadRequest, "mode must be zk or standard")
		return
	}
	malicious := r.URL.Query().Get("malicious") == "1"

	var a, b siteLog
	if err := getJSON(s.cfg.SiteAURL+"/api/log", &a); err != nil {
		web.Error(w, http.StatusBadGateway, err.Error())
		return
	}
	if err := getJSON(s.cfg.SiteBURL+"/api/log", &b); err != nil {
		web.Error(w, http.StatusBadGateway, err.Error())
		return
	}
	var shadow []shadowRecord
	if malicious {
		var sum summary
		if err := getJSON(s.cfg.StateURL+"/debug/summary", &sum); err != nil {
			web.Error(w, http.StatusBadGateway, err.Error())
			return
		}
		shadow = sum.Shadow
	}
	web.JSON(w, http.StatusOK, Attack(mode, a.Title, b.Title, accepted(a.Entries, mode), accepted(b.Entries, mode), shadow, malicious))
}

func accepted(entries []site.Entry, mode string) []site.Entry {
	out := []site.Entry{}
	for _, e := range entries {
		if e.Mode == mode && e.Result == "accepted" {
			out = append(out, e)
		}
	}
	return out
}

// Attack joins the logs on every logged value. A value that most entries on a
// site share cannot single anyone out, so those are excluded from the join.
func Attack(mode, titleA, titleB string, a, b []site.Entry, shadow []shadowRecord, malicious bool) Result {
	res := Result{
		Mode: mode, Malicious: malicious, EntriesA: len(a), EntriesB: len(b),
		TitleA: titleA, TitleB: titleB, Links: []Link{}, Identified: []Identified{}, Fields: []FieldRow{},
	}

	commonA := crowdValues(a)
	commonB := crowdValues(b)
	isCrowd := func(v string) bool { return commonA[v] || commonB[v] }

	// Attempt 1: find values that appear in both sites' logs.
	inB := map[string][]int{}
	for i, e := range b {
		for f, v := range e.Fields {
			if !isCrowd(v) && !windowFields[f] {
				inB[v] = append(inB[v], i)
			}
		}
	}
	linkedA := map[int]bool{}
	seen := map[[2]int]bool{}
	for i, e := range a {
		for _, field := range sortedKeys(e.Fields) {
			v := e.Fields[field]
			if isCrowd(v) || windowFields[field] {
				continue
			}
			for _, j := range inB[v] {
				linkedA[i] = true
				pair := [2]int{i, j}
				if seen[pair] {
					continue
				}
				seen[pair] = true
				res.Links = append(res.Links, Link{SiteA: i, SiteB: j, Field: field, Value: v})
			}
		}
	}
	res.LinkedA = len(linkedA)

	// Attempt 2: match log values against everything a cheating state retained.
	owner := map[string]struct{ person, field string }{}
	for _, rec := range shadow {
		for field, v := range rec.Values {
			owner[v] = struct{ person, field string }{rec.Person, field}
		}
	}
	identify := func(siteName string, entries []site.Entry) {
		for i, e := range entries {
			for _, field := range sortedKeys(e.Fields) {
				if o, ok := owner[e.Fields[field]]; ok {
					res.Identified = append(res.Identified, Identified{Site: siteName, Index: i, Person: o.person, Field: field})
					break
				}
			}
		}
	}
	identify(titleA, a)
	identify(titleB, b)

	res.Fields = fieldTable(a, b, commonA, commonB)
	return res
}

// crowdValues returns values appearing in at least half of a log's entries.
func crowdValues(entries []site.Entry) map[string]bool {
	counts := map[string]int{}
	for _, e := range entries {
		seen := map[string]bool{}
		for _, v := range e.Fields {
			if !seen[v] {
				seen[v] = true
				counts[v]++
			}
		}
	}
	out := map[string]bool{}
	for v, c := range counts {
		if c*2 >= len(entries) && len(entries) > 1 {
			out[v] = true
		}
	}
	return out
}

func fieldTable(a, b []site.Entry, commonA, commonB map[string]bool) []FieldRow {
	names := map[string]bool{}
	valuesA := map[string]map[string]bool{}
	valuesB := map[string]map[string]bool{}
	collect := func(entries []site.Entry, into map[string]map[string]bool) {
		for _, e := range entries {
			for f, v := range e.Fields {
				names[f] = true
				if into[f] == nil {
					into[f] = map[string]bool{}
				}
				into[f][v] = true
			}
		}
	}
	collect(a, valuesA)
	collect(b, valuesB)

	rows := []FieldRow{}
	for f := range names {
		shared := 0
		for v := range valuesA[f] {
			if valuesB[f][v] {
				shared++
			}
		}
		row := FieldRow{Field: f, DistinctA: len(valuesA[f]), DistinctB: len(valuesB[f]), Shared: shared}
		switch {
		case windowFields[f]:
			row.Verdict = verdictWindow
		case allIn(valuesA[f], commonA) && allIn(valuesB[f], commonB) && shared > 0:
			row.Verdict = verdictCrowd
		case allIn(valuesA[f], commonA) && allIn(valuesB[f], commonB):
			row.Verdict = verdictSite
		case hasPersonalOverlap(valuesA[f], valuesB[f], commonA, commonB):
			row.Verdict = verdictLinks
		default:
			row.Verdict = verdictUnique
		}
		rows = append(rows, row)
	}
	sort.Slice(rows, func(i, j int) bool {
		if (rows[i].Verdict == verdictLinks) != (rows[j].Verdict == verdictLinks) {
			return rows[i].Verdict == verdictLinks
		}
		return rows[i].Field < rows[j].Field
	})
	return rows
}

func allIn(values, set map[string]bool) bool {
	for v := range values {
		if !set[v] {
			return false
		}
	}
	return true
}

func hasPersonalOverlap(a, b, commonA, commonB map[string]bool) bool {
	for v := range a {
		if b[v] && !commonA[v] && !commonB[v] {
			return true
		}
	}
	return false
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// handleReplay takes the latest accepted proof from Site A, then tries to reuse
// it on Site A and on Site B, and returns what each site said.
func (s *Server) handleReplay(w http.ResponseWriter, _ *http.Request) {
	var a siteLog
	if err := getJSON(s.cfg.SiteAURL+"/api/log", &a); err != nil {
		web.Error(w, http.StatusBadGateway, err.Error())
		return
	}
	entries := accepted(a.Entries, "zk")
	if len(entries) == 0 {
		web.Error(w, http.StatusConflict, "no accepted proof to replay yet")
		return
	}
	last := entries[len(entries)-1]
	var p core.Presentation
	if err := json.Unmarshal(last.Raw, &p); err != nil {
		web.Error(w, http.StatusInternalServerError, err.Error())
		return
	}
	named, err := p.Named()
	if err != nil {
		web.Error(w, http.StatusInternalServerError, err.Error())
		return
	}

	type attempt struct {
		Name   string `json:"name"`
		OK     bool   `json:"ok"`
		Reason string `json:"reason"`
	}
	results := []attempt{}

	// Same site, same nonce: the nonce has already been used.
	ok, reason, err := submit(s.cfg.SiteAURL, named["nonce"], last.Raw)
	if err != nil {
		web.Error(w, http.StatusBadGateway, err.Error())
		return
	}
	results = append(results, attempt{"Replay to " + a.Title, ok, reason})

	// Different site, with a fresh live nonce from that site.
	var fresh struct {
		Nonce string `json:"nonce"`
	}
	if err := getJSON(s.cfg.SiteBURL+"/api/request", &fresh); err != nil {
		web.Error(w, http.StatusBadGateway, err.Error())
		return
	}
	ok, reason, err = submit(s.cfg.SiteBURL, fresh.Nonce, last.Raw)
	if err != nil {
		web.Error(w, http.StatusBadGateway, err.Error())
		return
	}
	results = append(results, attempt{"Relay to the other site", ok, reason})

	web.JSON(w, http.StatusOK, map[string]any{"attempts": results})
}

func submit(siteURL, nonce string, presentation json.RawMessage) (bool, string, error) {
	body, err := json.Marshal(map[string]any{"mode": "zk", "nonce": nonce, "presentation": presentation})
	if err != nil {
		return false, "", err
	}
	resp, err := http.Post(siteURL+"/api/verify", "application/json", bytes.NewReader(body))
	if err != nil {
		return false, "", err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, "", err
	}
	var out struct {
		OK     bool   `json:"ok"`
		Reason string `json:"reason"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return false, "", err
	}
	return out.OK, out.Reason, nil
}

// handleState passes through the state's records so the console can display them.
func (s *Server) handleState(w http.ResponseWriter, _ *http.Request) {
	var sum map[string]any
	if err := getJSON(s.cfg.StateURL+"/debug/summary", &sum); err != nil {
		web.Error(w, http.StatusBadGateway, err.Error())
		return
	}
	web.JSON(w, http.StatusOK, sum)
}
