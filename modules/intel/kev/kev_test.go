package kev

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/luannt2002/sigforge/framework/fetch"
)

// kevTestJSON is the real upstream KEV shape: an outer object + vulnerabilities[]
// with both a Known and an Unknown ransomware value to exercise the flag.
const kevTestJSON = `{
  "title": "CISA Catalog of Known Exploited Vulnerabilities",
  "catalogVersion": "2026.09.14",
  "count": 3,
  "vulnerabilities": [
    {"cveID":"CVE-2021-44228","vendorProject":"Apache","product":"Log4j2","vulnerabilityName":"Log4Shell","dateAdded":"2021-12-10","knownRansomwareCampaignUse":"Known"},
    {"cveID":"CVE-2018-13379","vendorProject":"Fortinet","product":"FortiOS","vulnerabilityName":"FortiOS Path Traversal","dateAdded":"2021-11-03","knownRansomwareCampaignUse":"Known"},
    {"cveID":"CVE-2014-0160","vendorProject":"OpenSSL","product":"OpenSSL","vulnerabilityName":"Heartbleed","dateAdded":"2022-05-04","knownRansomwareCampaignUse":"Unknown"}
  ]
}`

// epssTestJSON is the real EPSS shape: data[] with epss/percentile as STRINGS.
const epssTestJSON = `{
  "status":"OK","status-code":200,"version":"1.0","access":"public","total":2,"offset":0,"limit":100,
  "data":[
    {"cve":"CVE-2021-44228","epss":"0.944210000","percentile":"0.999500000","date":"2026-09-15"},
    {"cve":"CVE-2014-0160","epss":"0.010000000","percentile":"0.400000000","date":"2026-09-15"}
  ]
}`

func serveJSON(t *testing.T, body string) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func serve500(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "down", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

// ---- ExtractCVEs (pure) ----

func TestExtractCVEs(t *testing.T) {
	got := ExtractCVEs(
		"SRV-CVE-CVE-2021-23017",
		"detail: hit by CVE-2020-11022 and cve-2019-11358",
		"CVE-2021-23017 appears again", // duplicate → deduped
		"JSLIB-CVE-2015-9251 in the bundle",
		"a string with no id, CVE-abc, CVE-2021", // not a CVE → dropped
	)
	want := []string{"CVE-2021-23017", "CVE-2020-11022", "CVE-2019-11358", "CVE-2015-9251"}
	if len(got) != len(want) {
		t.Fatalf("want %v, got %v", want, got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("at %d: want %v, got %v", i, want, got)
		}
	}
}

func TestExtractCVEsEmpty(t *testing.T) {
	if got := ExtractCVEs("nothing here", "CVE-xx-yy"); len(got) != 0 {
		t.Fatalf("want empty, got %v", got)
	}
}

// ---- PriorityFor (pure table) ----

func TestPriorityFor(t *testing.T) {
	cases := []struct {
		name string
		in   Signal
		want string
	}{
		{"KEV → P0", Signal{CVE: "CVE-1", InKEV: true}, "P0"},
		{"ransomware → P0", Signal{CVE: "CVE-2", InKEV: true, Ransomware: true}, "P0"},
		{"ransomware own flag still P0", Signal{CVE: "CVE-2b", Ransomware: true}, "P0"},
		{"EPSS 0.7 → P1", Signal{CVE: "CVE-3", EPSS: 0.7}, "P1"},
		{"EPSS exactly 0.5 → P1", Signal{CVE: "CVE-3b", EPSS: 0.5}, "P1"},
		{"percentile 0.96 → P1", Signal{CVE: "CVE-4", EPSSPct: 0.96}, "P1"},
		{"percentile exactly 0.95 → P1", Signal{CVE: "CVE-4b", EPSSPct: 0.95}, "P1"},
		{"EPSS 0.01 → empty", Signal{CVE: "CVE-5", EPSS: 0.01, EPSSPct: 0.4}, ""},
		{"all 0 → empty", Signal{CVE: "CVE-6"}, ""},
		{"KEV wins even when EPSS is low", Signal{CVE: "CVE-7", InKEV: true, EPSS: 0.0}, "P0"},
	}
	for _, c := range cases {
		if got := PriorityFor(c.in); got != c.want {
			t.Errorf("%s: want %q, got %q", c.name, c.want, got)
		}
	}
}

// ---- ParseKEV / ParseEPSS (pure) ----

func TestParseKEV(t *testing.T) {
	m, err := ParseKEV([]byte(kevTestJSON))
	if err != nil {
		t.Fatalf("ParseKEV: %v", err)
	}
	if len(m) != 3 {
		t.Fatalf("want 3 entries, got %d", len(m))
	}
	log4, ok := m["CVE-2021-44228"]
	if !ok || !log4.Ransomware || log4.Product != "Log4j2" {
		t.Fatalf("Log4Shell parsed wrong: %+v ok=%v", log4, ok)
	}
	// Unknown → ransomware must stay false, never guessed true.
	if hb := m["CVE-2014-0160"]; hb.Ransomware {
		t.Fatal("Heartbleed knownRansomwareCampaignUse=Unknown but came out true")
	}
	// The key is always UPPER, looked up via a normalized source value.
	if _, ok := m[normalizeCVE("cve-2018-13379")]; !ok {
		t.Fatal("the map key must be UPPER and looked up")
	}
}

func TestParseEPSS(t *testing.T) {
	m, err := ParseEPSS([]byte(epssTestJSON))
	if err != nil {
		t.Fatalf("ParseEPSS: %v", err)
	}
	if len(m) != 2 {
		t.Fatalf("want 2, got %d", len(m))
	}
	// epss/percentile are strings in JSON → must parse to floats.
	if log4 := m["CVE-2021-44228"]; log4.EPSS < 0.94 || log4.EPSSPct < 0.99 {
		t.Fatalf("Log4Shell EPSS parsed wrong: %+v", log4)
	}
	if hb := m["CVE-2014-0160"]; hb.EPSS > 0.02 {
		t.Fatalf("Heartbleed EPSS parsed wrong: %+v", hb)
	}
}

// ---- Enrich over httptest (no real network) ----

func TestEnrichMergesKEVAndEPSS(t *testing.T) {
	a := New(serveJSON(t, kevTestJSON), serveJSON(t, epssTestJSON), fetch.New())

	// Dirty input: a CVE embedded in a finding id + a duplicate + a CVE no source knows.
	in := ExtractCVEs("SRV-CVE-CVE-2021-44228", "detail CVE-2014-0160", "CVE-2021-44228", "CVE-9999-1")
	got := a.Enrich(context.Background(), in)

	log4 := got["CVE-2021-44228"]
	if !log4.InKEV || !log4.Ransomware || log4.EPSS < 0.94 {
		t.Fatalf("Log4Shell did not merge enough KEV+EPSS: %+v", log4)
	}
	if p := PriorityFor(log4); p != "P0" {
		t.Fatalf("Log4Shell must be P0, got %q", p)
	}
	// In KEV but ransomware Unknown + low EPSS → still P0 because InKEV.
	hb := got["CVE-2014-0160"]
	if !hb.InKEV || hb.Ransomware || hb.EPSS > 0.02 {
		t.Fatalf("Heartbleed merged wrong: %+v", hb)
	}
	if p := PriorityFor(hb); p != "P0" {
		t.Fatalf("Heartbleed InKEV must be P0, got %q", p)
	}
	// A CVE no source knows: an entry must still exist (empty Signal) → priority "".
	unknown, ok := got["CVE-9999-1"]
	if !ok {
		t.Fatal("a CVE with no signal must still have an entry")
	}
	if unknown.InKEV || unknown.EPSS != 0 || PriorityFor(unknown) != "" {
		t.Fatalf("an unknown CVE must be an empty Signal with empty priority: %+v", unknown)
	}
}

func TestEnrichEmptyInput(t *testing.T) {
	a := New("http://127.0.0.1:1/should-not-hit", "http://127.0.0.1:1/should-not-hit", fetch.New())
	if got := a.Enrich(context.Background(), nil); len(got) != 0 {
		t.Fatalf("empty input must return empty, got %+v", got)
	}
}

// Both sources down → fail-open: an entry per CVE, no panic, and the embedded
// public-domain snapshot still recognizes Log4Shell as P0. Absence is never "safe".
func TestEnrichFailOpenBothSourcesDown(t *testing.T) {
	down := serve500(t)
	a := New(down, down, fetch.New())
	got := a.Enrich(context.Background(), []string{"CVE-2021-44228", "CVE-9999-1"})
	if len(got) != 2 {
		t.Fatalf("want 2 entries even when sources are down, got %d", len(got))
	}
	if p := PriorityFor(got["CVE-2021-44228"]); p != "P0" {
		t.Fatalf("the KEV snapshot must save Log4Shell as P0, got %q", p)
	}
	// A CVE neither the snapshot nor EPSS knows → empty Signal, priority "" (not "safe").
	if p := PriorityFor(got["CVE-9999-1"]); p != "" {
		t.Fatalf("an unknown CVE must have empty priority, got %q", p)
	}
}

// EPSS off (empty URL) → KEV snapshot still drives priority, no EPSS scores, no network for EPSS.
func TestEnrichEPSSOffUsesSnapshot(t *testing.T) {
	a := New("", "", fetch.New())
	got := a.Enrich(context.Background(), []string{"CVE-2021-44228", "CVE-2014-0160"})
	// Log4Shell is a ransomware CVE in the embedded snapshot → P0, with no EPSS score.
	log4 := got["CVE-2021-44228"]
	if !log4.InKEV || log4.EPSS != 0 || PriorityFor(log4) != "P0" {
		t.Fatalf("snapshot-only Log4Shell wrong: %+v", log4)
	}
}

// A live KEV feed serving junk (a proxy injecting HTML) falls back to the snapshot, no panic.
func TestEnrichGarbageKEVFeedFallsBackToSnapshot(t *testing.T) {
	a := New(serveJSON(t, "<html>Access Denied</html>"), "", fetch.New())
	got := a.Enrich(context.Background(), []string{"CVE-2021-44228"})
	if p := PriorityFor(got["CVE-2021-44228"]); p != "P0" {
		t.Fatalf("garbage feed must fall back to the snapshot (P0), got %q", p)
	}
}

// The EPSS URL really coalesces MANY CVEs into one request via ?cve=A,B.
func TestEnrichEPSSBatchesIntoOneRequest(t *testing.T) {
	var reqs int
	var gotCVE string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqs++
		gotCVE = r.URL.Query().Get("cve")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(epssTestJSON))
	}))
	defer srv.Close()

	// Empty KEV URL so only EPSS is hit; two CVEs must coalesce into one EPSS request.
	a := New("", srv.URL, fetch.New())
	a.Enrich(context.Background(), []string{"CVE-2021-44228", "CVE-2014-0160"})
	if reqs != 1 {
		t.Fatalf("want 1 coalesced EPSS request, got %d", reqs)
	}
	if !strings.Contains(gotCVE, ",") {
		t.Fatalf("want multiple CVEs comma-separated, got %q", gotCVE)
	}
}

// The embedded snapshot must carry at least one ransomware CVE so the air-gap P0 branch means something.
func TestEmbeddedSnapshotHasRansomware(t *testing.T) {
	m, err := ParseKEV(kevSnapshot)
	if err != nil {
		t.Fatalf("snapshot parse: %v", err)
	}
	if len(m) == 0 {
		t.Fatal("embedded snapshot is empty — is data/kev-snapshot.json broken?")
	}
	var ransom int
	for _, e := range m {
		if e.Ransomware {
			ransom++
		}
	}
	if ransom == 0 {
		t.Fatal("the snapshot has no ransomware CVE")
	}
}
