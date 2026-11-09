package kev

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/luannt2002/sigforge/framework/fetch"
	"github.com/luannt2002/sigforge/modules/intel/unified"
)

func TestMapSignalStates(t *testing.T) {
	tests := []struct {
		name      string
		in        Signal
		wantState unified.State
		wantLeads int
	}{
		{"in KEV → affected", Signal{CVE: "CVE-1", InKEV: true}, unified.StateAffectedByAdvisory, 1},
		{"not KEV but EPSS → potentially", Signal{CVE: "CVE-2", HasEPSS: true, EPSS: 0.3}, unified.StatePotentiallyAffected, 1},
		// neither source flags it → not_checked with NoteNoClearance, no lead — never a clearance.
		{"no signal → not_checked", Signal{CVE: "CVE-3"}, unified.StateNotChecked, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := MapSignal(tt.in, unified.FreshnessLive, true)
			if u.State != tt.wantState {
				t.Errorf("State = %v, want %v", u.State, tt.wantState)
			}
			if len(u.Leads) != tt.wantLeads {
				t.Errorf("leads = %d, want %d", len(u.Leads), tt.wantLeads)
			}
			if u.Scope != "cve" || u.Source != "kev" {
				t.Errorf("Scope/Source = %q/%q, want cve/kev", u.Scope, u.Source)
			}
		})
	}
}

// The bug this fixes: a missing EPSS score must be nil, never 0.0; a real 0.0 that
// FIRST returns must survive as a non-nil pointer to 0.0.
func TestSignalToLeadNullableEPSS(t *testing.T) {
	missing := SignalToLead(Signal{CVE: "CVE-1", InKEV: true, HasEPSS: false})
	if missing.EPSS != nil {
		t.Errorf("missing EPSS must be nil, got %v", *missing.EPSS)
	}
	if !missing.KnownExpl {
		t.Error("InKEV must set KnownExpl")
	}

	realZero := SignalToLead(Signal{CVE: "CVE-2", HasEPSS: true, EPSS: 0.0})
	if realZero.EPSS == nil {
		t.Fatal("a real EPSS 0.0 must be a non-nil pointer, not dropped as 'missing'")
	}
	if *realZero.EPSS != 0.0 {
		t.Errorf("real EPSS = %v, want 0.0", *realZero.EPSS)
	}
	if realZero.Score != nil {
		t.Errorf("EPSS must never land in Score (the CVSS field), got %v", *realZero.Score)
	}
}

// EnrichUnified must report Snapshot freshness when the live KEV catalog is
// unavailable and the embedded baseline is used — never a false "live".
func TestEnrichUnifiedSnapshotFreshness(t *testing.T) {
	a := New("", "", fetch.New()) // no live KEV URL → embedded snapshot
	got := a.EnrichUnified(context.Background(), []string{"CVE-2021-44228"})
	u, ok := got["CVE-2021-44228"]
	if !ok {
		t.Fatal("Log4Shell must have an entry")
	}
	if u.Freshness != unified.FreshnessSnapshot {
		t.Errorf("snapshot fallback must be FreshnessSnapshot, got %v", u.Freshness)
	}
	if u.State != unified.StateAffectedByAdvisory {
		t.Errorf("Log4Shell is in the KEV snapshot → affected, got %v", u.State)
	}
	// The embedded snapshot has no fetch time; it must NOT fake one.
	if u.FetchedAt != "" {
		t.Errorf("a snapshot run must leave FetchedAt empty, got %q", u.FetchedAt)
	}
}

// A live KEV catalog → Live freshness AND a populated RFC3339 FetchedAt (the
// catalog was really fetched this run), never a snapshot masquerading as live.
func TestEnrichUnifiedLiveFreshnessAndFetchedAt(t *testing.T) {
	a := New(serveJSON(t, kevTestJSON), "", fetch.New())
	got := a.EnrichUnified(context.Background(), []string{"CVE-2021-44228"})
	u, ok := got["CVE-2021-44228"]
	if !ok {
		t.Fatal("Log4Shell must have an entry")
	}
	if u.Freshness != unified.FreshnessLive {
		t.Fatalf("a live catalog must be FreshnessLive, got %v", u.Freshness)
	}
	if u.FetchedAt == "" {
		t.Fatal("a live fetch must populate FetchedAt")
	}
	if _, err := time.Parse(time.RFC3339, u.FetchedAt); err != nil {
		t.Errorf("FetchedAt must be RFC3339: %v (%q)", err, u.FetchedAt)
	}
}

// With only the embedded sample in use (no catalog configured or reachable), a CVE absent from
// that handful of entries was never checked against KEV — it is not_checked, not "not in KEV".
// Against a real catalog the same absence reaches the whole-data branch: still no clearance.
func TestEmbeddedSampleAbsenceIsNotChecked(t *testing.T) {
	const cve = "CVE-2099-12345"
	u := New("", "", fetch.New()).EnrichUnified(context.Background(), []string{cve})[cve]
	if u.State != unified.StateNotChecked || u.Err == "" {
		t.Fatalf("absence from the embedded sample = %v (%q), want not_checked with a reason", u.State, u.Err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"count":1,"vulnerabilities":[{"cveID":"CVE-2021-44228"}]}`))
	}))
	defer srv.Close()
	if u := New(srv.URL, "", fetch.New()).EnrichUnified(context.Background(), []string{cve})[cve]; u.State != unified.StateNotChecked || u.Err != unified.NoteNoClearance {
		t.Fatalf("absence from a real catalog = %v %q, want not_checked with NoteNoClearance", u.State, u.Err)
	}
}

// A catalog proves it is complete by its own count: when the entries do not add up to it (or it
// gives none), absence from it is checked against part of the data; when they do, it reaches
// the whole-data branch (still no clearance).
func TestCatalogMustProveItIsComplete(t *testing.T) {
	const cve = "CVE-2099-12345"
	for body, whole := range map[string]bool{
		`{"count":2,"vulnerabilities":[{"cveID":"CVE-2021-44228"}]}`:                            false,
		`{"vulnerabilities":[{"cveID":"CVE-2021-44228"}]}`:                                      false,
		`{"count":2,"vulnerabilities":[{"cveID":"CVE-2021-44228"},{"cveID":"CVE-2019-11043"}]}`: true,
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(body)) }))
		u := New(srv.URL, "", fetch.New()).EnrichUnified(context.Background(), []string{cve})[cve]
		srv.Close()
		if u.State != unified.StateNotChecked || (u.Err == unified.NoteNoClearance) != whole {
			t.Errorf("%s: absence = %v %q, want not_checked, whole=%v", body, u.State, u.Err, whole)
		}
	}
}
