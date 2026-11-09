package cve

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/luannt2002/sigforge/modules/intel/unified"
)

func TestToUnifiedStates(t *testing.T) {
	tests := []struct {
		name      string
		res       Result
		err       error
		wantState unified.State
		wantFresh unified.Freshness
	}{
		{"feed off → not_checked", Result{}, ErrFeedOff, unified.StateNotChecked, unified.FreshnessUnknown},
		{"fetch error → source_unavailable", Result{}, errors.New("boom"), unified.StateSourceUnavailable, unified.FreshnessUnknown},
		// empty CPE: honestly unknown-product, NEVER not_affected (a false "clean").
		{"empty CPE → unknown_product", Result{State: StateUnknown}, nil, unified.StateUnknownProduct, unified.FreshnessUnknown},
		{"no known cve → not_checked (no clearance) + live", Result{State: StateNoKnownCVE}, nil, unified.StateNotChecked, unified.FreshnessLive},
		{"has cve at a version → affected + live", Result{State: StateHasCVE, Version: "1.18.0"}, nil, unified.StateAffectedByAdvisory, unified.FreshnessLive},
		// no version: the feed listed every advisory for the PRODUCT, none pinned to the
		// running version — potentially affected, never "the version is in a range".
		{"has cve without a version → potentially_affected", Result{State: StateHasCVE}, nil, unified.StatePotentiallyAffected, unified.FreshnessLive},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := ToUnified(tt.res, tt.err)
			if u.State != tt.wantState {
				t.Errorf("State = %v, want %v", u.State, tt.wantState)
			}
			if u.Freshness != tt.wantFresh {
				t.Errorf("Freshness = %v, want %v", u.Freshness, tt.wantFresh)
			}
			if u.Scope != "cpe" || u.Source != "cve" {
				t.Errorf("Scope/Source = %q/%q, want cpe/cve", u.Scope, u.Source)
			}
		})
	}
}

// A fetched result carries its fetch time as RFC3339; a result that never
// fetched (feed off) leaves FetchedAt empty — never a fabricated timestamp.
func TestToUnifiedFetchedAt(t *testing.T) {
	at := time.Now().UTC()
	u := ToUnified(Result{State: StateNoKnownCVE, FetchedAt: at}, nil)
	if u.Freshness != unified.FreshnessLive {
		t.Fatalf("a fetched result must be live, got %v", u.Freshness)
	}
	if u.FetchedAt == "" {
		t.Fatal("a fetched result must populate FetchedAt")
	}
	if _, err := time.Parse(time.RFC3339, u.FetchedAt); err != nil {
		t.Errorf("FetchedAt must be RFC3339: %v (%q)", err, u.FetchedAt)
	}
	if off := ToUnified(Result{}, ErrFeedOff); off.FetchedAt != "" {
		t.Errorf("feed off never fetched; FetchedAt must stay empty, got %q", off.FetchedAt)
	}
}

func TestToUnifiedLeadsAndNullableScore(t *testing.T) {
	res := Result{
		CPE:     "cpe:2.3:a:f5:nginx:1.18.0:*:*:*:*:*:*:*",
		Version: "1.18.0",
		State:   StateHasCVE,
		CVEs: []CVE{
			{ID: "CVE-2021-23017", CVSS: 7.7, Severity: "HIGH", Source: "nvd@nist.gov"},
			{ID: "CVE-NO-SCORE", CVSS: 0, Severity: ""}, // feed gave no metric → Score must be nil
		},
	}
	u := ToUnified(res, nil)
	if len(u.Leads) != 2 {
		t.Fatalf("want 2 leads, got %d", len(u.Leads))
	}
	scored := u.Leads[0]
	if scored.Severity != "HIGH" || scored.CVSS != "7.7" {
		t.Errorf("CVSS/severity passthrough wrong: %+v", scored)
	}
	if scored.Score == nil || *scored.Score != 7.7 {
		t.Errorf("Score should be a real 7.7, got %v", scored.Score)
	}
	if u.Leads[1].Score != nil {
		t.Errorf("a CVE with no metric must have a nil Score, got %v", *u.Leads[1].Score)
	}
}

// A lead list that cannot be taken at face value says why in Err: no version (every
// advisory for the product), or one page of a paged feed (more CVEs exist than came
// back). A versioned, complete answer carries no note.
func TestToUnifiedNotes(t *testing.T) {
	one := []CVE{{ID: "CVE-2021-0001"}}
	if u := ToUnified(Result{State: StateHasCVE, CVEs: one, Total: 1}, nil); !strings.Contains(u.Err, "no version") {
		t.Errorf("versionless leads must say no version was detected, Err = %q", u.Err)
	}
	if u := ToUnified(Result{State: StateHasCVE, Version: "1.0", CVEs: one, Total: 2500}, nil); !strings.Contains(u.Err, "1 of 2500") {
		t.Errorf("a truncated page must say how much is missing, Err = %q", u.Err)
	}
	if u := ToUnified(Result{State: StateHasCVE, Version: "1.0", CVEs: one, Total: 1}, nil); u.Err != "" {
		t.Errorf("a versioned, complete answer must carry no note, Err = %q", u.Err)
	}
}
