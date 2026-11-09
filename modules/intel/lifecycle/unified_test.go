package lifecycle

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
		st        Status
		err       error
		wantState unified.State
		wantFresh unified.Freshness
	}{
		{"feed off → not_checked", Status{Product: "php"}, ErrFeedOff, unified.StateNotChecked, unified.FreshnessUnknown},
		{"fetch error → source_unavailable", Status{Product: "php"}, errors.New("boom"), unified.StateSourceUnavailable, unified.FreshnessUnknown},
		// EOLStatus only matches a cycle for a real version, so an EOL verdict carries one.
		{"eol at a version → affected + live", Status{Product: "php", Version: "7.2.34", Cycle: "7.2", EOLDate: "2020-11-30", IsEOL: StateEOL}, nil, unified.StateAffectedByAdvisory, unified.FreshnessLive},
		{"supported → not_checked (no clearance) + live", Status{Product: "php", Cycle: "8.3", IsEOL: StateSupported}, nil, unified.StateNotChecked, unified.FreshnessLive},
		// unmapped tech: unknown PRODUCT, never not_affected.
		{"unmapped product → unknown_product", Status{Product: "", IsEOL: StateUnknown}, nil, unified.StateUnknownProduct, unified.FreshnessUnknown},
		// mapped product, cycle not matched: unknown VERSION.
		{"mapped but no cycle → unknown_version", Status{Product: "php", Cycle: "", IsEOL: StateUnknown}, nil, unified.StateUnknownVersion, unified.FreshnessLive},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := ToUnified(tt.st, tt.err)
			if u.State != tt.wantState {
				t.Errorf("State = %v, want %v", u.State, tt.wantState)
			}
			if u.Freshness != tt.wantFresh {
				t.Errorf("Freshness = %v, want %v", u.Freshness, tt.wantFresh)
			}
			if u.Scope != "eol" {
				t.Errorf("Scope = %q, want eol", u.Scope)
			}
		})
	}
}

// A fetched status carries its fetch time as RFC3339; an unmapped product (never
// fetched) leaves FetchedAt empty — never a fabricated timestamp.
func TestToUnifiedFetchedAt(t *testing.T) {
	at := time.Now().UTC()
	u := ToUnified(Status{Product: "php", Cycle: "8.3", IsEOL: StateSupported, FetchedAt: at}, nil)
	if u.Freshness != unified.FreshnessLive {
		t.Fatalf("a fetched status must be live, got %v", u.Freshness)
	}
	if u.FetchedAt == "" {
		t.Fatal("a fetched status must populate FetchedAt")
	}
	if _, err := time.Parse(time.RFC3339, u.FetchedAt); err != nil {
		t.Errorf("FetchedAt must be RFC3339: %v (%q)", err, u.FetchedAt)
	}
	if un := ToUnified(Status{Product: "", IsEOL: StateUnknown}, nil); un.FetchedAt != "" {
		t.Errorf("unmapped product never fetched; FetchedAt must stay empty, got %q", un.FetchedAt)
	}
}

func TestToUnifiedEOLLead(t *testing.T) {
	u := ToUnified(Status{Product: "php", Version: "7.2.34", Cycle: "7.2", EOLDate: "2020-11-30", IsEOL: StateEOL}, nil)
	if len(u.Leads) != 1 {
		t.Fatalf("want 1 lead, got %d", len(u.Leads))
	}
	l := u.Leads[0]
	if l.ID != "eol:php:7.2" {
		t.Errorf("lead ID = %q, want eol:php:7.2", l.ID)
	}
	// Honest: an EOL lead carries no CVE and no fabricated score.
	if len(l.CVE) != 0 || l.Score != nil {
		t.Errorf("EOL lead must have no CVE and nil Score: %+v", l)
	}
	if l.Title == "" {
		t.Error("EOL lead should describe the cycle/eol date")
	}
}

func TestToUnifiedStaleSupportedKeepsItsNote(t *testing.T) {
	u := ToUnified(Status{Product: "nginx", Version: "1.22.1", Cycle: "1.22", IsEOL: StateSupported, Stale: true, FetchedAt: time.Now()}, nil)
	if u.State != unified.StateNotChecked || u.Freshness != unified.FreshnessStale || !strings.HasPrefix(u.Err, "endoflife source failed") || !strings.HasSuffix(u.Err, unified.NoteNoClearance) {
		t.Errorf("got %v %v %q, want not_checked, stale, with the stale note and the no-clearance note", u.State, u.Freshness, u.Err)
	}
}
