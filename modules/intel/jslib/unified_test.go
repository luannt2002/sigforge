package jslib

import (
	"context"
	"testing"

	"github.com/luannt2002/sigforge/framework/fetch"
	"github.com/luannt2002/sigforge/modules/intel/unified"
)

// An installed version inside a published range → affected_by_advisory, leads mapped, no numeric score.
func TestToUnifiedAffected(t *testing.T) {
	repo, _ := ParseRepo([]byte(flatRepoJSON))
	u := ToUnified(resolve(repo, "jQuery", "1.6.2"))
	if u.State != unified.StateAffectedByAdvisory {
		t.Fatalf("in-range version must be affected_by_advisory, got %s", u.State)
	}
	if u.Scope != "jslib" || u.Source != "jslib" || u.Freshness != unified.FreshnessSnapshot {
		t.Fatalf("wrong envelope: %+v", u)
	}
	if len(u.Leads) != 2 || u.Leads[0].ID != "CVE-2011-4969" {
		t.Fatalf("leads not mapped: %+v", u.Leads)
	}
	if u.Leads[0].Score != nil {
		t.Fatal("Retire.js is unscored; Lead.Score must stay nil")
	}
}

// Known library, version out of every range → not_checked with a reason (no clearance).
func TestToUnifiedNotAffected(t *testing.T) {
	repo, _ := ParseRepo([]byte(flatRepoJSON))
	u := ToUnified(resolve(repo, "jquery", "3.6.0"))
	if u.State != unified.StateNotChecked || u.Err == "" {
		t.Fatalf("resolved out-of-range is no clearance (the repository cannot prove itself whole), got %s %q", u.State, u.Err)
	}
	if len(u.Leads) != 0 {
		t.Fatalf("a miss carries no leads, got %+v", u.Leads)
	}
}

// A library the feed does not list → unknown_product, never "clean".
func TestToUnifiedUnknownProduct(t *testing.T) {
	repo, _ := ParseRepo([]byte(flatRepoJSON))
	u := ToUnified(resolve(repo, "left-pad", "1.0.0"))
	if u.State != unified.StateUnknownProduct {
		t.Fatalf("a library not in the feed must be unknown_product, got %s", u.State)
	}
}

// A detected-but-uncomparable version (git hash / "trunk") → unknown_version, never "clean".
func TestToUnifiedUnknownVersion(t *testing.T) {
	repo, _ := ParseRepo([]byte(flatRepoJSON))
	u := ToUnified(resolve(repo, "jquery", "trunk"))
	if u.State != unified.StateUnknownVersion {
		t.Fatalf("an uncomparable version must be unknown_version, got %s", u.State)
	}
}

// A LIVE operator feed that actually answered → FreshnessLive (no longer hardcoded snapshot).
func TestToUnifiedFreshnessLive(t *testing.T) {
	a := New(serveJSON(t, nestedRepoJSON), fetch.New())
	u := ToUnified(a.LookupOne(context.Background(), "angularjs", "1.7.0"))
	if u.Freshness != unified.FreshnessLive {
		t.Fatalf("a feed fetched live must report FreshnessLive, got %s", u.Freshness)
	}
}

// An empty operator URL falls open to the embedded snapshot → FreshnessSnapshot (honest).
func TestToUnifiedFreshnessSnapshot(t *testing.T) {
	a := New("", fetch.New())
	u := ToUnified(a.LookupOne(context.Background(), "jquery", "3.3.0"))
	if u.Freshness != unified.FreshnessSnapshot {
		t.Fatalf("the snapshot fallback must report FreshnessSnapshot, got %s", u.Freshness)
	}
}
