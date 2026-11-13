package osv

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/luannt2002/sigforge/framework/fetch"
	"github.com/luannt2002/sigforge/modules/intel/unified"
)

// A pinned version inside an advisory range → affected_by_advisory, with the lead mapped and no score.
func TestToUnifiedAffected(t *testing.T) {
	idx := npmIndex(t)
	u := ToUnified(idx.Lookup("lodash", "4.17.20"), "npm", "lodash", "4.17.20", idx.BuiltAt)
	if u.State != unified.StateAffectedByAdvisory {
		t.Fatalf("pinned in-range must be affected_by_advisory, got %s", u.State)
	}
	if u.Scope != "ecosystem:npm" || u.Source != "osv" || u.Freshness != unified.FreshnessLive {
		t.Fatalf("wrong envelope: %+v", u)
	}
	if u.FetchedAt == "" {
		t.Fatal("a non-zero BuiltAt must populate FetchedAt")
	}
	if len(u.Leads) != 1 || len(u.Leads[0].CVE) != 1 || u.Leads[0].CVE[0] != "CVE-2021-23337" {
		t.Fatalf("lead not mapped: %+v", u.Leads)
	}
	if u.Leads[0].Score != nil {
		t.Fatal("OSV carries no numeric score; Lead.Score must stay nil")
	}
}

// A resolved out-of-range version in a whole dump → not_checked with NoteNoClearance.
func TestToUnifiedNotAffected(t *testing.T) {
	// a whole dump: npmIndex carries a corrupt entry, which leaves its answers unproven
	u := ToUnified(buildNpm(t, "GHSA-35jh-r3h4-6jhm", advLodash).Lookup("lodash", "4.17.21"), "npm", "lodash", "4.17.21", time.Time{})
	if u.State != unified.StateNotChecked || u.Err != unified.NoteNoClearance {
		t.Fatalf("resolved out-of-range must reach the whole-data branch, got %s %q", u.State, u.Err)
	}
	if u.FetchedAt != "" {
		t.Fatalf("a zero fetchedAt must leave FetchedAt empty, got %q", u.FetchedAt)
	}
}

// An unpinnable version (a manifest range) against a known package → potentially_affected: advisories
// exist but the version is not confirmed. NOT affected_by_advisory, NOT clean.
func TestToUnifiedUnpinnedVersionIsPotentiallyAffected(t *testing.T) {
	res := npmIndex(t).Lookup("lodash", "^4.0.0")
	if res.Status != StatusVulnerable || res.VersionPinned {
		t.Fatalf("precondition: unpinned vulnerable, got status=%s pinned=%v", res.Status, res.VersionPinned)
	}
	u := ToUnified(res, "npm", "lodash", "^4.0.0", time.Time{})
	if u.State != unified.StatePotentiallyAffected {
		t.Fatalf("unpinnable version must be potentially_affected, got %s", u.State)
	}
	if len(u.Leads) == 0 {
		t.Fatal("potentially_affected from advisories must still surface the leads")
	}
}

// A known package whose version cannot be positioned (Unknown + PackageKnown) → potentially_affected,
// explicitly NEITHER affected_by_advisory NOR not_affected_by_advisory (the honesty split).
func TestToUnifiedUnknownVersionIsPotentiallyAffected(t *testing.T) {
	res := Result{Status: StatusUnknown, PackageKnown: true, VersionPinned: true}
	u := ToUnified(res, "npm", "lodash", "weird-version", time.Time{})
	if u.State != unified.StatePotentiallyAffected {
		t.Fatalf("known package, unpositionable version must be potentially_affected, got %s", u.State)
	}
	if u.State == unified.StateAffectedByAdvisory || u.State == unified.StateNotAffectedByAdvisory {
		t.Fatal("an unknown version must be neither affected nor clean")
	}
}

// A package absent from the index (Unknown + !PackageKnown) → unknown_product, never "clean".
func TestToUnifiedUnknownPackage(t *testing.T) {
	res := npmIndex(t).Lookup("totally-unseen-pkg", "1.0.0")
	if res.Status != StatusUnknown || res.PackageKnown {
		t.Fatalf("precondition: unindexed package, got status=%s known=%v", res.Status, res.PackageKnown)
	}
	u := ToUnified(res, "npm", "totally-unseen-pkg", "1.0.0", time.Time{})
	if u.State != unified.StateUnknownProduct {
		t.Fatalf("an unindexed package must be unknown_product, got %s", u.State)
	}
}

// Source off (empty env URL) → not_checked; any other load failure → source_unavailable.
func TestUnavailableSourceOffVsDead(t *testing.T) {
	_, offErr := New("", fetch.New()).LoadIndex(context.Background(), "npm")
	if offErr == nil {
		t.Fatal("source off must error")
	}
	u := Unavailable("npm", "lodash", "4.0.0", offErr)
	if u.State != unified.StateNotChecked {
		t.Fatalf("source off must map to not_checked, got %s", u.State)
	}
	if u.Scope != "ecosystem:npm" || u.Source != "osv" || u.Err == "" {
		t.Fatalf("envelope/err missing on not_checked: %+v", u)
	}
	if u.Freshness != unified.FreshnessUnknown {
		t.Fatalf("not_checked carries no fetched data ⇒ freshness unknown, got %s", u.Freshness)
	}

	dead := Unavailable("npm", "lodash", "4.0.0", fmt.Errorf("osv npm: download: status 500"))
	if dead.State != unified.StateSourceUnavailable {
		t.Fatalf("a dead source must map to source_unavailable, got %s", dead.State)
	}
	if dead.Freshness != unified.FreshnessUnknown {
		t.Fatalf("source_unavailable carries no fetched data ⇒ freshness unknown, got %s", dead.Freshness)
	}
}

// Every potentially_affected answer says why it is not pinned, and every result of one lookup
// names the ecosystem the same way, release or not.
func TestPotentialAnswersSayWhyAndScopeIsStable(t *testing.T) {
	unpinned := ToUnified(Result{Status: StatusVulnerable, Vulns: []Vuln{{ID: "GHSA-1"}}, PackageKnown: true}, "npm", "lodash", "", time.Time{})
	unplaced := ToUnified(Result{Status: StatusUnknown, PackageKnown: true, VersionPinned: true}, "npm", "lodash", "4.x-weird", time.Time{})
	for _, u := range []unified.Result{unpinned, unplaced} {
		if u.State != unified.StatePotentiallyAffected || u.Err == "" {
			t.Errorf("potentially affected must say why, got %v %q", u.State, u.Err)
		}
	}
	down := New("http://127.0.0.1:1", fetch.New()).Lookuper()(context.Background(), "debian:12", "openssl", "3.0.11-1")
	if down.Scope != "ecosystem:Debian:12" {
		t.Errorf("an unanswered Debian:12 lookup scope = %q, want ecosystem:Debian:12 like an answered one", down.Scope)
	}
}

// "No known vulnerability" for a version that was never pinned compared nothing: it is a gap.
func TestNoKnownVulnWithoutPinnedVersionIsNotClean(t *testing.T) {
	u := ToUnified(Result{Status: StatusNoKnownVuln, PackageKnown: true}, "npm", "lodash", "", time.Time{})
	if u.State == unified.StateNotAffectedByAdvisory || u.Err == "" || u.Err == unified.NoteNoClearance {
		t.Fatalf("got %v %q, want a named gap that is not the whole-data one", u.State, u.Err)
	}
	if u := ToUnified(Result{Status: StatusNoKnownVuln, PackageKnown: true, VersionPinned: true}, "npm", "lodash", "4.17.21", time.Time{}); u.Err != unified.NoteNoClearance {
		t.Fatalf("a pinned version clear of every record reaches the whole-data branch, got %v %q", u.State, u.Err)
	}
}

// FullData says the answer came from the whole dump, on every branch: a dump with an entry it could not read
// carries false, so what is absent from it is never read as gone.
func TestToUnifiedSaysWhetherTheDumpWasWhole(t *testing.T) {
	for _, res := range []Result{
		{Status: StatusVulnerable, Vulns: []Vuln{{ID: "GHSA-1"}}, PackageKnown: true, VersionPinned: true},
		{Status: StatusVulnerable, Vulns: []Vuln{{ID: "GHSA-1"}}, PackageKnown: true},
		{Status: StatusNoKnownVuln, PackageKnown: true, VersionPinned: true},
		{Status: StatusNoKnownVuln, PackageKnown: true},
		{Status: StatusUnknown, Vulns: []Vuln{{ID: "GHSA-1"}}, PackageKnown: true, VersionPinned: true},
		{Status: StatusUnknown},
	} {
		for _, partial := range []bool{false, true} {
			res.Partial = partial
			if u := ToUnified(res, "npm", "lodash", "4.17.20", time.Time{}); u.FullData == partial {
				t.Errorf("%s known=%v pinned=%v partial=%v: FullData = %v (%s)", res.Status, res.PackageKnown, res.VersionPinned, partial, u.FullData, u.State)
			}
		}
	}
	// npmIndex carries a corrupt entry, buildNpm reads every entry
	if u := ToUnified(npmIndex(t).Lookup("totally-unseen-pkg", "1.0.0"), "npm", "totally-unseen-pkg", "1.0.0", time.Time{}); u.FullData {
		t.Errorf("a package absent from a dump with an unreadable entry must not be FullData: %+v", u)
	}
	if u := ToUnified(buildNpm(t, "GHSA-35jh-r3h4-6jhm", advLodash).Lookup("totally-unseen-pkg", "1.0.0"), "npm", "totally-unseen-pkg", "1.0.0", time.Time{}); !u.FullData {
		t.Errorf("a package absent from a whole dump is FullData: %+v", u)
	}
}
