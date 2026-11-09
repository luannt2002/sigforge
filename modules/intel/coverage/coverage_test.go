package coverage

import (
	"reflect"
	"testing"

	"github.com/luannt2002/sigforge/modules/intel/baseline"
	"github.com/luannt2002/sigforge/modules/intel/schema"
	"github.com/luannt2002/sigforge/modules/intel/unified"
)

func TestDB(t *testing.T) {
	db := &schema.DB{Fingerprints: map[string]schema.Fingerprint{
		"Full":      {CPE: []string{"cpe:2.3:a:x:full:*:*:*:*:*:*:*:*"}, VersionRegex: []string{`full/([\d.]+)\;version:\1`}, Provenance: "baseline", License: "Apache-2.0"},
		"Borrowed":  {CPECandidate: []string{"cpe:2.3:a:y:borrowed:*:*:*:*:*:*:*:*"}, HTML: schema.StringList{"marker"}, Provenance: "baseline", License: "Apache-2.0"},
		"Versioned": {Headers: map[string]schema.StringList{"Server": {`v/([\d.]+)\;version:\1`}}, Provenance: "webappanalyzer", License: "GPL-3.0"},
		"Bare":      {HTML: schema.StringList{"bare"}},
	}}
	got := DB(db)
	want := DBReport{
		Fingerprints:  4,
		WithCPE:       1,
		CandidateOnly: 1,
		WithVersion:   2,
		Blind:         []string{"Bare", "Borrowed"}, // a borrowed CPE is not looked up, so it does not count as a CVE bridge
		ByProvenance:  map[string]int{"baseline": 2, "webappanalyzer": 1, "unknown": 1},
		ByLicense:     map[string]int{"Apache-2.0": 2, "GPL-3.0": 1, "unknown": 1},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("DB coverage:\n got %+v\nwant %+v", got, want)
	}
	if r := DB(nil); r.Fingerprints != 0 || r.Blind == nil {
		t.Fatalf("nil DB must report zero coverage with a non-nil Blind list, got %+v", r)
	}
}

// The embedded baseline is measured, not asserted against made-up numbers: the test
// logs the real coverage and checks only invariants that must hold for any DB.
func TestDBBaseline(t *testing.T) {
	db, err := baseline.DB()
	if err != nil {
		t.Fatal(err)
	}
	r := DB(db)
	t.Logf("baseline: %d fingerprints · %d with CPE · %d candidate-only · %d with version · %d blind %v",
		r.Fingerprints, r.WithCPE, r.CandidateOnly, r.WithVersion, len(r.Blind), r.Blind)
	if r.Fingerprints != len(db.Fingerprints) || r.Fingerprints == 0 {
		t.Fatalf("fingerprints = %d, DB has %d", r.Fingerprints, len(db.Fingerprints))
	}
	if r.WithCPE+r.CandidateOnly > r.Fingerprints || r.WithVersion > r.Fingerprints || len(r.Blind) > r.Fingerprints {
		t.Fatalf("a bucket exceeds the total: %+v", r)
	}
	for name, m := range map[string]map[string]int{"provenance": r.ByProvenance, "license": r.ByLicense} {
		sum := 0
		for _, n := range m {
			sum += n
		}
		if sum != r.Fingerprints {
			t.Fatalf("by_%s sums to %d, want %d", name, sum, r.Fingerprints)
		}
	}
}

func TestResults(t *testing.T) {
	rs := []unified.Result{
		{}, // zero value = not_checked: never answered
		{State: unified.StateSourceUnavailable},
		{State: unified.StateUnknownVersion, Freshness: unified.FreshnessLive},
		{State: unified.StateAffectedByAdvisory, Freshness: unified.FreshnessLive},
		{State: unified.StatePotentiallyAffected, Freshness: unified.FreshnessSnapshot},
		{State: unified.StateNotAffectedByAdvisory, Freshness: unified.FreshnessStale},
	}
	got := Results(rs)
	if got.Total != 6 || got.Answered != 3 || got.Unanswered != 3 {
		t.Fatalf("total/answered/unanswered = %d/%d/%d, want 6/3/3", got.Total, got.Answered, got.Unanswered)
	}
	wantStates := map[string]int{
		"not_checked": 1, "source_unavailable": 1, "unknown_product": 0, "unknown_version": 1,
		"potentially_affected": 1, "affected_by_advisory": 1, "not_affected_by_advisory": 1,
	}
	if !reflect.DeepEqual(got.ByState, wantStates) {
		t.Fatalf("by_state = %v, want %v (every state present, zeros included)", got.ByState, wantStates)
	}
	wantFresh := map[string]int{"unknown": 2, "live": 2, "snapshot": 1, "stale": 1}
	if !reflect.DeepEqual(got.ByFreshness, wantFresh) {
		t.Fatalf("by_freshness = %v, want %v", got.ByFreshness, wantFresh)
	}
}
