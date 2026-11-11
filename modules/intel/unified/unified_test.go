package unified

import (
	"encoding/json"
	"reflect"
	"testing"
)

// The JSON a consumer receives decodes back into the same states and freshness — a report
// written by one tool must be readable by another without a custom decoder.
func TestStateAndFreshnessRoundTrip(t *testing.T) {
	for s := StateNotChecked; s <= StateNotAffectedByAdvisory; s++ {
		in := Result{State: s, Freshness: FreshnessStale}
		b, err := json.Marshal(in)
		if err != nil {
			t.Fatal(err)
		}
		var out Result
		if err := json.Unmarshal(b, &out); err != nil || out.State != s || out.Freshness != FreshnessStale {
			t.Fatalf("%s: decoded %+v, %v", b, out, err)
		}
	}
	var r Result
	if err := json.Unmarshal([]byte(`{"state":"clean"}`), &r); err == nil {
		t.Fatal("an unknown state name must be refused, not read as not_checked")
	}
}

// CWEIDs keeps real weakness ids, each once and in one spelling: CWE-079 is CWE-79; NVD's
// placeholders, bare numbers and CWE-0 are not ids.
func TestCWEIDs(t *testing.T) {
	got := CWEIDs([]string{" cwe-79 ", "CWE-079", "NVD-CWE-noinfo", "NVD-CWE-Other", "79", "CWE-", "CWE-0", "CWE-7a", "CWE-1395"})
	if want := []string{"CWE-79", "CWE-1395"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("CWEIDs = %v, want %v", got, want)
	}
}

// Answered tells a caller whether the source gave an answer for the identity — affected, potentially,
// or a lookup in its data that matched nothing — or was off / unavailable / short of its data, which
// must be reported as a gap, never read as "no advisories".
func TestAnswered(t *testing.T) {
	for _, tc := range []struct {
		r    Result
		want bool
	}{
		{Result{State: StateAffectedByAdvisory}, true},
		{Result{State: StatePotentiallyAffected}, true},
		{Result{State: StateUnknownProduct}, true},
		{Result{State: StateUnknownVersion}, true},
		{Result{State: StateNotChecked, Err: NoteNoClearance}, true},
		{Result{State: StateNotChecked, Err: "stale; " + NoteNoClearance}, true},
		{Result{State: StateNotChecked, Err: "osv feed off"}, false},
		{Result{State: StateNotChecked}, false},
		{Result{State: StateSourceUnavailable, Err: "status 503"}, false},
	} {
		if got := tc.r.Answered(); got != tc.want {
			t.Errorf("%v %q: Answered() = %v, want %v", tc.r.State, tc.r.Err, got, tc.want)
		}
	}
}

// LookedUp (the source looked the identity up in its data) and Concluded (that lookup decided whether an
// advisory applies) are two questions: unknown_product, unknown_version and a whole-data miss are looked up
// yet concluded nothing. The first names keep their meaning: Result.Answered is LookedUp, State.Answered is Concluded.
func TestLookedUpAndConcluded(t *testing.T) {
	notes := []string{"", NoteNoClearance, "stale; " + NoteNoClearance}
	for _, tc := range []struct {
		state     State
		lookedUp  [3]bool // per note above
		concluded bool
	}{
		{StateNotChecked, [3]bool{false, true, true}, false},
		{StateSourceUnavailable, [3]bool{false, false, false}, false},
		{StateUnknownProduct, [3]bool{true, true, true}, false},
		{StateUnknownVersion, [3]bool{true, true, true}, false},
		{StatePotentiallyAffected, [3]bool{true, true, true}, true},
		{StateAffectedByAdvisory, [3]bool{true, true, true}, true},
		{StateNotAffectedByAdvisory, [3]bool{true, true, true}, true},
	} {
		for i, note := range notes {
			r := Result{State: tc.state, Err: note}
			if r.LookedUp() != tc.lookedUp[i] || r.State.Concluded() != tc.concluded {
				t.Errorf("%v %q: LookedUp() = %v, Concluded() = %v, want %v, %v", tc.state, note, r.LookedUp(), r.State.Concluded(), tc.lookedUp[i], tc.concluded)
			}
			if r.Answered() != r.LookedUp() || r.State.Answered() != r.State.Concluded() {
				t.Errorf("%v %q: Result.Answered() = %v, State.Answered() = %v: the first names changed meaning", tc.state, note, r.Answered(), r.State.Answered())
			}
		}
	}
}
