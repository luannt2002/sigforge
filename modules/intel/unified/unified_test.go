package unified

import (
	"encoding/json"
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
