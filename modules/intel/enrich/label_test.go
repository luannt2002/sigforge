package enrich

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/luannt2002/sigforge/modules/intel/cve"
	"github.com/luannt2002/sigforge/modules/intel/matcher"
	"github.com/luannt2002/sigforge/modules/intel/schema"
	"github.com/luannt2002/sigforge/modules/intel/unified"
)

// advisoryCVE answers every lookup with one CVE, so B's CPE result is a firm, lead-carrying
// affected_by_advisory answer that the label must leave untouched; no network.
type advisoryCVE struct{}

func (advisoryCVE) Lookup(_ context.Context, cpe, version string) (cve.Result, error) {
	return cve.Result{CPE: cpe, Version: version, State: cve.StateHasCVE,
		CVEs: []cve.CVE{{ID: "CVE-2024-0001", CVSS: 9.8, Severity: "CRITICAL"}}}, nil
}

// The excludes label reaches the unified results a scanner reads: every result of a labeled
// detection gains an "excluded by" note and nothing else — state and leads untouched, on a
// firm affected_by_advisory answer as on an unanswered one — while an unlabeled detection's
// results carry no such note.
func TestEnrichNotesExcludedBy(t *testing.T) {
	db := &schema.DB{SchemaVersion: schema.SchemaVersion, Fingerprints: map[string]schema.Fingerprint{
		"A": {HTML: schema.StringList{"a-marker"}, Excludes: schema.StringList{"B"}},
		"B": {HTML: schema.StringList{`b-marker-([\d.]+)\;version:\1`}, CPE: []string{"cpe:2.3:a:acme:b:*:*:*:*:*:*:*:*"}},
	}}
	ctx := context.Background()
	opt := Options{CVE: advisoryCVE{}}
	both := EnrichUnified(ctx, matcher.Match(db, matcher.Page{HTML: "a-marker b-marker-1.2"}), db, opt)
	alone := EnrichUnified(ctx, matcher.Match(db, matcher.Page{HTML: "b-marker-1.2"}), db, opt)

	firm := false
	for _, r := range alone {
		firm = firm || (r.State == unified.StateAffectedByAdvisory && len(r.Leads) > 0)
	}
	if !firm {
		t.Fatalf("fixture lost its affected_by_advisory result with a lead, so a label that changed state or leads would go unseen: %+v", alone)
	}

	var labeled []unified.Result
	for _, r := range both {
		switch r.Tech {
		case "A":
			if strings.Contains(r.Err, "excluded by") {
				t.Errorf("unlabeled A carries a label note: %q", r.Err)
			}
		case "B":
			labeled = append(labeled, r)
		}
	}
	if len(labeled) != len(alone) {
		t.Fatalf("B results: %d with A, %d alone", len(labeled), len(alone))
	}
	for i, r := range alone {
		if strings.Contains(r.Err, "excluded by") {
			t.Errorf("B alone carries a label note: %q", r.Err)
		}
		want := r
		want.Err = strings.TrimPrefix(r.Err+"; excluded by: A", "; ")
		if !reflect.DeepEqual(labeled[i], want) {
			t.Errorf("B result %d:\n got  %+v\n want %+v", i, labeled[i], want)
		}
	}
}
