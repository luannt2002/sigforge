package enrich

import (
	"context"
	"testing"

	"github.com/luannt2002/sigforge/modules/intel/cve"
	"github.com/luannt2002/sigforge/modules/intel/lifecycle"
	"github.com/luannt2002/sigforge/modules/intel/matcher"
	"github.com/luannt2002/sigforge/modules/intel/schema"
)

// fakeCVE / fakeEOL are injected providers: no network, deterministic answers.
type fakeCVE struct {
	res cve.Result
	err error
}

func (f fakeCVE) Lookup(_ context.Context, cpe, version string) (cve.Result, error) {
	r := f.res
	r.CPE, r.Version = cpe, version
	return r, f.err
}

type fakeEOL struct {
	st  lifecycle.Status
	err error
}

func (f fakeEOL) EOLStatus(_ context.Context, _, version string) (lifecycle.Status, error) {
	s := f.st
	s.Version = version
	return s, f.err
}

func testDB() *schema.DB {
	return &schema.DB{
		SchemaVersion: schema.SchemaVersion,
		Fingerprints: map[string]schema.Fingerprint{
			"Nginx": {Cats: []int{22}, CPE: []string{"cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*"}, Provenance: "baseline"},
		},
	}
}

func TestEnrichAttachesDepthWhenProvidersSet(t *testing.T) {
	dets := []matcher.Detection{{Tech: "Nginx", Version: "1.18.0", Confidence: 100, Provenance: "baseline"}}
	opt := Options{
		CVE: fakeCVE{res: cve.Result{State: cve.StateHasCVE, CVEs: []cve.CVE{{ID: "CVE-2021-23017", CVSS: 7.7, Severity: "HIGH"}}}},
		EOL: fakeEOL{st: lifecycle.Status{Product: "nginx", Cycle: "1.18", EOLDate: "2021-04-21", IsEOL: lifecycle.StateEOL}},
	}
	got := Enrich(context.Background(), dets, testDB(), opt)
	if len(got) != 1 {
		t.Fatalf("want 1 enriched, got %d", len(got))
	}
	ed := got[0]
	if len(ed.CVEs) != 1 || ed.CVEs[0].ID != "CVE-2021-23017" {
		t.Errorf("CVEs = %+v, want one CVE-2021-23017", ed.CVEs)
	}
	if ed.EOL.IsEOL != lifecycle.StateEOL {
		t.Errorf("EOL = %+v, want StateEOL", ed.EOL)
	}
	if len(ed.CPE) != 1 {
		t.Errorf("CPE should come from the DB entry, got %+v", ed.CPE)
	}
	if ed.Version != "1.18.0" {
		t.Errorf("version = %q, want 1.18.0", ed.Version)
	}
}

func TestEnrichProvidersNilStaysUnknown(t *testing.T) {
	dets := []matcher.Detection{{Tech: "Nginx", Version: "1.18.0", Confidence: 100, Provenance: "baseline"}}
	got := Enrich(context.Background(), dets, testDB(), Options{}) // both providers nil
	if len(got) != 1 {
		t.Fatalf("want 1 enriched, got %d", len(got))
	}
	ed := got[0]
	if ed.CVEs != nil {
		t.Errorf("CVE provider off → CVEs must stay nil (UNKNOWN, not 'safe'), got %+v", ed.CVEs)
	}
	if ed.EOL.IsEOL != lifecycle.StateUnknown {
		t.Errorf("EOL provider off → must stay StateUnknown (never 'supported'), got %v", ed.EOL.IsEOL)
	}
}

func TestEnrichCorroborationCountsDistinctProvenance(t *testing.T) {
	// same tech attested by two different sources → corroboration (provenance) ≥ 2.
	dets := []matcher.Detection{
		{Tech: "Nginx", Version: "1.18.0", Confidence: 100, Provenance: "baseline"},
		{Tech: "Nginx", Version: "1.18.0", Confidence: 80, Provenance: "nuclei"},
	}
	got := Enrich(context.Background(), dets, nil, Options{})
	if len(got) != 1 {
		t.Fatalf("two dets of one tech must collapse to 1 result, got %d", len(got))
	}
	if n := len(got[0].Provenance); n < 2 {
		t.Errorf("corroboration = %d (%v), want ≥2 distinct sources", n, got[0].Provenance)
	}
	if got[0].Confidence != 100 {
		t.Errorf("confidence should be the max across sources, got %d", got[0].Confidence)
	}
}
