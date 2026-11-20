package enrich

import (
	"context"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/luannt2002/sigforge/framework/fetch"
	"github.com/luannt2002/sigforge/modules/intel/cve"
	"github.com/luannt2002/sigforge/modules/intel/kev"
	"github.com/luannt2002/sigforge/modules/intel/lifecycle"
	"github.com/luannt2002/sigforge/modules/intel/matcher"
	"github.com/luannt2002/sigforge/modules/intel/schema"
	"github.com/luannt2002/sigforge/modules/intel/unified"
)

// A detection with no CPE gives the CVE source nothing to ask with: the source was not invoked, so the
// result is not_checked with no_identity — not unknown_product, which would claim the source was asked
// and did not know the product, and would count as "looked up".
func TestNoCPEIsNotCheckedNotUnknownProduct(t *testing.T) {
	db := &schema.DB{SchemaVersion: schema.SchemaVersion, Fingerprints: map[string]schema.Fingerprint{"Acme": {}}}
	out := EnrichUnified(context.Background(), []matcher.Detection{{Tech: "Acme", Version: "2.0"}}, db,
		Options{CVE: fakeCVE{res: cve.Result{State: cve.StateHasCVE, CVEs: []cve.CVE{{ID: "CVE-2099-1"}}}}})
	cpe := byScope(out, "cpe")
	if len(cpe) != 1 || cpe[0].State != unified.StateNotChecked || cpe[0].Reason != unified.ReasonNoIdentity || cpe[0].LookedUp() {
		t.Fatalf("cpe result = %+v, want not_checked / no_identity, not looked up", cpe)
	}
	if direct := cve.ToUnified(cve.Result{}, nil); direct.State != unified.StateNotChecked || direct.Reason != unified.ReasonNoIdentity {
		t.Errorf("cve.ToUnified with no CPE = %s / %q, want not_checked / no_identity", direct.State, direct.Reason)
	}
}

// A detected platform release with OSV off says so: one not_checked result per core package that would
// have been asked, so the gap is named instead of the platform reading as covered by the CVE source alone.
// No version (or one without its patch level) still asks nothing and adds nothing: there is no release.
func TestPlatformOSVOffIsReported(t *testing.T) {
	db := &schema.DB{SchemaVersion: schema.SchemaVersion, Fingerprints: map[string]schema.Fingerprint{"Drupal": {}}}
	for _, tc := range []struct {
		version string
		want    []string // identities of the not_checked OSV results
	}{
		{"9.5.0", []string{"drupal/core", "drupal/drupal"}},
		{"7.59", []string{"drupal/drupal"}},
		{"", nil},
		{"9", nil},
	} {
		var got []string
		for _, r := range EnrichUnified(context.Background(), []matcher.Detection{{Tech: "Drupal", Version: tc.version}}, db, Options{}) {
			if r.Source != "osv" {
				continue
			}
			if r.State != unified.StateNotChecked || r.Reason != unified.ReasonSourceOff || r.Scope != "ecosystem:Packagist" ||
				r.Version != tc.version || r.Tech != "Drupal" {
				t.Errorf("Drupal %q: OSV result %+v, want not_checked / source_off for the release", tc.version, r)
			}
			got = append(got, r.Identity)
		}
		if !slices.Equal(got, tc.want) {
			t.Errorf("Drupal %q: OSV not_checked identities %v, want %v", tc.version, got, tc.want)
		}
	}
}

// The kev field says what known_exploited was checked against: the catalog, the embedded sample (absence
// from a handful of entries says nothing), or nothing at all. Results without a CVE lead carry none.
func TestKEVFieldNamesWhatWasChecked(t *testing.T) {
	catalog := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"count":1,"vulnerabilities":[{"cveID":"CVE-2099-0001"}]}`))
	}))
	defer catalog.Close()
	dets := []matcher.Detection{{Tech: "Nginx", Version: "1.18.0"}}
	base := Options{
		CVE: fakeCVE{res: cve.Result{State: cve.StateHasCVE, CVEs: []cve.CVE{{ID: "CVE-2099-0002"}}}},
		EOL: fakeEOL{st: lifecycle.Status{Product: "nginx", Cycle: "1.18", EOLDate: "2021-04-21", IsEOL: lifecycle.StateEOL}},
	}
	for _, tc := range []struct {
		name string
		kev  KEVProvider
		want string
	}{
		{"catalog", kev.New(catalog.URL, "", fetch.New()), "catalog"},
		{"embedded sample", kev.New("", "", fetch.New()), "sample"},
		{"not consulted", nil, ""},
		{"no status to tell", fakeKEV{}, ""},
	} {
		opt := base
		opt.KEV = tc.kev
		out := EnrichUnified(context.Background(), dets, testDB(), opt)
		if c := byScope(out, "cpe"); len(c) != 1 || c[0].KEV != tc.want {
			t.Errorf("%s: cpe result kev = %q, want %q", tc.name, c[0].KEV, tc.want)
		}
		if e := byScope(out, "eol"); len(e) != 1 || e[0].KEV != "" {
			t.Errorf("%s: an EOL result names no CVE, so no kev: %+v", tc.name, e)
		}
	}
}

// A result from a page detection carries where its version came from and how sure the detection is; an
// identity the operator gave carries "inventory" and no detection confidence.
func TestEnrichCarriesVersionFromAndConfidence(t *testing.T) {
	dets := []matcher.Detection{{Tech: "Nginx", Version: "1.18.0", VersionFrom: "header", Confidence: 75}}
	opt := Options{CVE: fakeCVE{res: cve.Result{State: cve.StateNoKnownCVE}}, OSV: func(_ context.Context, eco, name, version string) unified.Result {
		return unified.Result{State: unified.StateUnknownProduct, Scope: "ecosystem:" + eco, Identity: name, Version: version, Source: "osv"}
	}}
	out := EnrichUnifiedExt(context.Background(), dets, testDB(), EnrichInput{Packages: []PkgRef{{Ecosystem: "npm", Name: "lodash", Version: "4.17.20"}}}, opt)
	for _, r := range out {
		switch r.Scope {
		case "cpe", "eol":
			if r.VersionFrom != "header" || r.DetectionConfidence != 75 {
				t.Errorf("%s: version_from %q confidence %d, want header / 75", r.Scope, r.VersionFrom, r.DetectionConfidence)
			}
		case "ecosystem:npm":
			if r.VersionFrom != "inventory" || r.DetectionConfidence != 0 {
				t.Errorf("package: version_from %q confidence %d, want inventory / 0", r.VersionFrom, r.DetectionConfidence)
			}
		}
	}
}

// Results that disagree are all kept, each with what limits it: a version conflict downgrades a hit to
// potentially_affected (version_conflict), one source affected beside another that does not know the product
// keeps both, a doubted lead stays doubted though KEV lists it, and an excluded tech's results keep their state.
func TestConflictingResultsAreKept(t *testing.T) {
	ctx := context.Background()
	hit := fakeCVE{res: cve.Result{State: cve.StateHasCVE, CVEs: []cve.CVE{{ID: "CVE-2099-0002"}}}}

	conflict := EnrichUnified(ctx, []matcher.Detection{{Tech: "Nginx", Version: "1.18.0", VersionConflict: true,
		VersionClaims: []matcher.VersionClaim{{Version: "1.18.0", Field: "header"}, {Version: "1.20.1", Field: "html"}}}}, testDB(), Options{CVE: hit})
	if c := byScope(conflict, "cpe"); len(c) != 1 || c[0].State != unified.StatePotentiallyAffected || c[0].Reason != unified.ReasonVersionConflict || len(c[0].Leads) != 1 {
		t.Errorf("version conflict: %+v, want potentially_affected / version_conflict with the lead kept", c)
	}
	if e := byScope(conflict, "eol"); len(e) != 1 || e[0].Reason != unified.ReasonSourceOff {
		t.Errorf("version conflict on an unanswered result keeps its own reason: %+v", e)
	}

	disagree := EnrichUnifiedExt(ctx, []matcher.Detection{{Tech: "Nginx", Version: "1.18.0"}}, testDB(),
		EnrichInput{Packages: []PkgRef{{Ecosystem: "npm", Name: "nginx", Version: "1.18.0"}}},
		Options{CVE: hit, OSV: func(_ context.Context, eco, name, version string) unified.Result {
			return unified.Result{State: unified.StateUnknownProduct, Reason: unified.ReasonNotInSource, Scope: "ecosystem:" + eco, Identity: name, Version: version, Source: "osv"}
		}})
	if c, o := byScope(disagree, "cpe"), byScope(disagree, "ecosystem:npm"); len(c) != 1 || c[0].State != unified.StateAffectedByAdvisory ||
		len(o) != 1 || o[0].State != unified.StateUnknownProduct {
		t.Errorf("sources that disagree must both be kept: cpe %+v · osv %+v", c, o)
	}

	doubted := unified.Result{State: unified.StateAffectedByAdvisory, Scope: "ecosystem:npm", Identity: "lodash", Version: "4.17.20", Source: "osv",
		Leads: []unified.Lead{{ID: "GHSA-sure", CVE: []string{"CVE-2099-0003"}}, {ID: "GHSA-doubt", CVE: []string{"CVE-2099-0004"}, Note: "may not apply"}}}
	kevAll := fakeKEV{m: map[string]unified.Result{
		"CVE-2099-0004": {State: unified.StateAffectedByAdvisory, Leads: []unified.Lead{{ID: "CVE-2099-0004", KnownExpl: true}}},
	}}
	ext := EnrichUnifiedExt(ctx, nil, nil, EnrichInput{Packages: []PkgRef{{Ecosystem: "npm", Name: "lodash", Version: "4.17.20"}}},
		Options{OSV: func(context.Context, string, string, string) unified.Result { return doubted }, KEV: kevAll})
	seen := 0
	for _, r := range ext {
		for _, l := range r.Leads {
			if l.ID == "GHSA-doubt" {
				seen++
				if l.Note == "" || !l.KnownExpl {
					t.Errorf("a doubted lead KEV lists must stay doubted and carry the KEV mark: %+v", l)
				}
			}
		}
	}
	if seen != 1 {
		t.Errorf("the doubted lead must be reported exactly once, got %d", seen)
	}

	excluded := EnrichUnified(ctx, []matcher.Detection{{Tech: "Nginx", Version: "1.18.0", ExcludedBy: []string{"Apache"}}}, testDB(), Options{CVE: hit})
	if c := byScope(excluded, "cpe"); len(c) != 1 || c[0].State != unified.StateAffectedByAdvisory || c[0].Reason != "" {
		t.Errorf("excluded by is a note, never a downgrade: %+v", c)
	}
}

// A tech whose name maps to no end-of-life product is asked of the bundle by each of its CPEs, in order, until one the
// bundle lists: that CPE's verdict stands whatever order the CPEs come in; when none is listed the bundle answered and
// does not know the product; with no CPE, or a per-product feed (which takes names, not CPEs), nothing was asked.
func TestEOLAskedByCPEWhenTheNameMapsToNone(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"result":[{"name":"acmeprod","identifiers":[{"type":"cpe","id":"cpe:2.3:a:acme:acme:*:*:*:*:*:*:*:*"}],` +
			`"releases":[{"name":"1.0","isEol":true}]}]}`))
	}))
	defer srv.Close()
	const listed, other = "cpe:2.3:a:acme:acme:*:*:*:*:*:*:*:*", "cpe:2.3:a:other:other:*:*:*:*:*:*:*:*"
	for _, tc := range []struct {
		name   string
		cpes   []string
		bundle bool
		state  unified.State
		reason string
	}{
		{"unlisted CPE first", []string{other, listed}, true, unified.StateAffectedByAdvisory, ""},
		{"listed CPE first", []string{listed, other}, true, unified.StateAffectedByAdvisory, ""},
		{"no CPE the bundle lists", []string{other}, true, unified.StateUnknownProduct, unified.ReasonNotInSource},
		{"no CPE at all", nil, true, unified.StateNotChecked, unified.ReasonNoIdentity},
		{"per-product feed", []string{listed}, false, unified.StateNotChecked, unified.ReasonNoIdentity},
	} {
		eol := lifecycle.New(srv.URL, fetch.New())
		if tc.bundle {
			eol = lifecycle.NewBundle(srv.URL, fetch.New())
		}
		db := &schema.DB{SchemaVersion: schema.SchemaVersion, Fingerprints: map[string]schema.Fingerprint{"Acme Thing": {CPE: tc.cpes}}}
		e := byScope(EnrichUnified(context.Background(), []matcher.Detection{{Tech: "Acme Thing", Version: "1.0.3"}}, db, Options{EOL: eol}), "eol")
		if len(e) != 1 || e[0].State != tc.state || e[0].Reason != tc.reason {
			t.Errorf("%s: eol result %+v, want %s / %q", tc.name, e, tc.state, tc.reason)
		}
	}
}
