package enrich

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/luannt2002/sigforge/modules/intel/cve"
	"github.com/luannt2002/sigforge/modules/intel/identity"
	"github.com/luannt2002/sigforge/modules/intel/lifecycle"
	"github.com/luannt2002/sigforge/modules/intel/matcher"
	"github.com/luannt2002/sigforge/modules/intel/schema"
	"github.com/luannt2002/sigforge/modules/intel/unified"
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

// --- EnrichUnified: injected providers, no network ---

// recordingCVE records every CPE it was queried with, so a test can prove which
// identity reached the CVE lookup (verified vs attested vs — never — a candidate).
type recordingCVE struct {
	queried []string
	res     cve.Result
}

func (r *recordingCVE) Lookup(_ context.Context, cpe, version string) (cve.Result, error) {
	r.queried = append(r.queried, cpe)
	out := r.res
	out.CPE, out.Version = cpe, version
	return out, nil
}

type fakeResolver struct {
	cpe   string
	state identity.State
}

func (f fakeResolver) resolve(_ context.Context, _, _, _ string) (string, string, identity.State) {
	return f.cpe, "", f.state
}

type fakeKEV struct{ m map[string]unified.Result }

func (f fakeKEV) EnrichUnified(_ context.Context, _ []string) map[string]unified.Result { return f.m }

func byScope(rs []unified.Result, scope string) []unified.Result {
	var out []unified.Result
	for _, r := range rs {
		if r.Scope == scope {
			out = append(out, r)
		}
	}
	return out
}

func TestEnrichUnifiedAttachesAffectedAndEOL(t *testing.T) {
	dets := []matcher.Detection{{Tech: "Nginx", Version: "1.18.0", Confidence: 100}}
	opt := Options{
		CVE: &recordingCVE{res: cve.Result{State: cve.StateHasCVE, CVEs: []cve.CVE{{ID: "CVE-2021-23017", CVSS: 7.7, Severity: "HIGH"}}}},
		EOL: fakeEOL{st: lifecycle.Status{Product: "nginx", Cycle: "1.18", EOLDate: "2021-04-21", IsEOL: lifecycle.StateEOL}},
		KEV: fakeKEV{m: map[string]unified.Result{"CVE-2021-23017": {Leads: []unified.Lead{{ID: "CVE-2021-23017", KnownExpl: true}}}}},
	}
	got := EnrichUnified(context.Background(), dets, testDB(), opt)

	cpe := byScope(got, "cpe")
	if len(cpe) != 1 || cpe[0].State != unified.StateAffectedByAdvisory {
		t.Fatalf("cpe result = %+v, want one StateAffectedByAdvisory", cpe)
	}
	if len(cpe[0].Leads) != 1 || cpe[0].Leads[0].ID != "CVE-2021-23017" {
		t.Fatalf("leads = %+v, want one CVE-2021-23017", cpe[0].Leads)
	}
	if !cpe[0].Leads[0].KnownExpl {
		t.Errorf("KEV prioritization must raise KnownExpl on the lead, got %+v", cpe[0].Leads[0])
	}
	eol := byScope(got, "eol")
	if len(eol) != 1 || eol[0].State != unified.StateAffectedByAdvisory {
		t.Fatalf("eol result = %+v, want one StateAffectedByAdvisory", eol)
	}
}

func TestEnrichUnifiedVersionConflictDowngrades(t *testing.T) {
	dets := []matcher.Detection{{
		Tech: "Nginx", Version: "10", Confidence: 100,
		VersionConflict: true,
		VersionClaims:   []matcher.VersionClaim{{Version: "9.5"}, {Version: "10"}},
	}}
	opt := Options{CVE: &recordingCVE{res: cve.Result{State: cve.StateHasCVE, CVEs: []cve.CVE{{ID: "CVE-2021-23017"}}}}}
	got := byScope(EnrichUnified(context.Background(), dets, testDB(), opt), "cpe")
	if len(got) != 1 {
		t.Fatalf("want 1 cpe result, got %d", len(got))
	}
	if got[0].State != unified.StatePotentiallyAffected {
		t.Errorf("version conflict must downgrade affected→potentially, got %v", got[0].State)
	}
	if !strings.Contains(got[0].Err, "version conflict") {
		t.Errorf("want a version-conflict note, got %q", got[0].Err)
	}
}

func TestEnrichUnifiedPrefersVerifiedCPEOverAttested(t *testing.T) {
	// DB attests the f5:nginx CPE, but the identity dictionary verifies nginx:nginx.
	// The verified identity must be the one queried for CVEs.
	const verified = "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*"
	rec := &recordingCVE{res: cve.Result{State: cve.StateNoKnownCVE}}
	opt := Options{CVE: rec, IdentityResolver: fakeResolver{cpe: verified, state: identity.StateVerified}.resolve}
	dets := []matcher.Detection{{Tech: "Nginx", Version: "1.18.0"}}
	EnrichUnified(context.Background(), dets, testDB(), opt)
	if len(rec.queried) != 1 || rec.queried[0] != verified {
		t.Errorf("CVE lookup must use the VERIFIED cpe %q, queried %v", verified, rec.queried)
	}
}

// TestEnrichUnifiedNeverUsesCPECandidate is the candidate-CPE guard (and the mutant target):
// an entry whose only CPE is an unverified CPECandidate must NOT reach the CVE lookup.
func TestEnrichUnifiedNeverUsesCPECandidate(t *testing.T) {
	db := &schema.DB{
		SchemaVersion: schema.SchemaVersion,
		Fingerprints: map[string]schema.Fingerprint{
			// no attested CPE, only a borrowed candidate from a lower-precedence entry
			"Joomla": {CPECandidate: []string{"cpe:2.3:a:borrowed:candidate:*:*:*:*:*:*:*:*"}},
		},
	}
	rec := &recordingCVE{res: cve.Result{State: cve.StateHasCVE, CVEs: []cve.CVE{{ID: "CVE-9999-0001"}}}}
	got := byScope(EnrichUnified(context.Background(), []matcher.Detection{{Tech: "Joomla", Version: "4.0"}}, db, Options{CVE: rec}), "cpe")
	if len(rec.queried) != 0 {
		t.Errorf("CPECandidate must NEVER be queried for CVEs, queried %v", rec.queried)
	}
	if len(got) != 1 || got[0].State != unified.StateUnknownProduct {
		t.Errorf("no verified/attested cpe → StateUnknownProduct, got %+v", got)
	}
}

func TestEnrichUnifiedProvidersOffStayNotChecked(t *testing.T) {
	got := EnrichUnified(context.Background(), []matcher.Detection{{Tech: "Nginx", Version: "1.18.0"}}, testDB(), Options{})
	for _, r := range got {
		if r.State != unified.StateNotChecked {
			t.Errorf("provider off → %s scope must be not_checked, got %v", r.Scope, r.State)
		}
	}
	if len(byScope(got, "cpe")) != 1 || len(byScope(got, "eol")) != 1 {
		t.Errorf("want one cpe + one eol result, got %+v", got)
	}
}

// --- B: CPEState field ---

func TestCPEStateVerifiedAndAttested(t *testing.T) {
	// identity dictionary verifies → CPEState "verified"; without it the DB-attested CPE
	// is used → CPEState "attested". The mutant (attested→verified) makes the second case red.
	const verified = "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*"
	dets := []matcher.Detection{{Tech: "Nginx", Version: "1.18.0"}}

	v := byScope(EnrichUnified(context.Background(), dets, testDB(), Options{
		CVE:              &recordingCVE{res: cve.Result{State: cve.StateNoKnownCVE}},
		IdentityResolver: fakeResolver{cpe: verified, state: identity.StateVerified}.resolve,
	}), "cpe")
	if len(v) != 1 || v[0].CPEState != "verified" || v[0].CPEEvidence != "nvd-dict" {
		t.Errorf("verified path: CPEState/Evidence = %q/%q, want verified/nvd-dict", v[0].CPEState, v[0].CPEEvidence)
	}

	a := byScope(EnrichUnified(context.Background(), dets, testDB(), Options{
		CVE: &recordingCVE{res: cve.Result{State: cve.StateNoKnownCVE}},
	}), "cpe")
	if len(a) != 1 || a[0].CPEState != "attested" || a[0].CPEEvidence != "source" {
		t.Errorf("attested path: CPEState/Evidence = %q/%q, want attested/source", a[0].CPEState, a[0].CPEEvidence)
	}
	if strings.Contains(a[0].Err, "cpe=") {
		t.Errorf("cpe resolution note must live in CPEState, not Err; Err=%q", a[0].Err)
	}
}

func TestCPEStateNoneWhenNoCPE(t *testing.T) {
	db := &schema.DB{SchemaVersion: schema.SchemaVersion, Fingerprints: map[string]schema.Fingerprint{"Joomla": {}}}
	got := byScope(EnrichUnified(context.Background(), []matcher.Detection{{Tech: "Joomla", Version: "4.0"}}, db, Options{CVE: &recordingCVE{}}), "cpe")
	if len(got) != 1 || got[0].CPEState != "none" {
		t.Errorf("no resolvable cpe → CPEState none, got %+v", got)
	}
}

// --- A: EnrichUnifiedExt dispatch (OSV / WP / JS injected hooks) ---

func TestEnrichUnifiedExtDispatchesEachProvider(t *testing.T) {
	// Each hook echoes its input into the unified result the operator would build; the test
	// proves the right identity/scope/version reached the right provider.
	opt := Options{
		OSV: func(_ context.Context, eco, name, version string) unified.Result {
			return unified.Result{State: unified.StateAffectedByAdvisory, Scope: "ecosystem:" + eco, Identity: name, Version: version, Source: "osv"}
		},
		WP: func(_ context.Context, slug, version, kind string) unified.Result {
			scope := "wordpress:plugin"
			if kind == "theme" {
				scope = "wordpress:theme"
			}
			return unified.Result{State: unified.StateNotAffectedByAdvisory, Scope: scope, Identity: slug, Version: version, Source: "wpcve"}
		},
		JS: func(_ context.Context, name, version string) unified.Result {
			return unified.Result{State: unified.StateAffectedByAdvisory, Scope: "jslib", Identity: name, Version: version, Source: "jslib"}
		},
	}
	inp := EnrichInput{
		Packages: []PkgRef{{Ecosystem: "npm", Name: "lodash", Version: "4.17.4"}},
		WPSlugs:  []WPRef{{Slug: "contact-form-7", Version: "5.0", Kind: "plugin"}},
		JSLibs:   []LibRef{{Name: "jquery", Version: "1.12.0"}},
	}
	got := EnrichUnifiedExt(context.Background(), nil, nil, inp, opt)

	osv := byScope(got, "ecosystem:npm")
	if len(osv) != 1 || osv[0].Identity != "lodash" || osv[0].Version != "4.17.4" || osv[0].Source != "osv" {
		t.Errorf("osv dispatch = %+v, want one lodash@4.17.4 ecosystem:npm result", osv)
	}
	wp := byScope(got, "wordpress:plugin")
	if len(wp) != 1 || wp[0].Identity != "contact-form-7" || wp[0].Source != "wpcve" {
		t.Errorf("wp dispatch = %+v, want one contact-form-7 result", wp)
	}
	js := byScope(got, "jslib")
	if len(js) != 1 || js[0].Identity != "jquery" || js[0].Source != "jslib" {
		t.Errorf("js dispatch = %+v, want one jquery result", js)
	}
}

// TestEnrichUnifiedExtPassesHonestUnknown is the dispatch mutant target: a package the
// OSV feed does not know must stay unknown_product — enrich must NOT fabricate affected.
func TestEnrichUnifiedExtPassesHonestUnknown(t *testing.T) {
	opt := Options{OSV: func(_ context.Context, eco, name, version string) unified.Result {
		return unified.Unknown("ecosystem:"+eco, name, unified.StateUnknownProduct, "not in index")
	}}
	got := EnrichUnifiedExt(context.Background(), nil, nil, EnrichInput{Packages: []PkgRef{{Ecosystem: "npm", Name: "nope", Version: "1.0"}}}, opt)
	if len(got) != 1 || got[0].State != unified.StateUnknownProduct {
		t.Fatalf("unknown package must stay unknown_product, got %+v", got)
	}
}

func TestEnrichUnifiedExtHooksOffStayNotChecked(t *testing.T) {
	inp := EnrichInput{
		Packages: []PkgRef{{Ecosystem: "npm", Name: "lodash", Version: "4.17.4"}},
		WPSlugs:  []WPRef{{Slug: "contact-form-7", Kind: "theme"}},
		JSLibs:   []LibRef{{Name: "jquery", Version: "1.12.0"}},
	}
	got := EnrichUnifiedExt(context.Background(), nil, nil, inp, Options{}) // all hooks nil
	if len(got) != 3 {
		t.Fatalf("want 3 dispatched results, got %d", len(got))
	}
	for _, r := range got {
		if r.State != unified.StateNotChecked {
			t.Errorf("hook off → %s must be not_checked, got %v", r.Scope, r.State)
		}
	}
	if len(byScope(got, "wordpress:theme")) != 1 {
		t.Errorf("theme kind must scope wordpress:theme, got %+v", got)
	}
}

// TestEnrichUnifiedExtOutput runs enrich with real offline input (injected hooks, no
// network) and logs the unified JSON — the offline output sample for the report.
func TestEnrichUnifiedExtOutput(t *testing.T) {
	opt := Options{
		CVE: &recordingCVE{res: cve.Result{State: cve.StateHasCVE, CVEs: []cve.CVE{{ID: "CVE-2021-23017", CVSS: 7.7, Severity: "HIGH"}}}},
		OSV: func(_ context.Context, eco, name, version string) unified.Result {
			return unified.Result{State: unified.StateAffectedByAdvisory, Scope: "ecosystem:" + eco, Identity: name, Version: version, Source: "osv", Freshness: unified.FreshnessLive, Leads: []unified.Lead{{ID: "GHSA-xxxx", CVE: []string{"CVE-2019-10744"}, Severity: "HIGH"}}}
		},
		WP: func(_ context.Context, slug, version, kind string) unified.Result {
			return unified.Result{State: unified.StateNotAffectedByAdvisory, Scope: "wordpress:plugin", Identity: slug, Version: version, Source: "wpcve", Freshness: unified.FreshnessLive}
		},
		JS: func(_ context.Context, name, version string) unified.Result {
			return unified.Result{State: unified.StateAffectedByAdvisory, Scope: "jslib", Identity: name, Version: version, Source: "jslib", Freshness: unified.FreshnessSnapshot, Leads: []unified.Lead{{ID: "jQuery-xss", Severity: "medium"}}}
		},
	}
	dets := []matcher.Detection{{Tech: "Nginx", Version: "1.18.0", Confidence: 100, Provenance: "baseline"}}
	inp := EnrichInput{
		Packages: []PkgRef{{Ecosystem: "npm", Name: "lodash", Version: "4.17.4"}},
		WPSlugs:  []WPRef{{Slug: "contact-form-7", Version: "5.0", Kind: "plugin"}},
		JSLibs:   []LibRef{{Name: "jquery", Version: "1.12.0"}},
	}
	got := EnrichUnifiedExt(context.Background(), dets, testDB(), inp, opt)
	b, err := json.MarshalIndent(got, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("EnrichUnifiedExt offline output:\n%s", b)
}

// --- DETERMINISTIC-REPLAY (release-gate v0.4): same input + frozen DB → byte-identical ---

// replayDB is the frozen fingerprint DB for the replay test: six technologies covering
// every match field (header, cookie, meta, scriptSrc) plus one — "ConflictApp" — whose
// header (9.5) and meta (10) claim incompatible versions, so the pipeline exercises the
// version-conflict downgrade. CPEs are attested so the CVE lookup actually fires; the
// cookie-only "Laravel" entry has no CPE, so it drives the unknown-product branch.
func replayDB() *schema.DB {
	return &schema.DB{
		SchemaVersion: schema.SchemaVersion,
		Fingerprints: map[string]schema.Fingerprint{
			"Nginx": {
				Cats:       []int{22},
				Headers:    map[string]schema.StringList{"Server": {`nginx(?:/([\d.]+))?\;version:\1`}},
				CPE:        []string{"cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*"},
				Provenance: "baseline",
			},
			"PHP": {
				Cats:       []int{27},
				Headers:    map[string]schema.StringList{"X-Powered-By": {`PHP/([\d.]+)\;version:\1`}},
				CPE:        []string{"cpe:2.3:a:php:php:*:*:*:*:*:*:*:*"},
				Provenance: "baseline",
			},
			"WordPress": {
				Cats:       []int{1},
				Meta:       map[string]schema.StringList{"generator": {`WordPress ([\d.]+)\;version:\1`}},
				CPE:        []string{"cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:*"},
				Provenance: "baseline",
			},
			"jQuery": {
				Cats:       []int{59},
				ScriptSrc:  schema.StringList{`jquery-([\d.]+)(?:\.min)?\.js\;version:\1`},
				CPE:        []string{"cpe:2.3:a:jquery:jquery:*:*:*:*:*:*:*:*"},
				Provenance: "baseline",
			},
			"ConflictApp": {
				Cats:       []int{22},
				Headers:    map[string]schema.StringList{"X-App-Version": {`([\d.]+)\;version:\1`}},
				Meta:       map[string]schema.StringList{"app-version": {`([\d.]+)\;version:\1`}},
				CPE:        []string{"cpe:2.3:a:vendor:conflictapp:*:*:*:*:*:*:*:*"},
				Provenance: "baseline",
			},
			"Laravel": { // presence-only cookie, no CPE → unknown-product branch
				Cats:       []int{18},
				Cookies:    map[string]schema.StringList{"laravel_session": {""}},
				Provenance: "baseline",
			},
		},
	}
}

// replayPage is the frozen HTTP evidence: enough headers/cookies/meta/scriptSrcs to fire
// every replayDB entry, including the two incompatible version claims for ConflictApp.
func replayPage() matcher.Page {
	return matcher.Page{
		Headers: map[string][]string{
			"Server":        {"nginx/1.18.0"},
			"X-Powered-By":  {"PHP/7.4.3"},
			"X-App-Version": {"9.5"},
		},
		Cookies: []string{"laravel_session=eyJ0; path=/; HttpOnly"},
		HTML: `<!doctype html><html><head>` +
			`<meta name="generator" content="WordPress 5.8">` +
			`<meta name="app-version" content="10">` +
			`</head><body>hello</body></html>`,
		ScriptSrcs: []string{"/assets/js/jquery-3.5.1.min.js"},
	}
}

// replayOptions / replayInput are the frozen, injected providers and out-of-band
// identities — fixed answers, no network — so the only thing under test is whether the
// pipeline itself (match → enrich → marshal) is order-stable.
func replayOptions() Options {
	return Options{
		CVE: fakeCVE{res: cve.Result{State: cve.StateHasCVE, CVEs: []cve.CVE{
			{ID: "CVE-2021-23017", CVSS: 7.7, Severity: "HIGH"},
			{ID: "CVE-2019-20372", CVSS: 5.3, Severity: "MEDIUM"},
		}}},
		EOL: fakeEOL{st: lifecycle.Status{Product: "nginx", Cycle: "1.18", EOLDate: "2021-04-21", IsEOL: lifecycle.StateEOL}},
		KEV: fakeKEV{m: map[string]unified.Result{
			"CVE-2021-23017": {Leads: []unified.Lead{{ID: "CVE-2021-23017", KnownExpl: true}}},
		}},
		OSV: func(_ context.Context, eco, name, version string) unified.Result {
			return unified.Result{State: unified.StateAffectedByAdvisory, Scope: "ecosystem:" + eco, Identity: name, Version: version, Source: "osv", Leads: []unified.Lead{{ID: "GHSA-jf85-cpcp-j695", CVE: []string{"CVE-2019-10744"}, Severity: "HIGH"}}}
		},
		WP: func(_ context.Context, slug, version, kind string) unified.Result {
			return unified.Result{State: unified.StateNotAffectedByAdvisory, Scope: "wordpress:plugin", Identity: slug, Version: version, Source: "wpcve"}
		},
		JS: func(_ context.Context, name, version string) unified.Result {
			return unified.Result{State: unified.StateAffectedByAdvisory, Scope: "jslib", Identity: name, Version: version, Source: "jslib", Leads: []unified.Lead{{ID: "jQuery-xss-2020", Severity: "medium"}}}
		},
	}
}

func replayInput() EnrichInput {
	return EnrichInput{
		Packages: []PkgRef{{Ecosystem: "npm", Name: "lodash", Version: "4.17.4"}},
		WPSlugs:  []WPRef{{Slug: "contact-form-7", Version: "5.0", Kind: "plugin"}},
		JSLibs:   []LibRef{{Name: "jquery", Version: "1.12.0"}},
	}
}

// runReplay runs the full pipeline once: match the frozen page against the frozen DB,
// then enrich with the frozen providers. Match is inside so the test is end-to-end — it
// would catch map-iteration order leaking out of EITHER layer, not just enrich.
func runReplay() ([]unified.Result, []byte) {
	dets := matcher.Match(replayDB(), replayPage())
	out := EnrichUnifiedExt(context.Background(), dets, replayDB(), replayInput(), replayOptions())
	b, err := json.Marshal(out)
	if err != nil {
		panic(err)
	}
	return out, b
}

// TestEnrichDeterministicReplay is the v0.4 release gate: the same input + frozen DB must
// produce byte-identical output on every run, independent of Go's randomized map order.
func TestEnrichDeterministicReplay(t *testing.T) {
	const runs = 128 // ≥100 so a per-run map-order flip has many chances to surface

	first, want := runReplay()

	// Guard against a vacuous pass: the output must actually exercise the rich paths
	// (multiple results, CVE leads, KEV prioritization, and the version-conflict downgrade).
	js := string(want)
	for _, must := range []string{
		"affected_by_advisory", "potentially_affected", "version conflict",
		"CVE-2021-23017", "unknown_product", "ecosystem:npm", "jslib",
	} {
		if !strings.Contains(js, must) {
			t.Fatalf("replay output missing %q — fixture does not exercise the pipeline: %s", must, js)
		}
	}
	if len(first) < 8 {
		t.Fatalf("want a rich result set (≥8 unified results), got %d", len(first))
	}

	for i := 1; i < runs; i++ {
		_, got := runReplay()
		if !bytes.Equal(got, want) {
			t.Fatalf("run %d is NOT byte-identical to run 0 — enrich pipeline is non-deterministic\nrun0: %s\nrun%d: %s", i, want, i, got)
		}
	}
}

// TestEnrichDeterministicReplayMutantHasTeeth proves the byte-equality assertion above
// is not blind to order: it reconstructs what a map-iterating enrich (the realistic
// non-determinism mutant — e.g. building results by ranging db.Fingerprints instead of
// the ordered dets slice, enrich.go:206) would emit, and shows that order DOES change the
// marshaled bytes across runs. If this ever fails to differ, TestEnrichDeterministicReplay
// would be unable to catch a real map-order regression.
func TestEnrichDeterministicReplayMutantHasTeeth(t *testing.T) {
	results, _ := runReplay()

	var firstBytes []byte
	differ := false
	for i := 0; i < 128; i++ {
		// Rebuild the slice in Go map-iteration order (randomized per range) — exactly how
		// output ordering would leak if enrich sourced it from a map.
		m := make(map[int]unified.Result, len(results))
		for idx, r := range results {
			m[idx] = r
		}
		shuffled := make([]unified.Result, 0, len(m))
		for _, r := range m {
			shuffled = append(shuffled, r)
		}
		b, err := json.Marshal(shuffled)
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			firstBytes = b
			continue
		}
		if !bytes.Equal(b, firstBytes) {
			differ = true
			break
		}
	}
	if !differ {
		t.Fatal("map-iteration order produced identical bytes across 128 runs — the replay test would be blind to a map-order mutant")
	}
}

// KEV/EPSS must ADD the exploitation signal to a CVE lead, never overwrite its CVSS:
// CVSS (0–10 severity) and EPSS (0–1 probability) are different scales.
func TestPrioritizeKeepsCVSSApartFromEPSS(t *testing.T) {
	cvss, epss := 7.7, 0.97
	u := unified.Result{Source: "cve", Leads: []unified.Lead{{ID: "CVE-2021-23017", CVSS: "7.7", Score: &cvss}}}
	opt := Options{KEV: fakeKEV{m: map[string]unified.Result{
		"CVE-2021-23017": {Leads: []unified.Lead{{ID: "CVE-2021-23017", KnownExpl: true, EPSS: &epss}}},
	}}}
	got := prioritize(context.Background(), []unified.Result{u}, opt)[0].Leads[0]
	if got.Score == nil || *got.Score != 7.7 {
		t.Fatalf("the CVSS score must survive prioritize, got %v", *got.Score)
	}
	if got.EPSS == nil || *got.EPSS != 0.97 || !got.KnownExpl {
		t.Fatalf("the KEV/EPSS signal must be added beside it, got epss=%v kev=%v", got.EPSS, got.KnownExpl)
	}
}

type countingKEV struct{ calls [][]string }

func (k *countingKEV) EnrichUnified(_ context.Context, ids []string) map[string]unified.Result {
	k.calls = append(k.calls, append([]string(nil), ids...))
	return map[string]unified.Result{}
}

type cvePerCPE map[string][]cve.CVE

func (m cvePerCPE) Lookup(_ context.Context, cpe, version string) (cve.Result, error) {
	return cve.Result{CPE: cpe, Version: version, State: cve.StateHasCVE, CVEs: m[cpe]}, nil
}

// KEV/EPSS is asked ONCE per enrich run with every CVE lead, not once per detection —
// the EPSS API takes many CVEs per request, so N detections must not become N requests.
func TestKEVAskedOncePerRun(t *testing.T) {
	db := &schema.DB{SchemaVersion: schema.SchemaVersion, Fingerprints: map[string]schema.Fingerprint{
		"Nginx": {CPE: []string{"cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*"}},
		"PHP":   {CPE: []string{"cpe:2.3:a:php:php:*:*:*:*:*:*:*:*"}},
	}}
	dets := []matcher.Detection{{Tech: "Nginx", Version: "1.18.0"}, {Tech: "PHP", Version: "7.4.3"}}
	k := &countingKEV{}
	EnrichUnified(context.Background(), dets, db, Options{
		CVE: cvePerCPE{
			"cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*": {{ID: "CVE-2021-23017"}},
			"cpe:2.3:a:php:php:*:*:*:*:*:*:*:*":  {{ID: "CVE-2019-11043"}},
		},
		KEV: k,
	})
	if len(k.calls) != 1 {
		t.Fatalf("KEV/EPSS must be asked once per run, asked %d times: %v", len(k.calls), k.calls)
	}
	got := append([]string(nil), k.calls[0]...)
	sort.Strings(got)
	if want := []string{"CVE-2019-11043", "CVE-2021-23017"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("the one call must carry every CVE lead, got %v want %v", got, want)
	}
}

// Every client-side JS library or framework the page reveals — chosen by fingerprint
// category, not a list of names — is looked up in the JS advisory source; server-side tech
// is not, and a library also passed in by the caller is not looked up twice.
func TestEnrichUnifiedDispatchesJSLibsByCategory(t *testing.T) {
	db := &schema.DB{SchemaVersion: schema.SchemaVersion, Fingerprints: map[string]schema.Fingerprint{
		"jQuery": {Cats: []int{59}},
		"Vue.js": {Cats: []int{12}},
		"Nginx":  {Cats: []int{22}, CPE: []string{"cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*"}},
	}}
	dets := []matcher.Detection{{Tech: "jQuery", Version: "3.5.0"}, {Tech: "Vue.js", Version: "2.6.0"}, {Tech: "Nginx", Version: "1.18.0"}}
	var asked []string
	opt := Options{JS: func(_ context.Context, name, version string) unified.Result {
		asked = append(asked, name+"@"+version)
		return unified.Result{State: unified.StateNotAffectedByAdvisory, Scope: "jslib", Identity: name, Version: version, Source: "jslib"}
	}}
	got := EnrichUnifiedExt(context.Background(), dets, db, EnrichInput{JSLibs: []LibRef{{Name: "jquery", Version: "3.5.0"}}}, opt)
	sort.Strings(asked)
	if want := []string{"Vue.js@2.6.0", "jQuery@3.5.0"}; !reflect.DeepEqual(asked, want) {
		t.Fatalf("JS lookups = %v, want only the page's JS libraries, once each: %v", asked, want)
	}
	if n := len(byScope(got, "jslib")); n != 2 {
		t.Fatalf("want 2 jslib results, got %d", n)
	}
	if n := len(byScope(EnrichUnified(context.Background(), dets, db, Options{}), "jslib")); n != 0 {
		t.Fatalf("with the JS source off there must be no jslib results, got %d", n)
	}
}

type eolWithCPE struct {
	byTech, byCPE lifecycle.Status
	askedCPE      []string
}

func (f *eolWithCPE) EOLStatus(context.Context, string, string) (lifecycle.Status, error) {
	return f.byTech, nil
}

func (f *eolWithCPE) EOLStatusByCPE(_ context.Context, cpe, _ string) (lifecycle.Status, error) {
	f.askedCPE = append(f.askedCPE, cpe)
	return f.byCPE, nil
}

// A tech the EOL source cannot map by name is resolved by the detection's CPE when the
// source can do that; a tech it maps by name never takes the CPE path.
func TestEOLFallsBackToCPE(t *testing.T) {
	db := &schema.DB{SchemaVersion: schema.SchemaVersion, Fingerprints: map[string]schema.Fingerprint{
		"Caddy": {CPE: []string{"cpe:2.3:a:caddyserver:caddy:*:*:*:*:*:*:*:*"}},
	}}
	dets := []matcher.Detection{{Tech: "Caddy", Version: "2.6.0"}}
	viaCPE := lifecycle.Status{Product: "caddy", Version: "2.6.0", Cycle: "2", IsEOL: lifecycle.StateSupported}
	f := &eolWithCPE{byTech: lifecycle.Status{Version: "2.6.0"}, byCPE: viaCPE}
	got := byScope(EnrichUnified(context.Background(), dets, db, Options{EOL: f}), "eol")
	if len(got) != 1 || got[0].Err != unified.NoteNoClearance || got[0].Identity != "caddy" || len(f.askedCPE) != 1 {
		t.Fatalf("an unmapped tech must be resolved by CPE: %+v (asked %v)", got, f.askedCPE)
	}
	byName := &eolWithCPE{byTech: viaCPE}
	EnrichUnified(context.Background(), dets, db, Options{EOL: byName})
	if len(byName.askedCPE) != 0 {
		t.Fatalf("a tech mapped by name must not take the CPE path, asked %v", byName.askedCPE)
	}
}

// Every result of a page detection names the detected technology, so a consumer reports
// "Nginx 1.18.0 is end-of-life" — the lookup identity alone (a CPE, the EOL product slug)
// does not say which detection it came from.
func TestEnrichUnifiedNamesTheDetection(t *testing.T) {
	dets := []matcher.Detection{{Tech: "Nginx", Version: "1.18.0"}, {Tech: "jQuery", Version: "3.4.0"}}
	opt := Options{
		EOL: fakeEOL{st: lifecycle.Status{Product: "nginx", Cycle: "1.18", IsEOL: lifecycle.StateEOL}},
		JS: func(ctx context.Context, name, version string) unified.Result {
			return unified.Result{Scope: "jslib", Identity: "jquery"}
		},
	}
	db := testDB()
	db.Fingerprints["jQuery"] = schema.Fingerprint{Cats: []int{59}}
	for _, r := range EnrichUnified(context.Background(), dets, db, opt) {
		if r.Tech != "Nginx" && r.Tech != "jQuery" {
			t.Errorf("%s result %q names no detection: %+v", r.Scope, r.Identity, r)
		}
	}
}

// A detection whose patterns disagree on the version has no resolved version: a lookup that
// matched nothing for the one version tried says nothing about the other, so it is
// unknown_version — never not_affected (answered, clean for that source).
func TestEnrichUnifiedVersionConflictIsNeverClean(t *testing.T) {
	dets := []matcher.Detection{{
		Tech: "Nginx", Version: "10", VersionConflict: true,
		VersionClaims: []matcher.VersionClaim{{Version: "9.5"}, {Version: "10"}},
	}}
	dets = append(dets, matcher.Detection{
		Tech: "jQuery", Version: "3.7.1", VersionConflict: true,
		VersionClaims: []matcher.VersionClaim{{Version: "1.6"}, {Version: "3.7.1"}},
	})
	opt := Options{
		CVE: &recordingCVE{res: cve.Result{State: cve.StateNoKnownCVE}},
		EOL: fakeEOL{st: lifecycle.Status{Product: "nginx", Cycle: "10", IsEOL: lifecycle.StateSupported}},
		JS: func(ctx context.Context, name, version string) unified.Result {
			return unified.Result{State: unified.StateNotAffectedByAdvisory, Scope: "jslib", Identity: name, Version: version}
		},
	}
	db := testDB()
	db.Fingerprints["jQuery"] = schema.Fingerprint{Cats: []int{59}}
	scopes := map[string]bool{}
	for _, r := range EnrichUnified(context.Background(), dets, db, opt) {
		scopes[r.Scope] = true
		if r.State == unified.StateNotAffectedByAdvisory || r.State == unified.StateAffectedByAdvisory || !strings.Contains(r.Err, "version conflict") {
			t.Errorf("%s result under a version conflict = %v (%q), want neither answered-clean nor pinned, naming the conflict", r.Scope, r.State, r.Err)
		}
	}
	if !scopes["jslib"] {
		t.Fatalf("the JS library detection must be looked up too, got scopes %v", scopes)
	}
}
