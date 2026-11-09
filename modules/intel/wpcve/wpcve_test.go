package wpcve

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/luannt2002/sigforge/framework/fetch"
	"github.com/luannt2002/sigforge/modules/intel/unified"
)

// ── pure matchers (no network) ─────────────────────────────────────────────────

func TestVersionAffected(t *testing.T) {
	cases := []struct {
		name string
		ver  string
		rec  feedVuln
		want bool
	}{
		{"ge/lt in range", "1.5.0", feedVuln{MinVersion: "1.0", MinOp: "ge", MaxVersion: "2.0", MaxOp: "lt"}, true},
		{"ge/lt at min inclusive", "1.0", feedVuln{MinVersion: "1.0", MinOp: "ge", MaxVersion: "2.0", MaxOp: "lt"}, true},
		{"ge/lt at max exclusive", "2.0", feedVuln{MinVersion: "1.0", MinOp: "ge", MaxVersion: "2.0", MaxOp: "lt"}, false},
		{"below min", "0.9", feedVuln{MinVersion: "1.0", MinOp: "ge", MaxVersion: "2.0", MaxOp: "lt"}, false},
		{"gt strictly above", "1.0", feedVuln{MinVersion: "1.0", MinOp: "gt", MaxVersion: "2.0", MaxOp: "lt"}, false},
		{"le at max inclusive", "2.0", feedVuln{MinVersion: "1.0", MaxVersion: "2.0", MaxOp: "le"}, true},
		{"le above max", "2.0.1", feedVuln{MinVersion: "1.0", MaxVersion: "2.0", MaxOp: "le"}, false},
		{"default ops (ge/lt)", "1.2.3", feedVuln{MinVersion: "1.0", MaxVersion: "1.3"}, true},
		{"fixed_in default lt at fix", "1.3", feedVuln{MinVersion: "1.0", MaxVersion: "1.3"}, false},
		{"unfixed at/above min", "9.9.9", feedVuln{MinVersion: "1.0", Unfixed: true}, true},
		{"unfixed below min", "0.1", feedVuln{MinVersion: "1.0", Unfixed: true}, false},
		{"empty installed is a lead", "", feedVuln{MinVersion: "1.0", MaxVersion: "2.0"}, true},
		{"only upper bound", "0.5", feedVuln{MaxVersion: "1.0", MaxOp: "lt"}, true},
	}
	for _, c := range cases {
		if got, _ := versionAffected(c.ver, &c.rec); got != c.want {
			t.Errorf("%s: versionAffected(%q)=%v want %v", c.name, c.ver, got, c.want)
		}
	}
}

func TestParseableVersion(t *testing.T) {
	cases := []struct {
		ver  string
		want bool
	}{
		{"1.5.0", true}, {"1.0", true}, {"v2.3", true}, {"1.0-beta", true}, {"1.2.3-rc1+build", true},
		{"trunk", false},    // non-numeric tag
		{"20231101", false}, // bare build-date, no dotted semver core
		{"7", false},        // bare integer, not a dotted version
		{"1.x", false},      // non-numeric group
		{"", false},         // a bare "" is not a version
		{"stable", false},   // channel name
	}
	for _, c := range cases {
		if got := parseableVersion(c.ver); got != c.want {
			t.Errorf("parseableVersion(%q)=%v want %v", c.ver, got, c.want)
		}
	}
}

func TestCheckCompatibility(t *testing.T) {
	cases := []struct {
		name                         string
		reqPHP, reqWP, runPHP, runWP string
		want                         Compat
	}{
		{"all ok", "7.4", "5.8", "8.1", "6.4", CompatOK},
		{"php too old", "8.0", "5.8", "7.4", "6.4", CompatIncompatible},
		{"wp too old", "7.4", "6.0", "8.1", "5.8", CompatIncompatible},
		{"missing runtime php", "8.0", "5.8", "", "6.4", CompatUnknown},
		{"missing requirement", "", "", "8.1", "6.4", CompatUnknown},
		{"one known ok one unknown -> unknown", "7.4", "", "8.1", "", CompatUnknown},
		{"incompatible wins over unknown", "8.0", "", "7.4", "", CompatIncompatible},
		{"equal is ok", "8.1", "6.4", "8.1", "6.4", CompatOK},
	}
	for _, c := range cases {
		if got := CheckCompatibility(c.reqPHP, c.reqWP, c.runPHP, c.runWP); got != c.want {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
}

// Severity is passed through from a numeric CVSS only, never invented. A bare
// vector (no numeric score) keeps the raw vector but leaves severity null (§2).
func TestLeadSeverityPassthrough(t *testing.T) {
	withScore := feedVuln{CVSSScore: "9.8"}
	lead := leadFrom(&withScore)
	if lead.Score != 9.8 || lead.Severity != "critical" {
		t.Fatalf("numeric CVSS passthrough: score=%v sev=%q want 9.8/critical", lead.Score, lead.Severity)
	}
	if lead.Confidence != "heuristic" {
		t.Fatalf("every lead is heuristic (version-range), got %q", lead.Confidence)
	}

	// Vector but no numeric score ⇒ null severity (not invented), vector preserved.
	vectorOnly := feedVuln{CVSSVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
	lead = leadFrom(&vectorOnly)
	if lead.Severity != "" || lead.Score != 0 {
		t.Fatalf("vector-only must give null severity, got sev=%q score=%v", lead.Severity, lead.Score)
	}
	if lead.CVSS == "" {
		t.Fatalf("the raw CVSS vector must be preserved on the lead")
	}

	// No CVSS at all ⇒ null severity.
	none := leadFrom(&feedVuln{ID: "x", Title: "some issue"})
	if none.Severity != "" || none.Score != 0 || none.Confidence != "heuristic" {
		t.Fatalf("no-CVSS must give null severity + heuristic, got %+v", none)
	}

	for _, c := range []struct {
		score float64
		want  string
	}{{0, ""}, {3.9, "low"}, {6.9, "medium"}, {8.9, "high"}, {9.0, "critical"}} {
		if got := severityFromScore(c.score); got != c.want {
			t.Errorf("severityFromScore(%v)=%q want %q", c.score, got, c.want)
		}
	}
}

// parseVulns honest-verdict (pure): a "found nothing" payload is UNKNOWN (nil),
// never an empty-but-resolved entry.
func TestParseVulnsFoundNothingIsUnknown(t *testing.T) {
	for _, body := range []string{"", "null", "false", "{}", "[]", `{"other":{"vulnerabilities":[]}}`} {
		e, err := parseVulns([]byte(body), "ghost")
		if err != nil {
			t.Fatalf("body %q: unexpected err %v", body, err)
		}
		if e != nil {
			t.Errorf("body %q: feed knew nothing ⇒ must be nil (UNKNOWN), got %+v", body, e)
		}
	}
	// A slug the feed KNOWS (even empty list) ⇒ a non-nil entry (NoKnownCVE, resolved).
	e, err := parseVulns([]byte(`{"acme":{"vulnerabilities":[]}}`), "acme")
	if err != nil || e == nil {
		t.Fatalf("known slug must be a non-nil entry, got %+v err=%v", e, err)
	}
	if len(e.Vulnerabilities) != 0 {
		t.Errorf("empty-but-known ⇒ 0 vulns, got %d", len(e.Vulnerabilities))
	}
}

func TestBuildURL(t *testing.T) {
	if got := buildURL("https://x/{slug}.json", "my plugin", "plugin"); !strings.Contains(got, "my%20plugin") {
		t.Errorf("slug must be escaped into the placeholder, got %q", got)
	}
	if got := buildURL("https://x/feed/", "acme", "plugin"); got != "https://x/feed/acme" {
		t.Errorf("no placeholder ⇒ trailing segment, got %q", got)
	}
}

// ── env-driven IO over httptest (no real network) ──────────────────────────────

// env UNSET ⇒ zero network, UNKNOWN provenance + result. A counting server proves
// it is never hit.
func TestOffNoNetwork(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hits, 1)
		io.WriteString(w, "{}")
	}))
	defer srv.Close()

	p := New("", "", fetch.New())
	if vuln, org := p.Enabled(); vuln || org {
		t.Fatalf("both sources must be OFF, got vuln=%v org=%v", vuln, org)
	}
	res := p.LookupPlugin(context.Background(), "akismet", "5.0")
	if res.Resolved {
		t.Error("off ⇒ UNKNOWN (Resolved=false)")
	}
	if res.Provenance != ProvUnknown || res.InDirectory != TriUnknown || res.Compat != CompatUnknown {
		t.Errorf("off ⇒ all unknown, got prov=%q dir=%v compat=%v", res.Provenance, res.InDirectory, res.Compat)
	}
	if n := atomic.LoadInt32(&hits); n != 0 {
		t.Errorf("made %d network call(s) with sources off; must be 0", n)
	}
}

// CRITICAL (honest-verdict): an unknown slug the feed returns "nothing" for must be
// UNKNOWN, never clean.
func TestUnknownSlugIsUnknownNotClean(t *testing.T) {
	for _, body := range []string{"null", "{}", "", `{"other-plugin":{"vulnerabilities":[]}}`} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			io.WriteString(w, body)
		}))
		p := New(srv.URL+"/{slug}", "", fetch.New())
		res := p.LookupPlugin(context.Background(), "ghost-slug", "1.0.0")
		if res.Resolved {
			t.Errorf("body %q: Resolved=true (clean) but feed knew nothing — must be UNKNOWN", body)
		}
		if len(res.Vulns) != 0 {
			t.Errorf("body %q: UNKNOWN must carry no vulns", body)
		}
		srv.Close()
	}
}

// A dead vuln feed (500) ⇒ UNKNOWN, never clean (fail-open to not-measured).
func TestVulnFeedDownIsUnknown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "down", http.StatusInternalServerError)
	}))
	defer srv.Close()
	res := New(srv.URL+"/{slug}", "", fetch.New()).LookupPlugin(context.Background(), "acme", "1.0.0")
	if res.Resolved {
		t.Error("a dead feed is UNKNOWN, not clean")
	}
}

// A vuln feed that KNOWS the slug but reports an empty list ⇒ NoKnownCVE: resolved,
// zero vulns (distinct from UNKNOWN above).
func TestKnownSlugEmptyIsNoKnownCVE(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, `{"acme":{"vulnerabilities":[]}}`)
	}))
	defer srv.Close()
	res := New(srv.URL+"/{slug}", "", fetch.New()).LookupPlugin(context.Background(), "acme", "1.0.0")
	if !res.Resolved {
		t.Fatal("feed knew the slug ⇒ Resolved must be true (NoKnownCVE, not UNKNOWN)")
	}
	if len(res.Vulns) != 0 {
		t.Errorf("empty list ⇒ 0 vulns, got %d", len(res.Vulns))
	}
}

// Full path: a free plugin in the .org directory, one vuln hitting the installed
// version, compat ok.
func TestLookupPluginFreeWithVuln(t *testing.T) {
	vuln := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, `{"acme":{"vulnerabilities":[
			{"id":"V1","title":"XSS","cve":"CVE-2024-0001","min_version":"1.0","min_operator":"ge",
			 "max_version":"1.5","max_operator":"lt","cvss_score":"9.8"},
			{"id":"V2","title":"old","min_version":"0.1","max_version":"0.5"}]}}`)
	}))
	defer vuln.Close()
	org := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, `{"slug":"acme","version":"1.9","requires_php":"7.4","requires":"5.8"}`)
	}))
	defer org.Close()

	res := New(vuln.URL+"/{slug}", org.URL+"/{slug}", fetch.New()).
		WithRuntime("8.1", "6.4").LookupPlugin(context.Background(), "acme", "1.2.0")
	if !res.Resolved {
		t.Fatal("feed knew the slug ⇒ Resolved must be true")
	}
	if res.InDirectory != TriYes || res.Provenance != ProvFree {
		t.Errorf("in .org ⇒ free, got %v / %q", res.InDirectory, res.Provenance)
	}
	if res.LatestVersion != "1.9" || res.Compat != CompatOK {
		t.Errorf("latest/compat wrong: latest=%q compat=%v", res.LatestVersion, res.Compat)
	}
	if len(res.Vulns) != 1 || res.Vulns[0].ID != "V1" {
		t.Fatalf("only V1 hits 1.2.0, got %d vulns %+v", len(res.Vulns), res.Vulns)
	}
	if res.Vulns[0].Severity != "critical" || res.Vulns[0].CVE != "CVE-2024-0001" {
		t.Errorf("lead severity/cve wrong: %+v", res.Vulns[0])
	}
}

// CRITICAL (honest-verdict): the .org 200 vs 404 distinction must NOT be flattened.
// 404 ⇒ not-in-directory (a premium/custom candidate), resolved cleanly, not an error.
func TestOrg404NotInDirectory(t *testing.T) {
	vuln := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, `{"premium-x":{"vulnerabilities":[]}}`) // feed knows it, no vulns
	}))
	defer vuln.Close()
	org := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer org.Close()

	res := New(vuln.URL+"/{slug}", org.URL+"/{slug}", fetch.New()).LookupPlugin(context.Background(), "premium-x", "2.0")
	if res.InDirectory != TriNo || res.Provenance != ProvNotInDir {
		t.Errorf("404 ⇒ not_in_directory, got %v / %q", res.InDirectory, res.Provenance)
	}
	if !res.Resolved || len(res.Vulns) != 0 {
		t.Errorf("feed knew slug with no vulns ⇒ resolved+clean, got resolved=%v vulns=%d", res.Resolved, len(res.Vulns))
	}
}

// The .org 200 case is in-directory ⇒ free (the other half of the status split).
func TestOrg200InDirectory(t *testing.T) {
	org := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, `{"version":"3.0","requires_php":"7.4","requires":"5.8"}`)
	}))
	defer org.Close()
	res := New("", org.URL+"/{slug}", fetch.New()).LookupPlugin(context.Background(), "akismet", "2.0")
	if res.InDirectory != TriYes || res.Provenance != ProvFree {
		t.Errorf("200 with a version ⇒ free/in-directory, got %v / %q", res.InDirectory, res.Provenance)
	}
}

// A .org server error (not 404) ⇒ provenance stays UNKNOWN, never flattened to
// not-in-directory.
func TestOrg500IsUnknownNotNotInDir(t *testing.T) {
	org := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer org.Close()
	res := New("", org.URL+"/{slug}", fetch.New()).LookupPlugin(context.Background(), "akismet", "2.0")
	if res.InDirectory != TriUnknown || res.Provenance != ProvUnknown {
		t.Errorf("a 500 ⇒ provenance UNKNOWN, got %v / %q", res.InDirectory, res.Provenance)
	}
}

// CRITICAL (honest-verdict): a slug the feed KNOWS, but whose detected version
// cannot be parsed for range comparison, must NOT be silently dropped to "no CVE".
// It lands in the unparsed_version UNKNOWN bucket (Resolved=false).
func TestUnparseableVersionIsUnknownNotClean(t *testing.T) {
	vuln := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, `{"acme":{"vulnerabilities":[{"id":"V1","title":"XSS","min_version":"1.0","max_version":"5.0"}]}}`)
	}))
	defer vuln.Close()
	for _, ver := range []string{"20231101", "trunk"} {
		res := New(vuln.URL+"/{slug}", "", fetch.New()).LookupPlugin(context.Background(), "acme", ver)
		if !res.UnparsedVersion {
			t.Errorf("ver %q: version present but unparseable must set UnparsedVersion", ver)
		}
		if res.Resolved {
			t.Errorf("ver %q: unparseable version is UNKNOWN, must not be Resolved (clean)", ver)
		}
		if len(res.Vulns) != 0 {
			t.Errorf("ver %q: unparsed_version is coverage UNKNOWN, not fabricated vulns, got %d", ver, len(res.Vulns))
		}
	}
}

// No version at all ⇒ the existing path (every feed vuln surfaces as a lead,
// "can't pin"). It must NOT be mislabeled unparsed_version.
func TestNoVersionNotMislabeledUnparsed(t *testing.T) {
	vuln := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, `{"acme":{"vulnerabilities":[
			{"id":"V1","title":"XSS","min_version":"1.0","max_version":"5.0"},
			{"id":"V2","title":"CSRF","min_version":"2.0","unfixed":true}]}}`)
	}))
	defer vuln.Close()
	res := New(vuln.URL+"/{slug}", "", fetch.New()).LookupPlugin(context.Background(), "acme", "")
	if res.UnparsedVersion {
		t.Error("no version is the existing not-pinned path, not unparsed_version")
	}
	if !res.Resolved || len(res.Vulns) != 2 {
		t.Errorf("no version ⇒ all feed vulns surface as leads, got resolved=%v vulns=%d", res.Resolved, len(res.Vulns))
	}
}

// CRITICAL (A#2): the .org provenance query must carry the real kind, not a
// hardcoded "plugin". A theme lookup against a {kind}-placeholder org endpoint must
// hit the themes path and resolve ProvFree — not miss (wrong plugins path → 404)
// and get mislabeled ProvNotInDir.
func TestLookupThemeOrgKindRouted(t *testing.T) {
	var gotPath string
	org := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		if !strings.Contains(r.URL.Path, "theme") {
			w.WriteHeader(http.StatusNotFound) // plugins path for a theme ⇒ miss
			return
		}
		io.WriteString(w, `{"version":"3.0","requires_php":"7.4","requires":"5.8"}`)
	}))
	defer org.Close()

	res := New("", org.URL+"/{kind}/{slug}", fetch.New()).LookupTheme(context.Background(), "twentytwenty", "1.5")
	if !strings.Contains(gotPath, "theme") {
		t.Fatalf("theme lookup must query the theme endpoint, got path %q", gotPath)
	}
	if res.InDirectory != TriYes || res.Provenance != ProvFree {
		t.Errorf("theme in .org ⇒ free, got %v / %q (ProvNotInDir ⇒ kind not routed)", res.InDirectory, res.Provenance)
	}
}

// LookupTheme routes through the same honest path (kind=theme).
func TestLookupThemeKnownSlug(t *testing.T) {
	vuln := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "twentytwenty") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		io.WriteString(w, `{"twentytwenty":{"vulnerabilities":[{"id":"T1","title":"theme bug","min_version":"1.0","max_version":"2.0"}]}}`)
	}))
	defer vuln.Close()
	res := New(vuln.URL+"/{slug}", "", fetch.New()).LookupTheme(context.Background(), "twentytwenty", "1.5")
	if !res.Resolved || len(res.Vulns) != 1 || res.Vulns[0].ID != "T1" {
		t.Fatalf("theme lookup wrong: resolved=%v vulns=%+v", res.Resolved, res.Vulns)
	}
}

// WordPress orders versions with PHP's version_compare: a letter suffix is part of the version
// (1.2.2 < 1.2.3a), and a bound that is not a version at all leaves the advisory's reach
// unknown — kept as a lead, potentially affected, never "not affected".
func TestBoundsUnderPHPOrderAndUncomparableBounds(t *testing.T) {
	if a, ok := versionAffected("1.2.2", &feedVuln{MaxVersion: "1.2.3a"}); !a || !ok {
		t.Errorf("1.2.2 below fix 1.2.3a: want affected+determinate, got %v %v", a, ok)
	}
	if a, ok := versionAffected("1.2.2", &feedVuln{MaxVersion: "trunk"}); a || ok {
		t.Errorf("a bound that is not a version: want indeterminate, got affected=%v determinate=%v", a, ok)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, `{"acme":{"vulnerabilities":[{"id":"V1","cve":"CVE-2099-0001","max_version":"trunk"}]}}`)
	}))
	defer srv.Close()
	res := New(srv.URL+"/{slug}", "", fetch.New()).LookupPlugin(context.Background(), "acme", "1.2.2")
	if u := ToUnified(res); u.State != unified.StatePotentiallyAffected || len(u.Leads) != 1 || u.Err == "" {
		t.Fatalf("an advisory with an uncomparable bound must be a potential lead, got %v %+v %q", u.State, u.Leads, u.Err)
	}
}

// A source that is off says so.
func TestFeedOffSaysWhy(t *testing.T) {
	if u := ToUnified(New("", "", fetch.New()).LookupPlugin(context.Background(), "acme", "1.0")); u.State != unified.StateNotChecked || u.Err == "" {
		t.Fatalf("an off feed must be not_checked with a reason, got %v %q", u.State, u.Err)
	}
}

// A slug the feed maps to null, or to an object without a vulnerabilities list, was not
// answered: unknown, not "no vulnerability".
func TestNullOrShapelessEntryIsUnknown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"nullslug":null,"emptyobj":{}}`)
	}))
	defer srv.Close()
	p := New(srv.URL, "", fetch.New())
	for _, slug := range []string{"nullslug", "emptyobj"} {
		if u := ToUnified(p.LookupPlugin(context.Background(), slug, "1.0")); u.State != unified.StateUnknownProduct {
			t.Errorf("%s: %v, want unknown_product", slug, u.State)
		}
	}
}

// When PHP's order and a zero-padded numeric order disagree (5.8.0 vs 5.8), the comparison is
// ambiguous — the advisory may apply — so it is indeterminate, never a clean miss.
func TestTrailingZeroDisagreementIsIndeterminate(t *testing.T) {
	cases := []struct {
		ver string
		rec feedVuln
	}{
		{"5.8.0", feedVuln{MaxVersion: "5.8", MaxOp: "le"}},
		{"2.0", feedVuln{MinVersion: "2.0.0", MinOp: "ge", MaxVersion: "2.1.3", MaxOp: "lt"}},
	}
	for _, c := range cases {
		if a, ok := versionAffected(c.ver, &c.rec); a || ok {
			t.Errorf("%s vs %+v: want indeterminate, got affected=%v determinate=%v", c.ver, c.rec, a, ok)
		}
	}
	if a, ok := versionAffected("5.8.1", &feedVuln{MaxVersion: "5.8"}); a || !ok {
		t.Errorf("5.8.1 is past fix 5.8 in both orders: want a determinate miss, got %v %v", a, ok)
	}
}
