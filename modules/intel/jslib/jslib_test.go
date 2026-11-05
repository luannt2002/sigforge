package jslib

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/luannt2002/sigforge/framework/fetch"
)

// flatRepoJSON is the classic, widely-mirrored jsrepository shape: version bounds
// sit FLAT on each vulnerability, and `summary` lives inside `identifiers`.
const flatRepoJSON = `{
  "jquery": {
    "extractors": {"func": ["jQuery.fn.jquery"]},
    "vulnerabilities": [
      {"below":"1.6.3","severity":"medium","cwe":["CWE-79"],"identifiers":{"CVE":["cve-2011-4969"],"summary":"XSS with location.hash"},"info":["https://example/1"]},
      {"atOrAbove":"1.0.3","below":"3.5.0","severity":"medium","identifiers":{"CVE":["CVE-2020-11022","CVE-2020-11023"]}}
    ]
  }
}`

// nestedRepoJSON is the newer master shape: bounds nest under `ranges`, with an
// `excludes` back-patch, a top-level `summary`, and a non-CVE identifier.
const nestedRepoJSON = `{
  "AngularJS": {
    "vulnerabilities": [
      {"ranges":[{"atOrAbove":"1.5.0","below":"1.8.0","excludes":["1.6.9"]}],"severity":"high","summary":"sce bypass","identifiers":{"githubID":"GHSA-xxxx-yyyy-zzzz"}}
    ]
  }
}`

func serveJSON(t *testing.T, body string) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func serve500(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "down", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

// ---- ParseRepo (pure) ----

func TestParseRepoFlatAndCaseInsensitiveKey(t *testing.T) {
	m, err := ParseRepo([]byte(flatRepoJSON))
	if err != nil {
		t.Fatalf("ParseRepo: %v", err)
	}
	// Keyed LOWER so lookups are case-insensitive; `extractors` is ignored on decode.
	e, ok := m["jquery"]
	if !ok {
		t.Fatal("jquery not keyed lower-case")
	}
	if len(e.Vulnerabilities) != 2 {
		t.Fatalf("want 2 vulns, got %d", len(e.Vulnerabilities))
	}
}

func TestParseRepoNested(t *testing.T) {
	m, err := ParseRepo([]byte(nestedRepoJSON))
	if err != nil {
		t.Fatalf("ParseRepo: %v", err)
	}
	e := m["angularjs"] // lower-cased from "AngularJS"
	if len(e.Vulnerabilities) != 1 || len(e.Vulnerabilities[0].Ranges) != 1 {
		t.Fatalf("nested ranges not decoded: %+v", e)
	}
}

// ---- versionAffected / inRange (pure range math) ----

func TestVersionAffectedFlat(t *testing.T) {
	// below 1.6.3 ⇒ strictly below is vulnerable.
	v := &repoVuln{Below: "1.6.3"}
	cases := []struct {
		ver  string
		want bool
	}{
		{"1.6.2", true},
		{"1.6.3", false}, // the fix release itself is NOT vulnerable (below is exclusive)
		{"1.4.0", true},
		{"3.0.0", false},
	}
	for _, c := range cases {
		if got := versionAffected(c.ver, v); got != c.want {
			t.Errorf("below 1.6.3, %s: want %v got %v", c.ver, c.want, got)
		}
	}
}

func TestVersionAffectedAboveExclusive(t *testing.T) {
	// above 1.0.0 ⇒ strictly greater is vulnerable; the boundary 1.0.0 itself is NOT.
	v := &repoVuln{Above: "1.0.0", Below: "2.0.0"}
	for ver, want := range map[string]bool{
		"1.0.0": false, // equal to the exclusive lower bound
		"1.0.1": true,
		"1.9.9": true,
		"2.0.0": false, // exclusive upper bound
	} {
		if got := versionAffected(ver, v); got != want {
			t.Errorf("above 1.0.0 %s: want %v got %v", ver, want, got)
		}
	}
}

func TestVersionAffectedBoundedWindow(t *testing.T) {
	// [1.0.3, 3.5.0)
	v := &repoVuln{AtOrAbove: "1.0.3", Below: "3.5.0"}
	for ver, want := range map[string]bool{
		"1.0.2": false, // below the lower bound
		"1.0.3": true,  // inclusive lower bound
		"3.4.1": true,
		"3.5.0": false, // exclusive upper bound (fixed)
		"3.6.0": false,
	} {
		if got := versionAffected(ver, v); got != want {
			t.Errorf("[1.0.3,3.5.0) %s: want %v got %v", ver, want, got)
		}
	}
}

func TestVersionAffectedNestedWithExcludes(t *testing.T) {
	v := &repoVuln{Ranges: []repoRange{{AtOrAbove: "1.5.0", Below: "1.8.0", Excludes: []string{"1.6.9"}}}}
	for ver, want := range map[string]bool{
		"1.4.0": false,
		"1.5.0": true,
		"1.6.9": false, // back-patched version explicitly excluded
		"1.7.0": true,
		"1.8.0": false,
	} {
		if got := versionAffected(ver, v); got != want {
			t.Errorf("nested+excludes %s: want %v got %v", ver, want, got)
		}
	}
}

func TestVersionAffectedEmptyVersionIsLead(t *testing.T) {
	// A version we can't pin must be reported as a LEAD, never dropped as clean.
	if !versionAffected("", &repoVuln{Below: "1.6.3"}) {
		t.Fatal("empty version must be treated as affected (a LEAD)")
	}
}

// ---- resolve: the honest tri-state ----

func TestResolveHasCVE(t *testing.T) {
	repo, _ := ParseRepo([]byte(flatRepoJSON))
	res := resolve(repo, "jQuery", "1.6.2") // caller casing preserved, repo lookup lower
	if !res.KnownLib || !res.Resolved {
		t.Fatalf("jquery 1.6.2 should be known+resolved: %+v", res)
	}
	// 1.6.2 falls in TWO ranges: below 1.6.3 AND [1.0.3, 3.5.0).
	if len(res.Vulns) != 2 || res.Vulns[0].ID != "CVE-2011-4969" {
		t.Fatalf("want 2 leads starting CVE-2011-4969, got %+v", res.Vulns)
	}
	if res.Vulns[0].Confidence != Confidence {
		t.Fatalf("every lead is heuristic (spoofable version), got %q", res.Vulns[0].Confidence)
	}
	// CVE ids UPPER-cased and summary read from identifiers.summary (flat shape).
	if res.Vulns[0].Summary == "" {
		t.Fatal("summary should fall back to identifiers.summary")
	}
}

func TestResolveNoKnownVulnIsResolvedNotUnknown(t *testing.T) {
	repo, _ := ParseRepo([]byte(flatRepoJSON))
	res := resolve(repo, "jquery", "3.6.0") // above every range
	if !res.KnownLib || !res.Resolved {
		t.Fatalf("known lib, version out of range must be RESOLVED: %+v", res)
	}
	if len(res.Vulns) != 0 {
		t.Fatalf("version out of every range ⇒ no-known-vuln, got %+v", res.Vulns)
	}
}

func TestResolveUnknownLibIsNotSafe(t *testing.T) {
	repo, _ := ParseRepo([]byte(flatRepoJSON))
	res := resolve(repo, "left-pad", "1.0.0")
	if res.KnownLib || res.Resolved {
		t.Fatalf("a library the feed does not list is UNKNOWN, never clean: %+v", res)
	}
}

func TestResolveUnparsedVersionIsUnknown(t *testing.T) {
	repo, _ := ParseRepo([]byte(flatRepoJSON))
	res := resolve(repo, "jquery", "trunk")
	if !res.KnownLib {
		t.Fatalf("lib is known: %+v", res)
	}
	if res.Resolved || !res.UnparsedVersion {
		t.Fatalf("a detected-but-uncomparable version is UNKNOWN, never clean: %+v", res)
	}
}

// A bare single-number version ("2") has no dotted core, so it is not semver-comparable ⇒
// UnparsedVersion UNKNOWN, never false-clean (parseableVersion requires >= 2 dotted parts).
func TestResolveSingleNumberVersionIsUnparsed(t *testing.T) {
	repo, _ := ParseRepo([]byte(flatRepoJSON))
	res := resolve(repo, "jquery", "2")
	if !res.KnownLib {
		t.Fatalf("lib is known: %+v", res)
	}
	if res.Resolved || !res.UnparsedVersion {
		t.Fatalf("a single-number version must be UnparsedVersion UNKNOWN, got %+v", res)
	}
	if len(res.Vulns) != 0 {
		t.Fatalf("an unparsed version must surface no leads, got %+v", res.Vulns)
	}
}

func TestResolveEmptyVersionReportsAllLeads(t *testing.T) {
	repo, _ := ParseRepo([]byte(flatRepoJSON))
	res := resolve(repo, "jquery", "")
	if !res.Resolved || len(res.Vulns) != 2 {
		t.Fatalf("no version ⇒ every vuln is a LEAD (can't pin): %+v", res)
	}
}

// ---- Lookup over httptest (no real network) ----

func TestLookupOneLiveFeed(t *testing.T) {
	a := New(serveJSON(t, nestedRepoJSON), fetch.New())
	res := a.LookupOne(context.Background(), "angularjs", "1.7.0")
	if !res.Resolved || len(res.Vulns) != 1 {
		t.Fatalf("live feed lookup failed: %+v", res)
	}
	lead := res.Vulns[0]
	if lead.ID != "GHSA-xxxx-yyyy-zzzz" || len(lead.CVE) != 0 {
		t.Fatalf("non-CVE advisory must still get an id: %+v", lead)
	}
	if lead.Severity != "high" || lead.Summary != "sce bypass" {
		t.Fatalf("severity/summary passed through wrong: %+v", lead)
	}
}

func TestLookupFailOpenUsesSnapshot(t *testing.T) {
	// Feed down ⇒ fall back to the embedded Apache-2.0 snapshot; Log4Shell-equivalent
	// well-known CVE (jQuery CVE-2019-11358) still recognized. Absence is never safe.
	a := New(serve500(t), fetch.New())
	res := a.LookupOne(context.Background(), "jquery", "3.3.0")
	if !res.Resolved {
		t.Fatalf("snapshot fallback should resolve: %+v", res)
	}
	if !hasCVE(res, "CVE-2019-11358") {
		t.Fatalf("snapshot must still flag jquery 3.3.0 prototype pollution: %+v", res.Vulns)
	}
}

func TestLookupGarbageFeedFallsBackToSnapshot(t *testing.T) {
	a := New(serveJSON(t, "<html>Access Denied</html>"), fetch.New())
	res := a.LookupOne(context.Background(), "lodash", "4.17.5")
	if !hasCVE(res, "CVE-2019-10744") {
		t.Fatalf("garbage feed must fall back to snapshot: %+v", res.Vulns)
	}
}

func TestLookupOffURLUsesSnapshotNoNetwork(t *testing.T) {
	a := New("", fetch.New())
	res := a.LookupOne(context.Background(), "bootstrap", "4.1.0")
	if !hasCVE(res, "CVE-2019-8331") {
		t.Fatalf("empty URL must use the snapshot: %+v", res.Vulns)
	}
	// A library the snapshot does not carry is UNKNOWN, not clean.
	if r := a.LookupOne(context.Background(), "vue", "2.6.0"); r.KnownLib || r.Resolved {
		t.Fatalf("unknown lib under snapshot-only must stay UNKNOWN: %+v", r)
	}
}

// Lookup (batch) loads the repository exactly ONCE regardless of how many libraries
// are queried — the point of the batch API for a JS bundle.
func TestLookupBatchLoadsRepoOnce(t *testing.T) {
	var reqs int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqs++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(flatRepoJSON))
	}))
	defer srv.Close()

	a := New(srv.URL, fetch.New())
	got := a.Lookup(context.Background(), map[string]string{
		"jquery":    "1.6.2",
		"unknownjs": "9.9.9",
	})
	if reqs != 1 {
		t.Fatalf("batch must load the repo once, got %d requests", reqs)
	}
	if !got["jquery"].Resolved || len(got["jquery"].Vulns) == 0 {
		t.Fatalf("jquery not resolved in batch: %+v", got["jquery"])
	}
	if got["unknownjs"].KnownLib {
		t.Fatalf("unknown lib must stay UNKNOWN in batch: %+v", got["unknownjs"])
	}
}

func TestLookupBatchEmpty(t *testing.T) {
	a := New("", fetch.New())
	if got := a.Lookup(context.Background(), nil); len(got) != 0 {
		t.Fatalf("empty input must return empty, got %+v", got)
	}
}

// ---- embedded snapshot sanity ----

func TestEmbeddedSnapshotHasCVE(t *testing.T) {
	m, err := ParseRepo(repoSnapshot)
	if err != nil {
		t.Fatalf("snapshot parse: %v", err)
	}
	if len(m) == 0 {
		t.Fatal("embedded snapshot is empty — is data/retirejs-snapshot.json broken?")
	}
	var cves int
	for _, e := range m {
		for i := range e.Vulnerabilities {
			cves += len(leadFrom(&e.Vulnerabilities[i]).CVE)
		}
	}
	if cves == 0 {
		t.Fatal("the snapshot carries no CVE — the air-gap baseline is meaningless")
	}
}

func hasCVE(res Result, cve string) bool {
	for _, l := range res.Vulns {
		for _, c := range l.CVE {
			if c == cve {
				return true
			}
		}
	}
	return false
}
