package accuracy

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/luannt2002/sigforge/framework/fetch"
	"github.com/luannt2002/sigforge/modules/intel/cve"
	"github.com/luannt2002/sigforge/modules/intel/jslib"
	"github.com/luannt2002/sigforge/modules/intel/kev"
	"github.com/luannt2002/sigforge/modules/intel/lifecycle"
	"github.com/luannt2002/sigforge/modules/intel/osv"
	"github.com/luannt2002/sigforge/modules/intel/unified"
	"github.com/luannt2002/sigforge/modules/intel/wpcve"
)

// TestNoVersionIsNeverAffected holds one contract for every advisory source at once:
// with no detected version, the advisories found for the product are
// potentially_affected — never affected_by_advisory, which claims the running version is
// inside a range. The same bug lived in three adapters, so every product-version source
// now labels a match through unified.AdvisoryState and the rule is held here for all of
// them. kev is CVE-centric (the identity is the CVE) and has no version to pin.
func TestNoVersionIsNeverAffected(t *testing.T) {
	cases := map[string]unified.Result{
		"lifecycle": lifecycle.ToUnified(lifecycle.Status{Product: "php", Cycle: "7.2", EOLDate: "2020-11-30", IsEOL: lifecycle.StateEOL}, nil),
		"cve":       cve.ToUnified(cve.Result{State: cve.StateHasCVE, CVEs: []cve.CVE{{ID: "CVE-2021-0001"}}}, nil),
		"jslib":     jslib.ToUnified(jslib.Result{Library: "jquery", KnownLib: true, Resolved: true, Vulns: []jslib.Lead{{ID: "CVE-2020-11022"}}}),
		"wpcve":     wpcve.ToUnified(wpcve.PluginResult{Slug: "contact-form-7", Resolved: true, Vulns: []wpcve.Lead{{ID: "WPV-0001"}}}),
		"osv":       osv.ToUnified(osv.Result{Status: osv.StatusVulnerable, PackageKnown: true, Vulns: []osv.Vuln{{ID: "GHSA-0001"}}}, "npm", "lodash", "", time.Time{}),
	}
	for src, u := range cases {
		if u.Version != "" {
			t.Fatalf("%s: fixture must carry no version, got %q", src, u.Version)
		}
		if u.State != unified.StatePotentiallyAffected || len(u.Leads) == 0 {
			t.Errorf("%s: no version → want potentially_affected with the advisories kept as leads, got %s with %d leads",
				src, u.State, len(u.Leads))
		}
	}
}

// TestEmptyResultIsNeverClean holds the core honesty rule (unknown ≠ clean) for every
// source at once: a result that carries nothing — no lookup, no answer — must never
// come out as not_affected_by_advisory, the only state a consumer may read as clean.
func TestEmptyResultIsNeverClean(t *testing.T) {
	cases := map[string]unified.Result{
		"cve":       cve.ToUnified(cve.Result{}, nil),
		"lifecycle": lifecycle.ToUnified(lifecycle.Status{}, nil),
		"jslib":     jslib.ToUnified(jslib.Result{}),
		"wpcve":     wpcve.ToUnified(wpcve.PluginResult{}),
		"osv":       osv.ToUnified(osv.Result{}, "npm", "lodash", "1.0.0", time.Time{}),
		"zero":      {},
	}
	for src, u := range cases {
		if u.State == unified.StateNotAffectedByAdvisory || u.State.Applicable() {
			t.Errorf("%s: an empty result must stay unanswered, got %s", src, u.State)
		}
	}
}

// TestIncompleteDataIsNeverClean holds the "not affected" contract for every source at once:
// an answer drawn from less than the source's full data (an embedded sample, one page of a
// paged answer, a cut-off version list) or from a version that could not be compared with
// every advisory (an unreadable bound) is a named gap, never not_affected_by_advisory.
// unified.Clean is the only producer of that state (held in package unified); this holds each
// source to the evidence it hands it.
func TestIncompleteDataIsNeverClean(t *testing.T) {
	ctx := context.Background()
	serve := func(body string) string {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(body)) }))
		t.Cleanup(srv.Close)
		return srv.URL
	}
	var zbuf bytes.Buffer
	zw := zip.NewWriter(&zbuf)
	f, _ := zw.Create("npm/GHSA-many.json")
	var vs []string
	for i := 0; i < 200; i++ {
		vs = append(vs, fmt.Sprintf(`"1.0.%d"`, i))
	}
	_, _ = f.Write([]byte(`{"id":"GHSA-many","affected":[{"package":{"name":"manyver","ecosystem":"npm"},"versions":[` + strings.Join(vs, ",") + `]}]}`))
	_ = zw.Close()
	osvIdx, err := osv.BuildIndex(ctx, "npm", bytes.NewReader(zbuf.Bytes()), int64(zbuf.Len()))
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]unified.Result{
		"kev, embedded sample":   kev.New("", "", fetch.New()).EnrichUnified(ctx, []string{"CVE-2099-12345"})["CVE-2099-12345"],
		"jslib, embedded sample": jslib.ToUnified(jslib.New("", fetch.New()).LookupOne(ctx, "lodash", "4.17.20")),
		"jslib, unreadable bound": jslib.ToUnified(jslib.New(serve(`{"testlib":{"vulnerabilities":[{"below":"2.0.0rc1"}]}}`), fetch.New()).
			LookupOne(ctx, "testlib", "1.5.0")),
		"wpcve, unreadable bound": wpcve.ToUnified(wpcve.New(serve(`{"acme":{"vulnerabilities":[{"id":"V1","max_version":"trunk"}]}}`)+"/{slug}", "", fetch.New()).
			LookupPlugin(ctx, "acme", "1.2.2")),
		"osv, cut-off version list": osv.ToUnified(osvIdx.Lookup("manyver", "1.0.199"), "npm", "manyver", "1.0.199", time.Time{}),
		"cve, one page":             cve.ToUnified(cve.Result{State: cve.StateNoKnownCVE, CPE: "cpe:2.3:a:x:y:*:*:*:*:*:*:*:*", Version: "1.0", Total: 3}, nil),
	}
	for name, u := range cases {
		if u.State == unified.StateNotAffectedByAdvisory || u.Err == "" {
			t.Errorf("%s: %v %q — incomplete data must be a named gap, never not_affected", name, u.State, u.Err)
		}
	}
}

// TestUnvouchedSourcesNeverAnswerClean: no source answers not_affected in v0.4, and the CVE
// API, the WordPress feed and the Retire.js repository cannot even prove an answer complete,
// so "nothing matched" from them is a partial-data gap — even when their data looks whole.
func TestUnvouchedSourcesNeverAnswerClean(t *testing.T) {
	ctx := context.Background()
	serve := func(body string) string {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(body)) }))
		t.Cleanup(srv.Close)
		return srv.URL
	}
	cases := map[string]unified.Result{
		"cve, no CVE listed": cve.ToUnified(cve.New(serve(`{"totalResults":0,"vulnerabilities":[]}`), fetch.New()).
			Lookup(ctx, "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*", "1.25.0")),
		"cve, not an NVD body": cve.ToUnified(cve.New(serve(`{}`), fetch.New()).Lookup(ctx, "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*", "1.25.0")),
		"jslib, live repository miss": jslib.ToUnified(jslib.New(serve(`{"lodash":{"vulnerabilities":[{"below":"4.17.21"}]}}`), fetch.New()).
			LookupOne(ctx, "lodash", "4.17.21")),
		"wpcve, slug listed with no vuln": wpcve.ToUnified(wpcve.New(serve(`{"acme":{"vulnerabilities":[]}}`)+"/{slug}", "", fetch.New()).
			LookupPlugin(ctx, "acme", "1.0")),
	}
	for name, u := range cases {
		if u.State == unified.StateNotAffectedByAdvisory || u.Err == "" {
			t.Errorf("%s: %v %q — this source cannot vouch for a clean answer", name, u.State, u.Err)
		}
	}
}
