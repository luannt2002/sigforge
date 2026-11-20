package accuracy

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
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

func serveBody(t *testing.T, status int, body string) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

// osvDump serves one npm advisory for lodash (fixed 4.17.21) and one whose bound cannot be compared.
func osvDump(t *testing.T) string {
	t.Helper()
	var zbuf bytes.Buffer
	zw := zip.NewWriter(&zbuf)
	for name, body := range map[string]string{
		"npm/GHSA-0001.json": `{"id":"GHSA-0001","affected":[{"package":{"name":"lodash","ecosystem":"npm"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"4.17.21"}]}]}]}`,
		"npm/GHSA-0002.json": `{"id":"GHSA-0002","affected":[{"package":{"name":"oddpkg","ecosystem":"npm"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"not-a-version"}]}]}]}`,
	} {
		w, _ := zw.Create(name)
		_, _ = w.Write([]byte(body))
	}
	_ = zw.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/npm/all.zip" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(zbuf.Bytes())
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

// TestEveryUnconcludedResultNamesAReason holds the reason contract on every source's real paths: each
// result that is not a conclusion, and each potentially_affected one, names why in Result.Reason — the
// code a consumer reads instead of parsing Err — and the code is the one for that path, not just any.
// A plain affected answer carries none. kev's own EPSS-only results (CVE-centric, used to rank leads) are
// the one potentially_affected without a reason: they say an exploitation probability exists, not why
// a version could not be pinned.
func TestEveryUnconcludedResultNamesAReason(t *testing.T) {
	ctx := context.Background()
	osvURL := osvDump(t)
	osvLook := osv.New(osvURL, fetch.New()).Lookuper()
	wpFeed := serveBody(t, 200, `{"acme":{"vulnerabilities":[{"id":"WPV-1","fixed_in":"2.0"}]},"oddslug":{"vulnerabilities":[{"id":"WPV-2","max_version":"trunk"}]},"quiet":{"vulnerabilities":[]}}`) + "/{slug}"
	wp := wpcve.New(wpFeed, "", fetch.New())
	repo := serveBody(t, 200, `{"lodash":{"vulnerabilities":[{"below":"4.17.21","identifiers":{"CVE":["CVE-2099-0001"]}}]},"oddlib":{"vulnerabilities":[{"below":"2.0.0rc1"}]}}`)
	js := jslib.New(repo, fetch.New())
	bundle := serveBody(t, 200, `{"result":[{"name":"nginx","releases":[{"name":"1.18","isEol":true},{"name":"1.26","isEol":false}]}]}`)
	eol := lifecycle.NewBundle(bundle, fetch.New())
	eolOf := func(tech, version string) unified.Result {
		return lifecycle.ToUnified(eol.EOLStatus(ctx, tech, version))
	}
	cveHit := []cve.CVE{{ID: "CVE-2099-0002"}}

	cases := []struct {
		name string
		r    unified.Result
		want string
	}{
		{"cve off", cve.ToUnified(cve.Result{}, cve.ErrFeedOff), unified.ReasonSourceOff},
		{"cve failed", cve.ToUnified(cve.Result{}, errors.New("status 500")), unified.ReasonSourceError},
		{"cve no CPE", cve.ToUnified(cve.Result{}, nil), unified.ReasonNoIdentity},
		{"cve miss", cve.ToUnified(cve.New(serveBody(t, 200, `{"totalResults":0,"vulnerabilities":[]}`), fetch.New()).
			Lookup(ctx, "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*", "1.25.0")), unified.ReasonNotProvablyComplete},
		{"cve one empty page", cve.ToUnified(cve.Result{State: cve.StateNoKnownCVE, CPE: "cpe:x", Version: "1.0", Total: 3}, nil), unified.ReasonPartialAnswer},
		{"cve no version", cve.ToUnified(cve.Result{State: cve.StateHasCVE, CVEs: cveHit}, nil), unified.ReasonNoVersion},
		{"cve hit on one page", cve.ToUnified(cve.Result{State: cve.StateHasCVE, Version: "1.0", CVEs: cveHit, Total: 3}, nil), unified.ReasonPartialAnswer},
		{"cve hit", cve.ToUnified(cve.Result{State: cve.StateHasCVE, Version: "1.0", CVEs: cveHit, Total: 1}, nil), ""},

		{"eol off", lifecycle.ToUnified(lifecycle.Status{}, lifecycle.ErrFeedOff), unified.ReasonSourceOff},
		{"eol failed", lifecycle.ToUnified(lifecycle.Status{}, errors.New("status 500")), unified.ReasonSourceError},
		{"eol off, tech with no product name", lifecycle.ToUnified(lifecycle.New("", fetch.New()).EOLStatus(ctx, "Acme", "1.0")), unified.ReasonSourceOff},
		{"eol bundle, tech with no product name: not asked", eolOf("Acme", "1.0"), unified.ReasonNoIdentity},
		{"eol per-product feed, tech with no product name: not asked", lifecycle.ToUnified(lifecycle.New(bundle, fetch.New()).EOLStatus(ctx, "Acme", "1.0")), unified.ReasonNoIdentity},
		{"eol per-product feed asked by CPE: cannot be", lifecycle.ToUnified(lifecycle.New(bundle, fetch.New()).EOLStatusByCPE(ctx, "cpe:2.3:a:acme:acme:*:*:*:*:*:*:*:*", "1.0")), unified.ReasonNoIdentity},
		{"eol off, asked by CPE", lifecycle.ToUnified(lifecycle.New("", fetch.New()).EOLStatusByCPE(ctx, "cpe:2.3:a:acme:acme:*:*:*:*:*:*:*:*", "1.0")), unified.ReasonSourceOff},
		{"eol bundle asked by CPE, product not listed", lifecycle.ToUnified(eol.EOLStatusByCPE(ctx, "cpe:2.3:a:acme:acme:*:*:*:*:*:*:*:*", "1.0")), unified.ReasonNotInSource},
		{"eol supported", eolOf("nginx", "1.26.2"), unified.ReasonNoClearance},
		{"eol ended, no version", eolOf("nginx", ""), unified.ReasonNoVersion},
		{"eol version in no cycle", eolOf("nginx", "1.99.0"), unified.ReasonVersionUnplaced},
		{"eol unreadable version", eolOf("nginx", "not.a.version"), unified.ReasonVersionUnreadable},
		{"eol ended", eolOf("nginx", "1.18.0"), ""},
		{"eol ended, release given without its version", lifecycle.ToUnified(lifecycle.Status{Product: "nginx", Cycle: "1.18", IsEOL: lifecycle.StateEOL}, nil), unified.ReasonNoVersion},
		{"eol version starting 0, in no cycle", eolOf("nginx", "0.9.1"), unified.ReasonVersionUnplaced},
		{"eol version starting 9, in no cycle", eolOf("nginx", "9.1"), unified.ReasonVersionUnplaced},
		{"eol version starting below 0", eolOf("nginx", "-1"), unified.ReasonVersionUnreadable},

		{"osv off", osv.New("", fetch.New()).Lookuper()(ctx, "npm", "lodash", "4.17.20"), unified.ReasonSourceOff},
		{"osv failed", osv.New(serveBody(t, 500, ""), fetch.New()).Lookuper()(ctx, "npm", "lodash", "4.17.20"), unified.ReasonSourceError},
		{"osv ecosystem not covered", osvLook(ctx, "no-such-ecosystem", "x", "1.0"), unified.ReasonUnsupported},
		{"osv distro without release", osvLook(ctx, "Debian", "openssl", "3.0.11-1"), unified.ReasonNoIdentity},
		{"osv package not listed", osvLook(ctx, "npm", "left-pad", "1.0.0"), unified.ReasonNotInSource},
		{"osv no version", osvLook(ctx, "npm", "lodash", ""), unified.ReasonNoVersion},
		{"osv unreadable version", osvLook(ctx, "npm", "lodash", "not.a.version"), unified.ReasonVersionUnreadable},
		{"osv unplaced bound", osvLook(ctx, "npm", "oddpkg", "1.0.0"), unified.ReasonVersionUnplaced},
		{"osv whole-dump miss", osvLook(ctx, "npm", "lodash", "4.17.21"), unified.ReasonNoClearance},
		{"osv hit in a dump read in part", osv.ToUnified(osv.Result{Status: osv.StatusVulnerable, PackageKnown: true, VersionPinned: true, Partial: true, Vulns: []osv.Vuln{{ID: "GHSA-1"}}},
			"npm", "lodash", "4.17.20", time.Time{}), unified.ReasonPartialAnswer},
		{"osv no version, dump read in part: the version is the reason", osv.ToUnified(osv.Result{Status: osv.StatusVulnerable, PackageKnown: true, Partial: true, Vulns: []osv.Vuln{{ID: "GHSA-1"}}},
			"npm", "lodash", "", time.Time{}), unified.ReasonNoVersion},
		{"osv partial-dump miss", osv.ToUnified(osv.Result{Status: osv.StatusNoKnownVuln, PackageKnown: true, VersionPinned: true, Partial: true},
			"npm", "lodash", "4.17.21", time.Time{}), unified.ReasonPartialAnswer},
		{"osv hit", osvLook(ctx, "npm", "lodash", "4.17.20"), ""},
		{"osv blank version", osv.ToUnified(osv.Result{Status: osv.StatusVulnerable, PackageKnown: true, Vulns: []osv.Vuln{{ID: "GHSA-1"}}}, "npm", "lodash", "  ", time.Time{}), unified.ReasonNoVersion},
		{"osv miss, no version", osv.ToUnified(osv.Result{Status: osv.StatusNoKnownVuln, PackageKnown: true}, "npm", "lodash", "", time.Time{}), unified.ReasonNoVersion},
		{"osv miss, blank version", osv.ToUnified(osv.Result{Status: osv.StatusNoKnownVuln, PackageKnown: true}, "npm", "lodash", "  ", time.Time{}), unified.ReasonNoVersion},
		{"osv miss, unreadable version", osv.ToUnified(osv.Result{Status: osv.StatusNoKnownVuln, PackageKnown: true}, "npm", "lodash", "not.a.version", time.Time{}), unified.ReasonVersionUnreadable},

		{"jslib sample miss", jslib.ToUnified(jslib.Result{Library: "jquery", Version: "3.7.1", KnownLib: true, Resolved: true, Sample: true}), unified.ReasonSampleOnly},
		{"jslib library not in sample", jslib.ToUnified(jslib.Result{Library: "acme", Version: "1.0", Sample: true}), unified.ReasonSampleOnly},
		{"jslib repository miss", jslib.ToUnified(js.LookupOne(ctx, "lodash", "4.17.21")), unified.ReasonNotProvablyComplete},
		{"jslib library not listed", jslib.ToUnified(js.LookupOne(ctx, "acme", "1.0")), unified.ReasonNotInSource},
		{"jslib no version", jslib.ToUnified(js.LookupOne(ctx, "lodash", "")), unified.ReasonNoVersion},
		{"jslib unreadable version", jslib.ToUnified(js.LookupOne(ctx, "lodash", "not.a.version")), unified.ReasonVersionUnreadable},
		{"jslib unplaced bound", jslib.ToUnified(js.LookupOne(ctx, "oddlib", "1.5.0")), unified.ReasonVersionUnplaced},
		{"jslib hit", jslib.ToUnified(js.LookupOne(ctx, "lodash", "4.17.20")), ""},

		{"wpcve off", wpcve.ToUnified(wpcve.New("", "", fetch.New()).LookupPlugin(ctx, "acme", "1.0")), unified.ReasonSourceOff},
		{"wpcve no slug", wpcve.ToUnified(wp.LookupPlugin(ctx, "", "1.0")), unified.ReasonNoIdentity},
		{"wpcve failed", wpcve.ToUnified(wpcve.New(serveBody(t, 500, "")+"/{slug}", "", fetch.New()).LookupPlugin(ctx, "acme", "1.0")), unified.ReasonSourceError},
		{"wpcve slug not listed", wpcve.ToUnified(wp.LookupPlugin(ctx, "nobody", "1.0")), unified.ReasonNotInSource},
		{"wpcve miss", wpcve.ToUnified(wp.LookupPlugin(ctx, "quiet", "1.0")), unified.ReasonNotProvablyComplete},
		{"wpcve no version", wpcve.ToUnified(wp.LookupPlugin(ctx, "acme", "")), unified.ReasonNoVersion},
		{"wpcve unreadable version", wpcve.ToUnified(wp.LookupPlugin(ctx, "acme", "not.a.version")), unified.ReasonVersionUnreadable},
		{"wpcve unplaced bound", wpcve.ToUnified(wp.LookupPlugin(ctx, "oddslug", "1.0")), unified.ReasonVersionUnplaced},
		{"wpcve hit", wpcve.ToUnified(wp.LookupPlugin(ctx, "acme", "1.0")), ""},

		{"kev sample miss", kev.New("", "", fetch.New()).EnrichUnified(ctx, []string{"CVE-2099-12345"})["CVE-2099-12345"], unified.ReasonSampleOnly},
		{"kev catalog miss", kev.MapSignal(kev.Signal{CVE: "CVE-2099-12345"}, unified.FreshnessLive, true), unified.ReasonNoClearance},
	}
	for _, c := range cases {
		if c.r.Reason != c.want {
			t.Errorf("%s: %s reason %q, want %q (error %q)", c.name, c.r.State, c.r.Reason, c.want, c.r.Err)
		}
		if (!c.r.State.Concluded() || c.r.State == unified.StatePotentiallyAffected) && !slices.Contains(unified.Reasons, c.r.Reason) {
			t.Errorf("%s: %s must name a known reason, got %q", c.name, c.r.State, c.r.Reason)
		}
	}
}

// An end-of-life verdict with no version says so in Err, after any stale note, never in place of it.
func TestEOLNoVersionNoteKeepsTheStaleNote(t *testing.T) {
	ended := lifecycle.Status{Product: "nginx", Cycle: "1.18", IsEOL: lifecycle.StateEOL}
	if u := lifecycle.ToUnified(ended, nil); u.Err != unified.NoteNoVersion {
		t.Errorf("fresh: error %q, want exactly the no-version note", u.Err)
	}
	ended.Stale, ended.Err = true, "status 500"
	u := lifecycle.ToUnified(ended, nil)
	if want := "endoflife source failed: verdict from the last synced bundle (stale): status 500; " + unified.NoteNoVersion; u.Err != want {
		t.Errorf("stale: error %q, want %q", u.Err, want)
	}
}

// TestUnreadableVersionNeverAffectedNorClean: a version the source's order cannot read is never placed in a
// range (never affected_by_advisory) and never read as clean, on every source that orders versions itself;
// its reason is version_unreadable and its note never claims no version was given. The CVE source compares
// versions on its side (sigforge only writes the string into the CPE), so it is not one of them.
func TestUnreadableVersionNeverAffectedNorClean(t *testing.T) {
	ctx := context.Background()
	const bad = "not.a.version"
	wp := wpcve.New(serveBody(t, 200, `{"acme":{"vulnerabilities":[{"id":"WPV-1","fixed_in":"2.0"}]}}`)+"/{slug}", "", fetch.New())
	js := jslib.New(serveBody(t, 200, `{"lodash":{"vulnerabilities":[{"below":"4.17.21"}]}}`), fetch.New())
	eol := lifecycle.NewBundle(serveBody(t, 200, `{"result":[{"name":"nginx","releases":[{"name":"1.18","isEol":true}]}]}`), fetch.New())
	cases := map[string]unified.Result{
		"osv":       osv.New(osvDump(t), fetch.New()).Lookuper()(ctx, "npm", "lodash", bad),
		"jslib":     jslib.ToUnified(js.LookupOne(ctx, "lodash", bad)),
		"wpcve":     wpcve.ToUnified(wp.LookupPlugin(ctx, "acme", bad)),
		"lifecycle": lifecycle.ToUnified(eol.EOLStatus(ctx, "nginx", bad)),
	}
	for src, u := range cases {
		if u.State == unified.StateAffectedByAdvisory || u.State == unified.StateNotAffectedByAdvisory || u.Reason != unified.ReasonVersionUnreadable ||
			strings.Contains(u.Err, "no version detected") || u.Version != bad {
			t.Errorf("%s: %s reason %q version %q error %q — want never affected or clean, version_unreadable, the version kept, no \"no version detected\"",
				src, u.State, u.Reason, u.Version, u.Err)
		}
	}
}
