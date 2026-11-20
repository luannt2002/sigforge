package accuracy

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/luannt2002/sigforge/framework/fetch"
	"github.com/luannt2002/sigforge/modules/intel/cve"
	"github.com/luannt2002/sigforge/modules/intel/enrich"
	"github.com/luannt2002/sigforge/modules/intel/matcher"
	"github.com/luannt2002/sigforge/modules/intel/osv"
	"github.com/luannt2002/sigforge/modules/intel/schema"
	"github.com/luannt2002/sigforge/modules/intel/unified"
)

// sureness orders states by how much they claim: nothing asked or nothing known, then advisories without a pinned
// version, then a pinned match; "not affected" (never issued) would claim the most.
func sureness(s unified.State) int {
	switch s {
	case unified.StateUnknownProduct, unified.StateUnknownVersion:
		return 1
	case unified.StatePotentiallyAffected:
		return 2
	case unified.StateAffectedByAdvisory:
		return 3
	case unified.StateNotAffectedByAdvisory:
		return 4
	}
	return 0 // not_checked, source_unavailable
}

type cveAnswer struct {
	res cve.Result
	err error
}

func (c cveAnswer) Lookup(_ context.Context, cpe, version string) (cve.Result, error) {
	r := c.res
	r.CPE, r.Version = cpe, version
	return r, c.err
}

// TestTransformsNeverMakeAResultSurer holds the plan's metamorphic rule on real data paths: take one input, make it
// worse — turn the source off, make the version unreadable, add a version claim that disagrees, let the stored copy go
// stale, keep only a borrowed identity — and the result never claims more than before (strictly less where the change
// takes away what the claim rested on); a provider answering nothing
// added beside a failing one never erases the failing one's evidence.
func TestTransformsNeverMakeAResultSurer(t *testing.T) {
	ctx := context.Background()
	dump := osvDump(t)
	pkg := func(url, version string) unified.Result {
		return osv.New(url, fetch.New()).Lookuper()(ctx, "npm", "lodash", version)
	}

	var failing atomic.Bool
	flaky := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if failing.Load() {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, dump+r.URL.Path, http.StatusFound)
	}))
	defer flaky.Close()
	store := t.TempDir()
	stored := func() unified.Result {
		c := fetch.New()
		c.CacheDir = store
		return osv.New(flaky.URL, c).Lookuper()(ctx, "npm", "lodash", "4.17.20")
	}
	live := stored()
	failing.Store(true)
	stale := stored()

	hit := cveAnswer{res: cve.Result{State: cve.StateHasCVE, CVEs: []cve.CVE{{ID: "CVE-2099-0001"}}}}
	attested := &schema.DB{SchemaVersion: schema.SchemaVersion, Fingerprints: map[string]schema.Fingerprint{
		"Acme": {CPE: []string{"cpe:2.3:a:acme:acme:*:*:*:*:*:*:*:*"}}}}
	borrowed := &schema.DB{SchemaVersion: schema.SchemaVersion, Fingerprints: map[string]schema.Fingerprint{
		"Acme": {CPECandidate: []string{"cpe:2.3:a:acme:acme:*:*:*:*:*:*:*:*"}}}}
	cpeOf := func(db *schema.DB, d matcher.Detection) unified.Result {
		for _, r := range enrich.EnrichUnified(ctx, []matcher.Detection{d}, db, enrich.Options{CVE: hit}) {
			if r.Scope == "cpe" {
				return r
			}
		}
		t.Fatalf("no cpe result for %+v", d)
		return unified.Result{}
	}
	plain := matcher.Detection{Tech: "Acme", Version: "1.0"}
	distroBuilt := matcher.Detection{Tech: "Acme", Version: "1.0", Distro: "Debian"}
	conflicted := matcher.Detection{Tech: "Acme", Version: "1.0", VersionConflict: true,
		VersionClaims: []matcher.VersionClaim{{Version: "1.0", Field: "header"}, {Version: "2.0", Field: "html"}}}

	for _, tc := range []struct {
		name          string
		before, after unified.Result
		less          bool // the transform takes away what the claim rested on: it must claim strictly less
	}{
		{"source on → off", pkg(dump, "4.17.20"), pkg("", "4.17.20"), true},
		{"version readable → unreadable", pkg(dump, "4.17.20"), pkg(dump, "not.a.version"), true},
		{"one version claim → claims that disagree", cpeOf(attested, plain), cpeOf(attested, conflicted), true},
		{"stored copy fresh → stale", live, stale, false},
		{"attested identity → borrowed candidate only", cpeOf(attested, plain), cpeOf(borrowed, plain), true},
		{"upstream build → a distro's package build", cpeOf(attested, plain), cpeOf(attested, distroBuilt), true},
	} {
		if b, a := sureness(tc.before.State), sureness(tc.after.State); a > b || (tc.less && a == b) {
			t.Errorf("%s: %s → %s — want less claimed after the input got worse", tc.name, tc.before.State, tc.after.State)
		}
		if tc.after.Freshness == unified.FreshnessLive && tc.before.Freshness != unified.FreshnessLive {
			t.Errorf("%s: became live", tc.name)
		}
	}
	if live.Freshness != unified.FreshnessLive || stale.Freshness != unified.FreshnessStale || len(stale.Leads) != len(live.Leads) {
		t.Errorf("stale: freshness %s → %s, leads %d → %d; want live → stale with the leads still traceable", live.Freshness, stale.Freshness, len(live.Leads), len(stale.Leads))
	}

	failingCVE := cveAnswer{err: errors.New("status 503")}
	only := enrich.EnrichUnified(ctx, []matcher.Detection{plain}, attested, enrich.Options{CVE: failingCVE})
	beside := enrich.EnrichUnifiedExt(ctx, []matcher.Detection{plain}, attested,
		enrich.EnrichInput{Packages: []enrich.PkgRef{{Ecosystem: "npm", Name: "left-pad", Version: "1.0.0"}}},
		enrich.Options{CVE: failingCVE, OSV: osv.New(dump, fetch.New()).Lookuper()})
	cpeErr := func(rs []unified.Result) (unified.State, string) {
		for _, r := range rs {
			if r.Scope == "cpe" {
				return r.State, r.Err
			}
		}
		return -1, ""
	}
	s1, e1 := cpeErr(only)
	if s2, e2 := cpeErr(beside); s2 != s1 || e2 != e1 || s1 != unified.StateSourceUnavailable {
		t.Errorf("a provider answering nothing beside a failing one changed the failing one's result: %s %q → %s %q", s1, e1, s2, e2)
	}
}
