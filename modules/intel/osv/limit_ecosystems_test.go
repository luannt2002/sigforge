package osv

import (
	"testing"
	"time"

	"github.com/luannt2002/sigforge/modules/intel/unified"
)

// Every comparator family bounds a range at its limit, read in the family's own syntax and order: a
// version below the limit is affected, one at or past it is not placed. X-OUT is limited at the below
// version itself, so the below case also shows a reached limit keeping a version out — a version below
// every limit is placed the same with or without them.
func TestEveryComparatorFamilyRespectsTheLimit(t *testing.T) {
	for _, tc := range []struct{ family, eco, limit, below, atOrAbove string }{
		{"pypi", "PyPI", "2.0", "2.0.dev1", "2.0.0"},                              // a dev release sorts below its release; trailing zeros are equal
		{"deb", "Debian:12", "1:2.0-1", "1:2.0~rc1-1", "1:2.0-1+deb12u1"},         // epoch; a tilde sorts before the end
		{"rpm", "Rocky Linux:9", "1:2.0-1.el9", "2.5-1.el9", "1:2.0-1.el9_1"},     // a missing epoch is 0, below epoch 1 whatever the version
		{"maven", "Maven", "2.0", "2.0.0.Beta1", "2.0.0.RELEASE"},                 // a beta qualifier is below the release, RELEASE is the release
		{"rubygems", "RubyGems", "2.0", "2.0.0.rc1", "2.0.0"},                     // a letter segment marks a pre-release
		{"alpine", "Alpine:v3.20", "2.0-r1", "2.0_rc1-r0", "2.0_p1-r0"},           // _rc is below no suffix, _p above it
		{"nuget", "NuGet", "2.0.0-RC2", "2.0.0-beta1", "2.0.0-rc2"},               // labels compare case-insensitively
		{"pub", "Pub", "2.0.0+2", "2.0.0+1", "2.0.0+10"},                          // build metadata orders, numerically
		{"packagist", "Packagist", "2.0.0", "2.0.0-RC1", "2.0.0-p1"},              // RC is below the release, a patch above it
		{"hackage", "Hackage", "2.0.0", "2.0", "2.0.0"},                           // a list ranks above its own prefix
		{"cran", "CRAN", "2.0-1", "2.0", "2.0.1"},                                 // "-" and "." both separate components
		{"semver", "Go", "2.0.0", "v2.0.0-20240101000000-abcdefabcdef", "v2.0.0"}, // a pseudo-version is a pre-release; the v prefix is dropped
	} {
		limited := func(id, limit string) string {
			return demoAdv(id, tc.eco, `"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"limit":"`+limit+`"}]}]`)
		}
		idx := buildIdx(t, tc.eco, map[string]string{"X-IN.json": limited("X-IN", tc.limit), "X-OUT.json": limited("X-OUT", tc.below)})
		look := func(v string) unified.Result {
			return ToUnified(idx.LookupIn(tc.eco, "demo", v), tc.eco, "demo", v, time.Time{})
		}
		t.Run(tc.family+"/below", func(t *testing.T) {
			if u := look(tc.below); u.State != unified.StateAffectedByAdvisory || len(u.Leads) != 1 || u.Leads[0].ID != "X-IN" {
				t.Errorf("%s %s, limit %s: %v %+v, want affected with the one lead X-IN", tc.eco, tc.below, tc.limit, u.State, u.Leads)
			}
		})
		t.Run(tc.family+"/at-or-above", func(t *testing.T) {
			if u := look(tc.atOrAbove); u.State != unified.StateNotChecked || u.Err != unified.NoteNoClearance {
				t.Errorf("%s %s, limit %s: %v %q, want not placed (no clearance)", tc.eco, tc.atOrAbove, tc.limit, u.State, u.Err)
			}
		})
	}
}
