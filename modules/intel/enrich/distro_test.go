package enrich

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/luannt2002/sigforge/modules/intel/cve"
	"github.com/luannt2002/sigforge/modules/intel/lifecycle"
	"github.com/luannt2002/sigforge/modules/intel/matcher"
	"github.com/luannt2002/sigforge/modules/intel/unified"
)

// A hit on a version from a distro's package build is only potential: the distro may have backported the fix or still
// support the package, so an advisory or end-of-life hit on the upstream number is potentially_affected
// (distro_build), its leads kept and the distro named. An unanswered result keeps its own reason; a version conflict keeps its reason and
// gains the distro in its note.
func TestDistroBuildHitIsOnlyPotential(t *testing.T) {
	ctx := context.Background()
	hitCVE := fakeCVE{res: cve.Result{State: cve.StateHasCVE, CVEs: []cve.CVE{{ID: "CVE-2021-23017", Severity: "HIGH"}}}}
	eolNow := fakeEOL{st: lifecycle.Status{Product: "nginx", Cycle: "1.18", EOLDate: "2021-04-21", IsEOL: lifecycle.StateEOL}}
	debian := matcher.Detection{Tech: "Nginx", Version: "1.18.0", Confidence: 100, VersionFrom: "header", Distro: "Debian"}
	byScope := func(rs []unified.Result) map[string]unified.Result {
		m := map[string]unified.Result{}
		for _, r := range rs {
			m[r.Scope] = r
		}
		return m
	}

	got := byScope(EnrichUnified(ctx, []matcher.Detection{debian}, testDB(), Options{CVE: hitCVE, EOL: eolNow}))
	for _, scope := range []string{"cpe", "eol"} {
		r := got[scope]
		if r.State != unified.StatePotentiallyAffected || r.Reason != unified.ReasonDistroBuild || r.Distro != "Debian" ||
			len(r.Leads) != 1 || !strings.Contains(r.Err, "Debian") {
			t.Errorf("%s hit on a Debian build = %s / %q distro %q, %d leads, err %q — want potentially_affected / distro_build, Debian, the lead kept, Debian named",
				scope, r.State, r.Reason, r.Distro, len(r.Leads), r.Err)
		}
	}

	off := byScope(EnrichUnified(ctx, []matcher.Detection{debian}, testDB(), Options{CVE: fakeCVE{err: errors.New("down")}}))
	if r := off["cpe"]; r.State != unified.StateSourceUnavailable || r.Reason != unified.ReasonSourceError || r.Distro != "Debian" {
		t.Errorf("failed source on a Debian build = %s / %q distro %q — want source_unavailable / source_error, Debian named", r.State, r.Reason, r.Distro)
	}
	if r := off["eol"]; r.State != unified.StateNotChecked || r.Reason != unified.ReasonSourceOff {
		t.Errorf("EOL off on a Debian build = %s / %q — want not_checked / source_off", r.State, r.Reason)
	}

	both := debian
	both.VersionConflict, both.VersionClaims = true, []matcher.VersionClaim{{Version: "1.18.0", Field: "header"}, {Version: "1.20.1", Field: "html"}}
	r := byScope(EnrichUnified(ctx, []matcher.Detection{both}, testDB(), Options{CVE: hitCVE}))["cpe"]
	if r.State != unified.StatePotentiallyAffected || r.Reason != unified.ReasonVersionConflict || !strings.Contains(r.Err, "Debian") {
		t.Errorf("conflict on a Debian build = %s / %q err %q — want potentially_affected / version_conflict, Debian in the note", r.State, r.Reason, r.Err)
	}

	paged := fakeCVE{res: cve.Result{State: cve.StateHasCVE, Total: 5, CVEs: []cve.CVE{{ID: "CVE-2021-23017", Severity: "HIGH"}}}}
	if r := byScope(EnrichUnified(ctx, []matcher.Detection{debian}, testDB(), Options{CVE: paged}))["cpe"]; r.State != unified.StatePotentiallyAffected ||
		r.Reason != unified.ReasonDistroBuild || !strings.Contains(r.Err, "partial: 1 of 5") {
		t.Errorf("hit from one page on a Debian build = %s / %q err %q — want potentially_affected / distro_build, the partial note kept", r.State, r.Reason, r.Err)
	}

	plain := debian
	plain.Distro = ""
	if r := byScope(EnrichUnified(ctx, []matcher.Detection{plain}, testDB(), Options{CVE: hitCVE}))["cpe"]; r.State != unified.StateAffectedByAdvisory || r.Reason != "" || r.Distro != "" {
		t.Errorf("hit on an upstream build = %s / %q distro %q — want affected_by_advisory, no reason, no distro", r.State, r.Reason, r.Distro)
	}
}
