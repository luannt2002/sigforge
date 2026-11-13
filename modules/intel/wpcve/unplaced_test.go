package wpcve

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/luannt2002/sigforge/modules/intel/unified"
)

// Every advisory a plugin's or core's version may fall under reaches the unified result as a lead: one whose
// bounds cannot place the version is kept with a note, even beside one that matched (which still decides the
// state); one the version is surely outside never becomes a lead. The typed results keep their meaning — Vulns
// and Unpositioned as they always were — and name every advisory not placed in Unplaced. Cases T1–T9 below.
func TestUnplacedAdvisoryStaysALeadBesideAMatch(t *testing.T) {
	const (
		m = `{"id":"WPV-M","title":"m","min_version":"1.0","max_version":"2.0"}`
		u = `{"id":"WPV-U","title":"u","max_version":"trunk"}`
		o = `{"id":"WPV-O","title":"o","max_version":"1.0"}`
	)
	ctx := context.Background()
	for _, tc := range []struct {
		row, ver string
		feed     []string
		vulns    []string // the typed Vulns, unchanged by Unplaced
		unpos    bool
		unplaced []string
		state    unified.State
		leads    []string // a lead noted as not placed ends in "*"
		err      bool
	}{
		{"T1", "1.5", []string{m}, []string{"WPV-M"}, false, nil, unified.StateAffectedByAdvisory, []string{"WPV-M"}, false},
		{"T2", "1.5", []string{o}, nil, false, nil, unified.StateNotChecked, nil, true},
		{"T3", "1.5", []string{u}, []string{"WPV-U"}, true, []string{"WPV-U"}, unified.StatePotentiallyAffected, []string{"WPV-U*"}, true},
		{"T4", "1.5", []string{m, u}, []string{"WPV-M"}, false, []string{"WPV-U"}, unified.StateAffectedByAdvisory, []string{"WPV-M", "WPV-U*"}, false},
		{"T5", "1.5", []string{m, o}, []string{"WPV-M"}, false, nil, unified.StateAffectedByAdvisory, []string{"WPV-M"}, false},
		{"T6", "1.5", []string{u, o}, []string{"WPV-U"}, true, []string{"WPV-U"}, unified.StatePotentiallyAffected, []string{"WPV-U*"}, true},
		{"T7", "1.5", []string{u, m, o}, []string{"WPV-M"}, false, []string{"WPV-U"}, unified.StateAffectedByAdvisory, []string{"WPV-M", "WPV-U*"}, false},
		{"T8", "", []string{u, m, o}, []string{"WPV-U", "WPV-M", "WPV-O"}, false, nil, unified.StatePotentiallyAffected, []string{"WPV-U", "WPV-M", "WPV-O"}, true},
		{"T9", "trunk", []string{u, m, o}, nil, false, nil, unified.StateUnknownVersion, nil, false},
	} {
		p := vulnFeed(t, `{"vulnerabilities":[`+strings.Join(tc.feed, ",")+`]}`)
		pr, cr := p.LookupPlugin(ctx, "acme", tc.ver), p.LookupCore(ctx, tc.ver)
		for kind, typed := range map[string]struct {
			vulns, unplaced []Lead
			unpos           bool
		}{"plugin": {pr.Vulns, pr.Unplaced, pr.Unpositioned}, "core": {cr.Vulns, cr.Unplaced, cr.Unpositioned}} {
			if !slices.Equal(ids(typed.vulns), tc.vulns) || typed.unpos != tc.unpos || !slices.Equal(ids(typed.unplaced), tc.unplaced) {
				t.Errorf("%s %s typed: Vulns=%v Unpositioned=%v Unplaced=%v, want %v %v %v", tc.row, kind, ids(typed.vulns), typed.unpos, ids(typed.unplaced), tc.vulns, tc.unpos, tc.unplaced)
			}
		}
		for kind, r := range map[string]unified.Result{"plugin": ToUnified(pr), "core": CoreToUnified(cr)} {
			if got := noted(r.Leads); r.State != tc.state || !slices.Equal(got, tc.leads) || (r.Err != "") != tc.err {
				t.Errorf("%s %s: got %v %v err=%q, want %v %v err set=%v", tc.row, kind, r.State, got, r.Err, tc.state, tc.leads, tc.err)
			}
		}
	}
}

func ids(ls []Lead) []string {
	var out []string
	for _, l := range ls {
		out = append(out, l.ID)
	}
	return out
}

// noted lists lead ids, a lead carrying the not-placed note marked "*" and any other note spelled out.
func noted(ls []unified.Lead) []string {
	var out []string
	for _, l := range ls {
		switch l.Note {
		case "":
			out = append(out, l.ID)
		case "the version could not be placed against this advisory's bounds under PHP's version_compare: whether it applies is unknown":
			out = append(out, l.ID+"*")
		default:
			out = append(out, l.ID+"?"+l.Note)
		}
	}
	return out
}
