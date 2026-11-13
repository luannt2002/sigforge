package jslib

import (
	"slices"
	"strings"
	"testing"

	"github.com/luannt2002/sigforge/modules/intel/unified"
)

// Every advisory a library's version may fall under reaches the unified result as a lead: one whose bounds
// cannot place the version is kept with a note, even beside one that matched (which still decides the
// state); one the version is surely outside never becomes a lead. The typed result keeps its meaning — Vulns
// and Unpositioned as they always were — and names every advisory not placed in Unplaced. Rows T1–T9 of the B1 table.
func TestUnplacedAdvisoryStaysALeadBesideAMatch(t *testing.T) {
	const (
		m = `{"below":"2.0.0","identifiers":{"CVE":["CVE-2099-0001"]}}`
		u = `{"below":"@@@","identifiers":{"CVE":["CVE-2099-0002"]}}`
		o = `{"below":"1.0.0","identifiers":{"CVE":["CVE-2099-0003"]}}`
		M = "CVE-2099-0001"
		U = "CVE-2099-0002"
		O = "CVE-2099-0003"
	)
	for _, tc := range []struct {
		row, ver string
		feed     []string
		vulns    []string // the typed Vulns, as before B1
		unpos    bool
		unplaced []string
		state    unified.State
		leads    []string // a lead noted as not placed ends in "*"
		err      bool
	}{
		{"T1", "1.5.0", []string{m}, []string{M}, false, nil, unified.StateAffectedByAdvisory, []string{M}, false},
		{"T2", "1.5.0", []string{o}, nil, false, nil, unified.StateNotChecked, nil, true},
		{"T3", "1.5.0", []string{u}, []string{U}, true, []string{U}, unified.StatePotentiallyAffected, []string{U + "*"}, true},
		{"T4", "1.5.0", []string{m, u}, []string{M}, false, []string{U}, unified.StateAffectedByAdvisory, []string{M, U + "*"}, false},
		{"T5", "1.5.0", []string{m, o}, []string{M}, false, nil, unified.StateAffectedByAdvisory, []string{M}, false},
		{"T6", "1.5.0", []string{u, o}, []string{U}, true, []string{U}, unified.StatePotentiallyAffected, []string{U + "*"}, true},
		{"T7", "1.5.0", []string{u, m, o}, []string{M}, false, []string{U}, unified.StateAffectedByAdvisory, []string{M, U + "*"}, false},
		{"T8", "", []string{u, m, o}, []string{U, M, O}, false, nil, unified.StatePotentiallyAffected, []string{U, M, O}, true},
		{"T9", "trunk", []string{u, m, o}, nil, false, nil, unified.StateUnknownVersion, nil, false},
	} {
		repo, err := ParseRepo([]byte(`{"lib":{"vulnerabilities":[` + strings.Join(tc.feed, ",") + `]}}`))
		if err != nil {
			t.Fatal(err)
		}
		raw := resolve(repo, "lib", tc.ver)
		if !slices.Equal(ids(raw.Vulns), tc.vulns) || raw.Unpositioned != tc.unpos || !slices.Equal(ids(raw.Unplaced), tc.unplaced) {
			t.Errorf("%s typed: Vulns=%v Unpositioned=%v Unplaced=%v, want %v %v %v", tc.row, ids(raw.Vulns), raw.Unpositioned, ids(raw.Unplaced), tc.vulns, tc.unpos, tc.unplaced)
		}
		r := ToUnified(raw)
		if got := noted(r.Leads); r.State != tc.state || !slices.Equal(got, tc.leads) || (r.Err != "") != tc.err {
			t.Errorf("%s: got %v %v err=%q, want %v %v err set=%v", tc.row, r.State, got, r.Err, tc.state, tc.leads, tc.err)
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
		case "the version could not be placed against this advisory's bounds under the npm order: whether it applies is unknown":
			out = append(out, l.ID+"*")
		default:
			out = append(out, l.ID+"?"+l.Note)
		}
	}
	return out
}
