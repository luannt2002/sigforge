package osv

import (
	"slices"
	"testing"
	"time"

	"github.com/luannt2002/sigforge/modules/intel/unified"
)

// demoNpm is an npm advisory for demo; top holds extra top-level fields (severity, aliases).
func demoNpm(id, top, affected string) string {
	return `{"id":"` + id + `",` + top + `"affected":[{"package":{"name":"demo","ecosystem":"npm"},` + affected + `}]}`
}

// An advisory the version cannot be placed against reaches the unified result as a lead, noted, after every
// match — a match never hides it; one the version is placed outside never becomes a lead. The typed result
// keeps its meaning — Status and Vulns as they always were — and names every advisory not placed in Unplaced;
// one advisory both placed and not (an alias) is reported once, placed. Rows T1–T9, D1 and G1–G2 of the B1 table.
func TestUnplacedAdvisoryStaysALeadBesideAMatch(t *testing.T) {
	var (
		m   = demoNpm("X-M", `"database_specific":{"severity":"LOW"},`, `"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"9.0.0"}]}]`)
		u   = demoNpm("X-U", `"database_specific":{"severity":"CRITICAL"},`, `"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"@@@"}]}]`)
		o   = demoNpm("X-O", ``, `"ranges":[{"type":"SEMVER","events":[{"introduced":"5.0.0"},{"fixed":"9.0.0"}]}]`)
		m2  = demoNpm("X-M2", `"aliases":["X-M"],`, `"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"@@@"}]}]`)
		l   = demoNpm("X-L", ``, `"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"limit":"@@@"}]}]`)
		v   = demoNpm("X-V", ``, `"versions":["4.x-weird"]`)
		lim = demoNpm("X-LIM", ``, `"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"limit":"2.0.0"}]}]`)
	)
	for _, tc := range []struct {
		row, ver string
		feed     []string // in dump order
		status   Status
		vulns    []string // the typed Vulns, as before B1
		unplaced []string
		state    unified.State
		leads    []string // "*" a lead noted as not placed
	}{
		{"T1", "1.0.0", []string{m}, StatusVulnerable, []string{"X-M"}, nil, unified.StateAffectedByAdvisory, []string{"X-M"}},
		{"T2", "1.0.0", []string{o}, StatusNoKnownVuln, nil, nil, unified.StateNotChecked, nil},
		{"T3", "1.0.0", []string{u}, StatusUnknown, []string{"X-U"}, []string{"X-U"}, unified.StatePotentiallyAffected, []string{"X-U*"}},
		{"T4", "1.0.0", []string{m, u}, StatusVulnerable, []string{"X-M"}, []string{"X-U"}, unified.StateAffectedByAdvisory, []string{"X-M", "X-U*"}},
		{"T5", "1.0.0", []string{m, o}, StatusVulnerable, []string{"X-M"}, nil, unified.StateAffectedByAdvisory, []string{"X-M"}},
		{"T6", "1.0.0", []string{u, o}, StatusUnknown, []string{"X-U"}, []string{"X-U"}, unified.StatePotentiallyAffected, []string{"X-U*"}},
		{"T7", "1.0.0", []string{u, m, o}, StatusVulnerable, []string{"X-M"}, []string{"X-U"}, unified.StateAffectedByAdvisory, []string{"X-M", "X-U*"}},
		{"T8", "", []string{u, m, o}, StatusVulnerable, []string{"X-U", "X-M", "X-O"}, nil, unified.StatePotentiallyAffected, []string{"X-U", "X-M", "X-O"}},
		{"T9", "4.x-weird", []string{u, m, o}, StatusUnknown, []string{"X-U", "X-M", "X-O"}, []string{"X-U", "X-M", "X-O"}, unified.StatePotentiallyAffected, []string{"X-U*", "X-M*", "X-O*"}},
		{"D1", "1.0.0", []string{m2, m}, StatusVulnerable, []string{"X-M"}, nil, unified.StateAffectedByAdvisory, []string{"X-M"}},
		{"G1", "1.0.0", []string{l, m}, StatusVulnerable, []string{"X-M"}, []string{"X-L"}, unified.StateAffectedByAdvisory, []string{"X-M", "X-L*"}},
		{"G2", "4.x-weird", []string{lim, v}, StatusVulnerable, []string{"X-V"}, []string{"X-LIM"}, unified.StateAffectedByAdvisory, []string{"X-V", "X-LIM*"}},
	} {
		res := indexInOrder(t, "npm", seq(len(tc.feed)), tc.feed).Lookup("demo", tc.ver)
		if res.Status != tc.status || !slices.Equal(vulnIDs(res.Vulns), tc.vulns) || !slices.Equal(vulnIDs(res.Unplaced), tc.unplaced) {
			t.Errorf("%s typed: %v Vulns=%v Unplaced=%v, want %v %v %v", tc.row, res.Status, vulnIDs(res.Vulns), vulnIDs(res.Unplaced), tc.status, tc.vulns, tc.unplaced)
		}
		r := ToUnified(res, "npm", "demo", tc.ver, time.Time{})
		if got := noted(r.Leads); r.State != tc.state || !slices.Equal(got, tc.leads) {
			t.Errorf("%s: got %v %v err=%q, want %v %v", tc.row, r.State, got, r.Err, tc.state, tc.leads)
		}
	}
}

// The release lookup keeps the same rule beside OutsideListed: below the floor a match, a lead reached only from
// the start (its own note kept) and an unplaced one are all reported, the unplaced last; above the floor it is the
// package's rule. Rows R1–R4 of the B1 table.
func TestReleaseKeepsAnUnplacedAdvisoryBesideAMatch(t *testing.T) {
	var (
		m = acmeAdv("GHSA-m", `{"introduced":"0"},{"fixed":"6.4.0"}`, ``)
		o = acmeAdv("GHSA-o", `{"introduced":"0"},{"fixed":"6.4.0"}`, `"6.0.0","6.1.0"`)
		u = acmeAdv("GHSA-u", `{"introduced":"0"},{"fixed":"@@@"}`, `"6.0.0"`)
	)
	for _, tc := range []struct {
		row, ver string
		feed     []string
		below    bool
		status   Status
		vulns    []string // the typed Vulns, as before B1
		unplaced []string
		state    unified.State
		leads    []string // "*" not placed, "?" outside the listed releases
	}{
		{"R1", "5.0.0", []string{o}, true, StatusVulnerable, []string{"GHSA-o"}, nil, unified.StateAffectedByAdvisory, []string{"GHSA-o?"}},
		{"R2", "5.0.0", []string{u, o, m}, true, StatusVulnerable, []string{"GHSA-m", "GHSA-o"}, []string{"GHSA-u"}, unified.StateAffectedByAdvisory, []string{"GHSA-m", "GHSA-o?", "GHSA-u*"}},
		{"R3", "5.0.0", []string{u}, true, StatusUnknown, []string{"GHSA-u"}, []string{"GHSA-u"}, unified.StatePotentiallyAffected, []string{"GHSA-u*"}},
		{"R4", "6.2.0", []string{u, m}, false, StatusVulnerable, []string{"GHSA-m"}, []string{"GHSA-u"}, unified.StateAffectedByAdvisory, []string{"GHSA-m", "GHSA-u*"}},
	} {
		res := indexInOrder(t, "Packagist", seq(len(tc.feed)), tc.feed).lookup("", "acme/core", tc.ver, true)
		if res.BelowListed != tc.below || res.Status != tc.status || !slices.Equal(vulnIDs(res.Vulns), tc.vulns) || !slices.Equal(vulnIDs(res.Unplaced), tc.unplaced) {
			t.Errorf("%s typed: below=%v %v Vulns=%v Unplaced=%v, want below=%v %v %v %v", tc.row, res.BelowListed, res.Status, vulnIDs(res.Vulns), vulnIDs(res.Unplaced), tc.below, tc.status, tc.vulns, tc.unplaced)
		}
		r := ToUnified(res, "Packagist", "acme/core", tc.ver, time.Time{})
		if got := noted(r.Leads); r.State != tc.state || !slices.Equal(got, tc.leads) {
			t.Errorf("%s: got %v %v, want %v %v", tc.row, r.State, got, tc.state, tc.leads)
		}
	}
}

func seq(n int) []int {
	out := make([]int, n)
	for i := range out {
		out[i] = i
	}
	return out
}

func vulnIDs(vs []Vuln) []string {
	var out []string
	for _, v := range vs {
		out = append(out, v.ID)
	}
	return out
}

// noted lists lead ids: "*" a lead carrying the not-placed note, "?" one outside the listed releases, any other note spelled out.
func noted(ls []unified.Lead) []string {
	var out []string
	for _, l := range ls {
		switch l.Note {
		case "":
			out = append(out, l.ID)
		case "the version could not be placed against this advisory's affected ranges or versions: whether it applies is unknown":
			out = append(out, l.ID+"*")
		case noteOutsideListed:
			out = append(out, l.ID+"?")
		default:
			out = append(out, l.ID+"!"+l.Note)
		}
	}
	return out
}
