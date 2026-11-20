package osv

import (
	"archive/zip"
	"bytes"
	"context"
	"slices"
	"testing"
)

// The same advisories give the same lead order whatever order the dump lists them in: severity first, then id —
// a consumer diffing two runs, or two mirrors, never sees a reorder that is not a change.
func TestOSVLeadOrderIndependentOfDump(t *testing.T) {
	adv := func(id, sev string) string {
		return `{"id":"` + id + `","database_specific":{"severity":"` + sev + `"},"affected":[{"package":{"name":"lodash","ecosystem":"npm"},` +
			`"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"4.17.21"}]}]}]}`
	}
	order := func(entries ...string) []string {
		var buf bytes.Buffer
		zw := zip.NewWriter(&buf)
		for i, e := range entries {
			w, _ := zw.Create(string(rune('a'+i)) + ".json")
			_, _ = w.Write([]byte(e))
		}
		_ = zw.Close()
		idx, err := BuildIndex(context.Background(), "npm", bytes.NewReader(buf.Bytes()), int64(buf.Len()))
		if err != nil {
			t.Fatal(err)
		}
		var ids []string
		for _, v := range idx.Lookup("lodash", "4.17.20").Vulns {
			ids = append(ids, v.ID)
		}
		return ids
	}
	b, c, a := adv("GHSA-bbbb", "HIGH"), adv("GHSA-cccc", "HIGH"), adv("GHSA-aaaa", "CRITICAL")
	one, two := order(b, c, a), order(c, a, b)
	if want := []string{"GHSA-aaaa", "GHSA-bbbb", "GHSA-cccc"}; !slices.Equal(one, want) || !slices.Equal(two, want) {
		t.Errorf("lead order %v and %v, want %v for both dump orders", one, two, want)
	}

	// advisories the version cannot be placed against, alone and beside a match: the same order rule
	odd := func(id string) string {
		return `{"id":"` + id + `","database_specific":{"severity":"HIGH"},"affected":[{"package":{"name":"lodash","ecosystem":"npm"},` +
			`"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"not-a-version"}]}]}]}`
	}
	x, y := odd("GHSA-xxxx"), odd("GHSA-yyyy")
	if p, q := unplacedOrder(t, x, y), unplacedOrder(t, y, x); !slices.Equal(p, q) || !slices.Equal(p, []string{"GHSA-xxxx", "GHSA-yyyy"}) {
		t.Errorf("unplaced lead order %v and %v, want [GHSA-xxxx GHSA-yyyy] for both dump orders", p, q)
	}
	if p, q := unplacedOrder(t, b, x, y), unplacedOrder(t, y, b, x); !slices.Equal(p, q) {
		t.Errorf("unplaced beside a match: %v and %v, want the same order", p, q)
	}

	// one flaw filed twice under aliases: the id kept is the same whatever the dump's order
	alias := func(id, other string) string {
		return `{"id":"` + id + `","aliases":["` + other + `"],"database_specific":{"severity":"HIGH"},"affected":[{"package":{"name":"lodash","ecosystem":"npm"},` +
			`"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"4.17.21"}]}]}]}`
	}
	g, o := alias("GHSA-zzzz", "GO-2099-0001"), alias("GO-2099-0001", "GHSA-zzzz")
	if p, q := order(g, o), order(o, g); !slices.Equal(p, q) || !slices.Equal(p, []string{"GHSA-zzzz"}) {
		t.Errorf("aliased advisory kept as %v and %v, want the smaller id, [GHSA-zzzz], for both dump orders", p, q)
	}
	// a match wins over its alias the version cannot be placed against, whatever their ids
	oddAlias := `{"id":"GHSA-aaaa","aliases":["GO-2099-0002"],"database_specific":{"severity":"HIGH"},"affected":[{"package":{"name":"lodash","ecosystem":"npm"},` +
		`"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"not-a-version"}]}]}]}`
	matched := alias("GO-2099-0002", "GHSA-aaaa")
	for _, dump := range [][]string{{oddAlias, matched}, {matched, oddAlias}} {
		if p, u := order(dump...), unplacedOrder(t, dump...); !slices.Equal(p, []string{"GO-2099-0002"}) || len(u) != 0 {
			t.Errorf("a match beside its unplaced alias: leads %v, unplaced %v — want [GO-2099-0002] and none unplaced", p, u)
		}
	}
}

// unplacedOrder is the ids of the advisories lodash 4.17.20 could not be placed against, in the dump order given.
func unplacedOrder(t *testing.T, entries ...string) []string {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for i, e := range entries {
		w, _ := zw.Create(string(rune('a'+i)) + ".json")
		_, _ = w.Write([]byte(e))
	}
	_ = zw.Close()
	idx, err := BuildIndex(context.Background(), "npm", bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, v := range idx.Lookup("lodash", "4.17.20").Unplaced {
		ids = append(ids, v.ID)
	}
	return ids
}

// byRank is the lead order itself: a more severe lead first whichever side it is on, the id only between equal
// severities, and the answer for (a, b) the opposite of (b, a) — a sort may ask either pair, in any order.
func TestLeadRankIsSeverityThenID(t *testing.T) {
	leads := []Vuln{{ID: "A", Severity: "low"}, {ID: "B", Severity: "high"}, {ID: "C", Severity: "high"},
		{ID: "D", Severity: "critical"}, {ID: "E"}, {ID: "0", Severity: "medium"}}
	for _, a := range leads {
		for _, b := range leads {
			got, want := byRank(a, b), 0
			switch ra, rb := severityRank(a.Severity), severityRank(b.Severity); {
			case ra > rb:
				want = -1
			case ra < rb:
				want = 1
			case a.ID < b.ID:
				want = -1
			case a.ID > b.ID:
				want = 1
			}
			if got != want || byRank(b, a) != -got {
				t.Errorf("byRank(%s %q, %s %q) = %d (reverse %d), want %d", a.ID, a.Severity, b.ID, b.Severity, got, byRank(b, a), want)
			}
		}
	}
}
