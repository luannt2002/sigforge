package osv

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"slices"
	"testing"
)

// indexInOrder builds an index from a zip holding bodies in the given order, which makeZip's map cannot fix.
func indexInOrder(t *testing.T, eco string, order []int, bodies []string) *Index {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, i := range order {
		w, err := zw.Create(fmt.Sprintf("%d.json", i))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(bodies[i])); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	idx, err := BuildIndex(context.Background(), eco, bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatal(err)
	}
	return idx
}

// A dump's entry order is arbitrary, so the floor — and the marks it decides — must not depend on it (F21).
func TestFloorIgnoresEntryOrder(t *testing.T) {
	for _, eco := range []string{"Packagist", "NuGet"} {
		bodies := []string{
			demoAdv("GHSA-a", eco, `"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"limit":"@@@"}]}]`),
			demoAdv("GHSA-b", eco, `"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"7.1.0"}]}],"versions":["7.0.0"]`),
			demoAdv("GHSA-c", eco, `"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"7.3.0"}]}],"versions":["7.2.0"]`),
		}
		for _, order := range [][]int{{0, 1, 2}, {0, 2, 1}, {1, 0, 2}, {1, 2, 0}, {2, 0, 1}, {2, 1, 0}} {
			idx := indexInOrder(t, eco, order, bodies)
			floors := map[string]string{}
			for _, r := range idx.byName["demo"] {
				floors[r.id] = r.floor
			}
			if len(floors) != 3 || floors["GHSA-a"] != "" || floors["GHSA-b"] != "7.0.0" || floors["GHSA-c"] != "7.2.0" {
				t.Errorf("%s entries %v: floors %q, want GHSA-a none, GHSA-b 7.0.0, GHSA-c 7.2.0", eco, order, floors)
			}
			for _, tc := range []struct {
				release string
				below   bool
			}{{"6.5.0", true}, {"6.9.9", true}, {"7.0.0", false}} {
				got := idx.lookup("", "demo", tc.release, true)
				marked := map[string]bool{}
				for _, v := range got.Vulns {
					marked[v.ID] = v.OutsideListed
				}
				b, hasB := marked["GHSA-b"]
				c, hasC := marked["GHSA-c"]
				if got.BelowListed != tc.below || !hasB || !hasC || b != tc.below || c != tc.below {
					t.Errorf("%s entries %v: release %s below=%v marks %v, want below=%v with GHSA-b and GHSA-c kept, marked=%v",
						eco, order, tc.release, got.BelowListed, marked, tc.below, tc.below)
				}
			}
		}
	}
}

// A value the ecosystem's order cannot read names no version to compare against, so wherever it sits it is never a floor.
func TestUnreadableValueNeverBecomesTheFloor(t *testing.T) {
	for _, tc := range []struct {
		name, eco string
		events    []rawEvent
		versions  []string
		want      string
	}{
		{"listed first", "Packagist", []rawEvent{{Introduced: "0"}, {Fixed: "7.1.0"}}, []string{"dev-master", "7.0.0"}, "7.0.0"},
		{"bound first", "Packagist", []rawEvent{{Introduced: "@@@"}, {Fixed: "6.9.0"}}, nil, "6.9.0"},
		{"limit only", "Packagist", []rawEvent{{Introduced: "0"}, {Limit: "@@@"}}, nil, ""},
		{"NuGet listed first", "NuGet", []rawEvent{{Introduced: "0"}, {Fixed: "2.1.0"}}, []string{"@@@", "2.0.0"}, "2.0.0"},
		{"npm listed first", "npm", []rawEvent{{Introduced: "0"}, {LastAffected: "1.4.0"}}, []string{"latest", "1.3.0"}, "1.3.0"},
		{"PyPI bound first", "PyPI", []rawEvent{{Introduced: "@@@"}, {Fixed: "2.0"}}, nil, "2.0"},
		{"no order for the ecosystem", "Linux", []rawEvent{{Introduced: "0"}, {Fixed: "6.1.2"}}, []string{"6.1.1"}, ""},
	} {
		raw := rawRecord{ID: "X-1", Affected: []*rawAffected{{Package: rawPackage{Name: "demo", Ecosystem: tc.eco},
			Ranges: []rawRange{{Type: "ECOSYSTEM", Events: tc.events}}, Versions: tc.versions}}}
		if recs := reduceRecord(&raw, tc.eco); len(recs) != 1 || recs[0].floor != tc.want {
			t.Errorf("%s: %+v, want floor %q", tc.name, recs, tc.want)
		}
	}
	// rows of an index file cut before this fix can still carry an unreadable floor
	a := record{pkg: "demo", ecosystem: "Packagist", id: "GHSA-a", vulnKeys: []string{"GHSA-a"}, floor: "@@@",
		ranges: []affectedRange{{typ: "ECOSYSTEM", introduced: "0", limits: []string{"@@@"}}}}
	b := record{pkg: "demo", ecosystem: "Packagist", id: "GHSA-b", vulnKeys: []string{"GHSA-b"}, floor: "7.0.0", listed: true,
		ranges: []affectedRange{{typ: "ECOSYSTEM", introduced: "0", fixed: "7.1.0"}}}
	for _, rows := range [][]record{{a, b}, {b, a}} {
		idx := newIndex("Packagist")
		for i := range rows {
			idx.add(&rows[i])
		}
		got := idx.lookup("", "demo", "6.5.0", true)
		if !got.BelowListed || !slices.ContainsFunc(got.Vulns, func(v Vuln) bool { return v.ID == "GHSA-b" && v.OutsideListed }) {
			t.Errorf("rows %s,%s: release 6.5.0 below=%v %+v, want below 7.0.0 with GHSA-b kept, marked", rows[0].id, rows[1].id, got.BelowListed, got.Vulns)
		}
	}
}

// Readable values keep the floor they always had: the lowest under the ecosystem's own order, listed first or last.
func TestReadableValuesKeepTheirFloor(t *testing.T) {
	for _, tc := range []struct {
		eco      string
		events   []rawEvent
		versions []string
		want     string
	}{
		{"Packagist", []rawEvent{{Introduced: "0"}, {Fixed: "6.5.1.0"}}, []string{"6.5.0.0", "6.2.0"}, "6.2.0"},
		{"Maven", []rawEvent{{Introduced: "0"}, {Fixed: "2.1"}}, []string{"2.0", "1.5.Final"}, "1.5.Final"},
		{"NuGet", []rawEvent{{Introduced: "0"}, {Fixed: "1.0.1"}}, []string{"1.0.0", "1.0.0-Beta"}, "1.0.0-Beta"},
		{"npm", []rawEvent{{Introduced: "1.0.0-rc.1"}, {Fixed: "1.0.1"}}, nil, "1.0.0-rc.1"},
		{"npm", []rawEvent{{Introduced: "1.5.0"}, {LastAffected: "1.9.0"}, {Limit: "1.2.0"}}, nil, "1.2.0"},
		{"PyPI", []rawEvent{{Introduced: "0"}, {Fixed: "1.1"}}, []string{"1.0", "1.0a1"}, "1.0a1"},
		{"RubyGems", []rawEvent{{Introduced: "0"}, {Fixed: "1.0.1"}}, []string{"1.0.0", "1.0.0.pre"}, "1.0.0.pre"},
		{"Debian:12", []rawEvent{{Introduced: "0"}, {Fixed: "1.0-2"}}, []string{"1.0-1", "1.0~rc1-1"}, "1.0~rc1-1"},
		{"Go", []rawEvent{{Introduced: "0"}, {Fixed: "1.10.1"}}, []string{"1.10.0", "1.2.3"}, "1.2.3"},
	} {
		rev := slices.Clone(tc.versions)
		slices.Reverse(rev)
		for _, versions := range [][]string{tc.versions, rev} {
			raw := rawRecord{ID: "X-1", Affected: []*rawAffected{{Package: rawPackage{Name: "demo", Ecosystem: tc.eco},
				Ranges: []rawRange{{Type: "ECOSYSTEM", Events: tc.events}}, Versions: versions}}}
			if recs := reduceRecord(&raw, tc.eco); len(recs) != 1 || recs[0].floor != tc.want {
				t.Errorf("%s %+v %v: %+v, want floor %q", tc.eco, tc.events, versions, recs, tc.want)
			}
		}
	}
}
