package osv

import (
	"compress/gzip"
	"context"
	"encoding/gob"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luannt2002/sigforge/framework/fetch"
	"github.com/luannt2002/sigforge/modules/intel/unified"
)

// demoAdv is one advisory for the package demo in eco; affected holds its ranges (and versions).
func demoAdv(id, eco, affected string) string {
	return `{"id":"` + id + `","affected":[{"package":{"name":"demo","ecosystem":"` + eco + `"},` + affected + `}]}`
}

// advLimit is the probe's advisory: a SEMVER range from the start, limited at 2.0.0.
var advLimit = demoAdv("TEST-LIMIT", "npm", `"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"limit":"2.0.0"}]}]`)

// OSV evaluates a range's events only for a version below one of its limits (BeforeLimits: v < limit),
// so "introduced 0, limit 2.0.0" holds 1.9.9 but neither 2.0.0 nor 3.0.0 — and those two are no
// clearance either, only nothing matched.
func TestLimitBoundsTheRange(t *testing.T) {
	idx := buildIdx(t, "npm", map[string]string{"npm/TEST-LIMIT.json": advLimit})
	for _, tc := range []struct {
		version string
		want    unified.State
	}{
		{"1.9.9", unified.StateAffectedByAdvisory},
		{"2.0.0", unified.StateNotChecked},
		{"3.0.0", unified.StateNotChecked},
	} {
		u := ToUnified(idx.Lookup("demo", tc.version), "npm", "demo", tc.version, time.Time{})
		switch {
		case u.State != tc.want:
			t.Errorf("demo@%s = %v, want %v", tc.version, u.State, tc.want)
		case tc.want == unified.StateAffectedByAdvisory && (len(u.Leads) != 1 || u.Leads[0].ID != "TEST-LIMIT"):
			t.Errorf("demo@%s leads %+v, want TEST-LIMIT", tc.version, u.Leads)
		case tc.want == unified.StateNotChecked && u.Err != unified.NoteNoClearance:
			t.Errorf("demo@%s = %q, want the whole-data branch (nothing matched, no clearance)", tc.version, u.Err)
		}
	}
}

// A range's limits bound every introduced→fixed/last_affected pair of that range, whatever the event
// order; a version is inside when it is below any one of them, "*" is no limit, a listed version is
// affected past the limit, and each range keeps its own limits.
func TestLimitWithOtherEvents(t *testing.T) {
	for _, tc := range []struct {
		name, affected string
		in, out        []string
	}{
		{"limit below fixed", `"ranges":[{"type":"SEMVER","events":[{"introduced":"1.0.0"},{"fixed":"3.0.0"},{"limit":"2.0.0"}]}]`,
			[]string{"1.0.0", "1.9.9"}, []string{"0.9.0", "2.0.0", "2.5.0", "3.5.0"}},
		{"limit below last_affected", `"ranges":[{"type":"SEMVER","events":[{"introduced":"1.0.0"},{"last_affected":"2.5.0"},{"limit":"2.0.0"}]}]`,
			[]string{"1.9.9"}, []string{"0.9.0", "2.0.0", "2.5.0"}},
		{"limit over two pairs", `"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.0.0"},{"introduced":"1.5.0"},{"limit":"2.0.0"}]}]`,
			[]string{"0.5.0", "1.7.0"}, []string{"1.2.0", "2.0.0", "9.0.0"}},
		{"limit cuts every pair", `"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"2.0.0"},{"introduced":"3.0.0"},{"fixed":"4.0.0"},{"limit":"1.0.0"}]}]`,
			[]string{"0.5.0"}, []string{"1.5.0", "3.5.0"}},
		{"limit listed first", `"ranges":[{"type":"SEMVER","events":[{"limit":"2.0.0"},{"introduced":"0"}]}]`,
			[]string{"1.0.0"}, []string{"2.0.0"}},
		{"below any one limit", `"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"limit":"2.0.0"},{"limit":"3.0.0"}]}]`,
			[]string{"2.5.0"}, []string{"3.0.0"}},
		{"star is no limit", `"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"limit":"*"}]}]`,
			[]string{"99.0.0"}, nil},
		{"listed past the limit", `"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"limit":"2.0.0"}]}],"versions":["1.0.0","2.5.0"]`,
			[]string{"1.0.0", "2.5.0"}, []string{"2.4.0", "3.0.0"}},
		{"each range its own limit", `"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"limit":"2.0.0"}]},{"type":"SEMVER","events":[{"introduced":"3.0.0"},{"fixed":"3.5.0"}]}]`,
			[]string{"1.0.0", "3.2.0"}, []string{"2.5.0", "3.5.0"}},
		{"a range without a limit stays open", `"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"limit":"2.0.0"}]},{"type":"SEMVER","events":[{"introduced":"4.0.0"}]}]`,
			[]string{"1.0.0", "99.0.0"}, []string{"3.0.0"}},
	} {
		idx := buildIdx(t, "npm", map[string]string{"npm/X-1.json": demoAdv("X-1", "npm", tc.affected)})
		for _, v := range tc.in {
			if r := idx.Lookup("demo", v); r.Status != StatusVulnerable {
				t.Errorf("%s: demo@%s = %s, want vulnerable", tc.name, v, r.Status)
			}
		}
		for _, v := range tc.out {
			if r := idx.Lookup("demo", v); r.Status != StatusNoKnownVuln {
				t.Errorf("%s: demo@%s = %s, want no-known-vuln", tc.name, v, r.Status)
			}
		}
	}
}

// The limit is compared under the order every other bound uses: the ecosystem's own (PEP 440, dpkg
// with epoch and tilde), semver for a SEMVER range whatever the ecosystem. A limit that order cannot
// read leaves the version unplaced — never clean — unless the events already keep it out.
func TestLimitUnderEachComparator(t *testing.T) {
	for _, tc := range []struct {
		eco, typ, limit string
		in, out         []string
	}{
		{"PyPI", "ECOSYSTEM", "2.0", []string{"1.9.9", "2.0.rc1"}, []string{"2.0.0", "2.0.post1"}},
		{"Debian:12", "ECOSYSTEM", "2.0-1", []string{"1.9-3", "2.0~rc1-1"}, []string{"2.0-1", "1:1.0-1"}},
		{"PyPI", "SEMVER", "1.0.0+local", []string{"0.9.0"}, []string{"1.0.0"}}, // semver ignores build metadata; PEP 440 puts 1.0.0 below 1.0.0+local
	} {
		dir := strings.SplitN(tc.eco, ":", 2)[0]
		adv := demoAdv("X-1", tc.eco, `"ranges":[{"type":"`+tc.typ+`","events":[{"introduced":"0"},{"limit":"`+tc.limit+`"}]}]`)
		idx := buildIdx(t, tc.eco, map[string]string{dir + "/X-1.json": adv})
		for _, v := range tc.in {
			if r := idx.LookupIn(tc.eco, "demo", v); r.Status != StatusVulnerable {
				t.Errorf("%s %s limit %s: demo@%s = %s, want vulnerable", tc.eco, tc.typ, tc.limit, v, r.Status)
			}
		}
		for _, v := range tc.out {
			if r := idx.LookupIn(tc.eco, "demo", v); r.Status != StatusNoKnownVuln {
				t.Errorf("%s %s limit %s: demo@%s = %s, want no-known-vuln", tc.eco, tc.typ, tc.limit, v, r.Status)
			}
		}
	}
	unreadable := func(introduced string) *Index {
		return buildIdx(t, "npm", map[string]string{"npm/X-1.json": demoAdv("X-1", "npm",
			`"ranges":[{"type":"SEMVER","events":[{"introduced":"`+introduced+`"},{"limit":"not-a-version"}]}]`)})
	}
	if r := unreadable("0").Lookup("demo", "3.0.0"); r.Status != StatusUnknown || !r.PackageKnown || len(r.Vulns) != 1 {
		t.Errorf("an unreadable limit must leave 3.0.0 unplaced with the advisory as a lead, got %+v", r)
	}
	if r := unreadable("5.0.0").Lookup("demo", "3.0.0"); r.Status != StatusNoKnownVuln {
		t.Errorf("3.0.0 is below introduced, which no limit can change, got %+v", r)
	}
	// the mirror: an event bound that cannot be read leaves the version unplaced unless the limit keeps it out
	for _, events := range []string{`{"introduced":"0"},{"fixed":"@@@"}`, `{"introduced":"@@@"}`} {
		idx := buildIdx(t, "npm", map[string]string{"npm/X-1.json": demoAdv("X-1", "npm",
			`"ranges":[{"type":"SEMVER","events":[`+events+`,{"limit":"2.0.0"}]}]`)})
		if r := idx.Lookup("demo", "3.0.0"); r.Status != StatusNoKnownVuln {
			t.Errorf("%s: 3.0.0 is past the limit, which keeps it out whatever the unreadable event says, got %+v", events, r)
		}
		if r := idx.Lookup("demo", "1.0.0"); r.Status != StatusUnknown || !r.PackageKnown || len(r.Vulns) != 1 {
			t.Errorf("%s: 1.0.0 is below the limit and the event cannot be read: unplaced with the advisory as a lead, got %+v", events, r)
		}
	}
}

// A version past one range's limit is out of that range only: another record, and another package
// of the same advisory, are read as before; when nothing reaches the version it is still no clearance.
func TestLimitBindsOnlyItsOwnRange(t *testing.T) {
	twoPackages := `{"id":"X-2","affected":[` +
		`{"package":{"name":"demo","ecosystem":"npm"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"limit":"2.0.0"}]}]},` +
		`{"package":{"name":"other","ecosystem":"npm"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"4.0.0"}]}]}]}`
	idx := buildIdx(t, "npm", map[string]string{
		"npm/TEST-LIMIT.json": advLimit,
		"npm/X-1.json":        demoAdv("X-1", "npm", `"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"4.0.0"}]}]`),
		"npm/X-2.json":        twoPackages,
	})
	if r := idx.Lookup("demo", "3.0.0"); r.Status != StatusVulnerable || len(r.Vulns) != 1 || r.Vulns[0].ID != "X-1" {
		t.Errorf("demo@3.0.0 is past both limits but inside X-1: %s %+v", r.Status, r.Vulns)
	}
	if r := idx.Lookup("other", "3.0.0"); r.Status != StatusVulnerable || len(r.Vulns) != 1 || r.Vulns[0].ID != "X-2" {
		t.Errorf("other@3.0.0 has no limit and is before X-2's fix: %s %+v", r.Status, r.Vulns)
	}
	if u := ToUnified(idx.Lookup("demo", "4.0.0"), "npm", "demo", "4.0.0", time.Time{}); u.State != unified.StateNotChecked || u.Err != unified.NoteNoClearance {
		t.Errorf("demo@4.0.0 is reached by nothing: %v %q, want no clearance", u.State, u.Err)
	}
}

// A limit is a version the record names, as a fixed bound is: a platform release at or above it is not
// older than every version the package's advisories name, so a listed advisory reaches it unmarked.
func TestLimitCountsAsANamedVersion(t *testing.T) {
	for _, upper := range []string{"limit", "fixed"} {
		idx := buildIdx(t, "Packagist", map[string]string{
			"Packagist/GHSA-l.json": `{"id":"GHSA-l","affected":[{"package":{"name":"acme/core","ecosystem":"Packagist"},` +
				`"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"` + upper + `":"6.0.0"}]}]}]}`,
			"Packagist/GHSA-a.json": `{"id":"GHSA-a","affected":[{"package":{"name":"acme/core","ecosystem":"Packagist"},` +
				`"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"7.1.0"}]}],"versions":["7.0.0"]}]}`,
		})
		got := idx.lookup("", "acme/core", "6.5.0", true)
		if got.BelowListed || len(got.Vulns) != 1 || got.Vulns[0].ID != "GHSA-a" || got.Vulns[0].OutsideListed {
			t.Errorf("%s 6.0.0 names a version: release 6.5.0 below=%v %+v, want GHSA-a unmarked", upper, got.BelowListed, got.Vulns)
		}
	}
}

// The limits travel in the index file: a run reading it answers as the run that reduced the dump.
func TestIndexFileKeepsTheLimit(t *testing.T) {
	r, size := makeZip(t, map[string]string{
		"npm/TEST-LIMIT.json": advLimit,
		"npm/X-1.json":        demoAdv("X-1", "npm", `"ranges":[{"type":"SEMVER","events":[{"introduced":"3.0.0"},{"limit":"4.0.0"},{"limit":"5.0.0"}]}]`),
	})
	path := filepath.Join(t.TempDir(), "dump.idx.gz")
	all := func(*record) bool { return true }
	built, err := buildIndex(context.Background(), "npm", r, size, all, path, "stamp")
	if err != nil {
		t.Fatal(err)
	}
	read, err := readIndexFile(path, "stamp", "npm", all)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		version string
		want    Status
	}{
		{"1.9.9", StatusVulnerable}, {"2.0.0", StatusNoKnownVuln}, {"3.0.0", StatusVulnerable},
		{"4.5.0", StatusVulnerable}, {"5.0.0", StatusNoKnownVuln},
	} {
		for name, idx := range map[string]*Index{"reduced": built, "read back": read} {
			if got := idx.Lookup("demo", tc.version); got.Status != tc.want {
				t.Errorf("%s: demo@%s = %s, want %s", name, tc.version, got.Status, tc.want)
			}
		}
	}
}

// A record changed after the dump reaches a run through the overlay with its limit: the dump's open
// range is replaced, so 3.0.0 is no longer reached while 1.9.9 still is.
func TestOverlayRecordKeepsItsLimit(t *testing.T) {
	open := `{"id":"GHSA-lim","affected":[{"package":{"name":"lodash","ecosystem":"npm"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"}]}]}]}`
	limited := strings.Replace(open, `{"introduced":"0"}`, `{"introduced":"0"},{"limit":"2.0.0"}`, 1)
	r, _ := makeZip(t, map[string]string{"npm/GHSA-lim.json": open})
	m := &osvMirror{dump: mustBytes(r)}
	syncNow, look, _ := mirrorRun(t, m)
	m.set(func() {
		m.csv = "2026-11-09T04:00:00Z,GHSA-lim\n"
		m.records = map[string]string{"GHSA-lim": limited}
	})
	if err := syncNow(); err != nil {
		t.Fatal(err)
	}
	if m.zips.Load() != 1 || m.recs.Load() != 1 {
		t.Fatalf("the change must come from the overlay: %d dump downloads (want 1), %d records (want 1)", m.zips.Load(), m.recs.Load())
	}
	for _, tc := range []struct {
		version string
		want    unified.State
	}{
		{"1.9.9", unified.StateAffectedByAdvisory},
		{"3.0.0", unified.StateNotChecked},
	} {
		if u := look(tc.version); u.State != tc.want {
			t.Errorf("lodash@%s after the overlay = %v %q, want %v", tc.version, u.State, u.Err, tc.want)
		}
	}
}

// An index file cut before rows carried a range's limits holds that range open. Its format is not
// this one, so a run does not read it: the stored dump is reduced again and the file re-cut. The same
// rows under this format are read as they are, so the format alone decides.
func TestIndexFileCutBeforeLimitIsCutAgain(t *testing.T) {
	r, _ := makeZip(t, map[string]string{"npm/TEST-LIMIT.json": advLimit})
	body := mustBytes(r)
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = w.Write(body)
	}))
	defer srv.Close()
	c := fetch.New()
	c.CacheDir, c.MaxAge = t.TempDir(), time.Hour
	look := func() Status {
		t.Helper()
		idx, err := New(srv.URL, c).LoadIndex(context.Background(), "npm")
		if err != nil {
			t.Fatal(err)
		}
		return idx.Lookup("demo", "3.0.0").Status
	}
	look()
	dumps, _ := filepath.Glob(filepath.Join(c.CacheDir, "*.body"))
	if len(dumps) != 1 {
		t.Fatalf("want one stored dump, found %v", dumps)
	}
	st, err := os.Stat(dumps[0])
	if err != nil {
		t.Fatal(err)
	}
	plant := func(format string) {
		t.Helper()
		f, err := os.Create(dumps[0] + ".idx.gz")
		if err != nil {
			t.Fatal(err)
		}
		gz := gzip.NewWriter(f)
		enc := gob.NewEncoder(gz)
		for _, v := range []any{
			indexHeader{Format: format, Dump: dumpStamp(st)},
			indexRow{Pkg: "demo", Ecosystem: "npm", ID: "TEST-LIMIT", VulnKeys: []string{"TEST-LIMIT"}, Ranges: []indexRange{{Typ: "SEMVER", Introduced: "0"}}},
			indexRow{}, // trailer: no unreadable entry
		} {
			if err := enc.Encode(v); err != nil {
				t.Fatal(err)
			}
		}
		if err := gz.Close(); err != nil {
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
	}
	plant(indexFormat)
	if got := look(); got != StatusVulnerable {
		t.Fatalf("rows under this format are what a run reads: demo@3.0.0 = %s, want the planted open range", got)
	}
	plant("sigforge-osv-index/10") // the format index files were cut under before rows carried limits
	if got := look(); got != StatusNoKnownVuln {
		t.Fatalf("an index file cut before limits was read: demo@3.0.0 = %s, want the dump reduced again", got)
	}
	if hits.Load() != 1 {
		t.Fatalf("the stored dump must answer, not a new download: %d requests", hits.Load())
	}
	f, err := os.Open(dumps[0] + ".idx.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := indexDecoder(f, dumpStamp(st)); err != nil {
		t.Fatalf("the index file must be re-cut under this format: %v", err)
	}
}
