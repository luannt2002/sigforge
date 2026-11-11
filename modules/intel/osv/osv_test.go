package osv

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luannt2002/sigforge/framework/fetch"
	"github.com/luannt2002/sigforge/modules/intel/unified"
)

// Real OSV advisory shapes (trimmed to the fields the reducer reads).
const (
	// lodash: a half-open range, fixed in 4.17.21, with a CVE alias and a GHSA text severity.
	advLodash = `{
	  "id":"GHSA-35jh-r3h4-6jhm","aliases":["CVE-2021-23337"],
	  "database_specific":{"severity":"HIGH"},
	  "affected":[{"package":{"name":"lodash","ecosystem":"npm"},
	    "ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"4.17.21"}]}]}]
	}`
	// A multi-ecosystem advisory: the npm index must keep the npm package and drop the PyPI one.
	advMulti = `{
	  "id":"GHSA-multi-0001","aliases":["CVE-2022-0001"],
	  "database_specific":{"severity":"CRITICAL"},
	  "affected":[
	    {"package":{"name":"minimist","ecosystem":"npm"},
	      "ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.2.6"}]}]},
	    {"package":{"name":"minimist-py","ecosystem":"PyPI"},
	      "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"9.9.9"}]}]}]
	}`
	// Withdrawn: reporting it would be a pure false positive, so the reducer drops it entirely.
	advWithdrawn = `{
	  "id":"GHSA-withdrawn-1","aliases":["CVE-2019-0000"],"withdrawn":"2020-01-01T00:00:00Z",
	  "database_specific":{"severity":"HIGH"},
	  "affected":[{"package":{"name":"ghost","ecosystem":"npm"},
	    "ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"9.9.9"}]}]}]
	}`
	// No range at all, only a concrete affected-version list: the matcher must fall back to exact
	// version matching (reduce.go keeps versions[] only in this case).
	advConcrete = `{
	  "id":"GHSA-concrete-1","aliases":["CVE-2023-0002"],
	  "database_specific":{"severity":"MODERATE"},
	  "affected":[{"package":{"name":"leftpad","ecosystem":"npm"},
	    "versions":["1.0.0","1.0.1"]}]
	}`
	// A last_affected range (CLOSED upper bound): version <= last_affected is affected. Exercises the
	// rangesFrom last_affected event path, which the flat VersionInRange test does not reach.
	advLastAffected = `{
	  "id":"GHSA-last-1","aliases":["CVE-2023-0003"],
	  "database_specific":{"severity":"LOW"},
	  "affected":[{"package":{"name":"tailpkg","ecosystem":"npm"},
	    "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"1.0.0"},{"last_affected":"1.5.0"}]}]}]
	}`
	// Multi-range (OR): one affected package with two disjoint ranges[] — a version is affected if it
	// falls in EITHER. OSV schema allows several ranges per affected entry (ossf.github.io/osv-schema).
	advMultiRange = `{
	  "id":"GHSA-multirange-1","aliases":["CVE-2024-3001"],
	  "database_specific":{"severity":"HIGH"},
	  "affected":[{"package":{"name":"multir","ecosystem":"npm"},
	    "ranges":[
	      {"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.2.0"}]},
	      {"type":"SEMVER","events":[{"introduced":"2.0.0"},{"fixed":"2.1.0"}]}]}]
	}`
	// Two introduced/fixed pairs in ONE range: affected in [0,1.2.0) and [1.5.0,1.6.0), clean in the
	// gap [1.2.0,1.5.0). OSV events are an ordered timeline that can reopen a range.
	advTwoPairs = `{
	  "id":"GHSA-twopairs-1","aliases":["CVE-2024-3002"],
	  "database_specific":{"severity":"MODERATE"},
	  "affected":[{"package":{"name":"twopair","ecosystem":"npm"},
	    "ranges":[{"type":"SEMVER","events":[
	      {"introduced":"0"},{"fixed":"1.2.0"},
	      {"introduced":"1.5.0"},{"fixed":"1.6.0"}]}]}]
	}`
	// GIT-only range: bounds are commit hashes, not versions. The package must stay indexed and the
	// lookup must be honestly UNKNOWN (never a silent "no vuln"), since the version cannot be positioned.
	advGitOnly = `{
	  "id":"OSV-2021-GIT1","aliases":["CVE-2021-9999"],
	  "database_specific":{"severity":"HIGH"},
	  "affected":[{"package":{"name":"gitpkg","ecosystem":"npm"},
	    "ranges":[{"type":"GIT","events":[
	      {"introduced":"0"},{"fixed":"6879efc2c1596d11a6a6ce296d1cf3b2f5b4f6ad"}]}]}]
	}`
	// Alias dedup: the SAME flaw appears under a GHSA id and a GO id, cross-referencing each other via
	// aliases (real cross-source overlap in the Go dump). It must fold to ONE vuln, not two.
	advDupGhsa = `{
	  "id":"GHSA-dup-aaaa-bbbb-cccc","aliases":["CVE-2024-1111","GO-2024-2222"],
	  "database_specific":{"severity":"HIGH"},
	  "affected":[{"package":{"name":"example.com/pkg","ecosystem":"Go"},
	    "ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"2.0.0"}]}]}]
	}`
	advDupGo = `{
	  "id":"GO-2024-2222","aliases":["CVE-2024-1111","GHSA-dup-aaaa-bbbb-cccc"],
	  "database_specific":{"severity":"HIGH"},
	  "affected":[{"package":{"name":"example.com/pkg","ecosystem":"Go"},
	    "ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"2.0.0"}]}]}]
	}`
)

// buildIdx packs name→json entries into a zip and builds an index for eco (no disk, no network).
func buildIdx(t *testing.T, eco string, entries map[string]string) *Index {
	t.Helper()
	r, size := makeZip(t, entries)
	idx, err := BuildIndex(context.Background(), eco, r, size)
	if err != nil {
		t.Fatalf("BuildIndex(%s): %v", eco, err)
	}
	return idx
}

// makeZip packs name→json-content into a zip, returning a ReaderAt + its size (no disk, no network).
func makeZip(t *testing.T, entries map[string]string) (*bytes.Reader, int64) {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, content := range entries {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("zip create %s: %v", name, err)
		}
		if _, err := w.Write([]byte(content)); err != nil {
			t.Fatalf("zip write %s: %v", name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	b := buf.Bytes()
	return bytes.NewReader(b), int64(len(b))
}

func npmIndex(t *testing.T) *Index {
	t.Helper()
	r, size := makeZip(t, map[string]string{
		"npm/GHSA-35jh-r3h4-6jhm.json": advLodash,
		"npm/GHSA-multi-0001.json":     advMulti,
		"npm/GHSA-withdrawn-1.json":    advWithdrawn,
		"npm/not-json.txt":             "ignored",
		"npm/corrupt.json":             "{ this is not json",
	})
	idx, err := BuildIndex(context.Background(), "npm", r, size)
	if err != nil {
		t.Fatalf("BuildIndex: %v", err)
	}
	return idx
}

// ---- Ecosystem alias map (pure) ----

func TestEcosystem(t *testing.T) {
	cases := map[string]string{"yarn": "npm", "pip": "PyPI", "golang": "Go", "cargo": "crates.io", "DOTNET": "NuGet"}
	for alias, want := range cases {
		if got, ok := Ecosystem(alias); !ok || got != want {
			t.Errorf("Ecosystem(%q) = %q,%v; want %q", alias, got, ok, want)
		}
	}
	if _, ok := Ecosystem("cocoapods"); ok {
		t.Error("an unsupported ecosystem must report ok=false")
	}
}

// ---- Version comparison + range (pure) — MUTATION TARGET ----

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.2.3", "1.2.3", 0},
		{"1.2", "1.2.0", 0},
		{"v1.2.3", "1.2.3", 0},
		{"1.2.3", "1.2.4", -1},
		{"1.10.0", "1.9.0", 1}, // numeric, not lexical
		{"1.0.0-rc.1", "1.0.0", -1},
		{"4.17.21+build", "4.17.21", 0},
		{"20230101120000", "20230101119999", 1}, // long numeric, no int64 overflow
	}
	for _, c := range cases {
		if got := CompareVersions(c.a, c.b); got != c.want {
			t.Errorf("CompareVersions(%q,%q) = %d; want %d", c.a, c.b, got, c.want)
		}
	}
}

// VersionInRange is the matcher a mutation (flip the half-open/closed comparison) must break.
func TestVersionInRange(t *testing.T) {
	halfOpen := affectedRange{introduced: "4.0.0", fixed: "4.17.21"} // version < fixed is affected
	if !VersionInRange("4.17.20", halfOpen) {
		t.Error("4.17.20 is below the fix and must be in range")
	}
	if VersionInRange("4.17.21", halfOpen) {
		t.Error("4.17.21 is the fixed version and must be OUT of a half-open range")
	}
	if VersionInRange("3.0.0", halfOpen) {
		t.Error("3.0.0 is below introduced and must be out of range")
	}
	closed := affectedRange{introduced: "0", lastAffected: "2.0.0"} // version <= last is affected
	if !VersionInRange("2.0.0", closed) {
		t.Error("2.0.0 equals last_affected and must be in a closed range")
	}
	if VersionInRange("2.0.1", closed) {
		t.Error("2.0.1 is past last_affected and must be out of range")
	}
	openEnded := affectedRange{introduced: "1.0.0"} // introduced, never fixed
	if !VersionInRange("99.0.0", openEnded) {
		t.Error("an introduced-but-never-fixed range must cover every later version")
	}
}

func TestCleanVersion(t *testing.T) {
	if CleanVersion("4.17.15") == "" {
		t.Error("a pinned version must survive CleanVersion")
	}
	for _, r := range []string{"^4.17.0", ">=1.2 <2", "", "   "} {
		if CleanVersion(r) != "" {
			t.Errorf("a range/empty version %q must clean to \"\"", r)
		}
	}
}

// ---- reduceRecord (pure) ----

func TestReduceRecordWithdrawnDropped(t *testing.T) {
	var raw rawRecord
	mustUnmarshal(t, advWithdrawn, &raw)
	if recs := reduceRecord(&raw, "npm"); recs != nil {
		t.Fatalf("a withdrawn advisory must reduce to nil, got %+v", recs)
	}
}

func TestReduceRecordFiltersForeignEcosystem(t *testing.T) {
	var raw rawRecord
	mustUnmarshal(t, advMulti, &raw)
	recs := reduceRecord(&raw, "npm")
	if len(recs) != 1 || recs[0].pkg != "minimist" {
		t.Fatalf("the npm index must keep only the npm package, got %+v", recs)
	}
}

// ---- Lookup tri-state over a built index ----

func TestLookupVulnerable(t *testing.T) {
	res := npmIndex(t).Lookup("lodash", "4.17.20")
	if res.Status != StatusVulnerable {
		t.Fatalf("lodash 4.17.20 must be vulnerable, got %s", res.Status)
	}
	if len(res.Vulns) != 1 || res.Vulns[0].CVE != "CVE-2021-23337" || res.Vulns[0].Severity != "high" {
		t.Fatalf("wrong vuln detail: %+v", res.Vulns)
	}
	if res.Vulns[0].Ref() != "CVE-2021-23337" {
		t.Fatalf("Ref must prefer the CVE, got %q", res.Vulns[0].Ref())
	}
}

// version OUTSIDE every affected range, package KNOWN → RESOLVED no-known-vuln (not "unknown", not "vulnerable").
func TestLookupResolvedVersionOutOfRange(t *testing.T) {
	res := npmIndex(t).Lookup("lodash", "4.17.21")
	if res.Status != StatusNoKnownVuln {
		t.Fatalf("lodash 4.17.21 (fixed) must be no-known-vuln, got %s", res.Status)
	}
	if len(res.Vulns) != 0 {
		t.Fatalf("a resolved lookup must carry no vulns, got %+v", res.Vulns)
	}
}

// package NOT in the index → UNKNOWN, never "safe".
func TestLookupUnknownPackage(t *testing.T) {
	if res := npmIndex(t).Lookup("totally-unseen-pkg", "1.0.0"); res.Status != StatusUnknown {
		t.Fatalf("an unseen package must be unknown (not safe), got %s", res.Status)
	}
}

// nil index (source off / dump dead) → UNKNOWN, never "safe".
func TestLookupNilIndexUnknown(t *testing.T) {
	var idx *Index
	if res := idx.Lookup("lodash", "4.17.20"); res.Status != StatusUnknown {
		t.Fatalf("a nil index must be unknown, got %s", res.Status)
	}
}

// An unpinnable version (a manifest range) against a known package surfaces every advisory.
func TestLookupUnpinnedVersionSurfacesAll(t *testing.T) {
	res := npmIndex(t).Lookup("lodash", "^4.0.0")
	if res.Status != StatusVulnerable || len(res.Vulns) != 1 {
		t.Fatalf("an unpinned version must surface the package's advisories, got %s %+v", res.Status, res.Vulns)
	}
}

func TestBuildIndexSkipsCorruptAndWithdrawn(t *testing.T) {
	idx := npmIndex(t)
	// lodash + minimist survive; the withdrawn ghost, the foreign PyPI pkg, and the corrupt entry do not.
	if idx.Packages() != 2 {
		t.Fatalf("want 2 packages (lodash, minimist), got %d", idx.Packages())
	}
	if res := idx.Lookup("ghost", "1.0.0"); res.Status != StatusUnknown {
		t.Fatalf("the withdrawn advisory's package must not be indexed, got %s", res.Status)
	}
}

// ---- concrete-version list + last_affected (match paths the flat tests miss) ----

func buildNpm(t *testing.T, name, adv string) *Index {
	t.Helper()
	r, size := makeZip(t, map[string]string{"npm/" + name + ".json": adv})
	idx, err := BuildIndex(context.Background(), "npm", r, size)
	if err != nil {
		t.Fatalf("BuildIndex: %v", err)
	}
	return idx
}

// An advisory with NO range matches only via the concrete versions[] list.
func TestLookupConcreteVersionList(t *testing.T) {
	idx := buildNpm(t, "GHSA-concrete-1", advConcrete)
	if res := idx.Lookup("leftpad", "1.0.1"); res.Status != StatusVulnerable || len(res.Vulns) != 1 {
		t.Fatalf("a listed concrete version must be vulnerable, got %s %+v", res.Status, res.Vulns)
	}
	// A version NOT in the list, package known ⇒ resolved no-known-vuln, never "unknown".
	if res := idx.Lookup("leftpad", "2.0.0"); res.Status != StatusNoKnownVuln {
		t.Fatalf("a version outside the concrete list must be no-known-vuln, got %s", res.Status)
	}
}

// last_affected is a CLOSED upper bound: version <= last_affected is affected, past it is not.
func TestLookupLastAffectedRange(t *testing.T) {
	idx := buildNpm(t, "GHSA-last-1", advLastAffected)
	if res := idx.Lookup("tailpkg", "1.5.0"); res.Status != StatusVulnerable {
		t.Fatalf("1.5.0 equals last_affected and must be vulnerable, got %s", res.Status)
	}
	if res := idx.Lookup("tailpkg", "1.5.1"); res.Status != StatusNoKnownVuln {
		t.Fatalf("1.5.1 is past last_affected and must be no-known-vuln, got %s", res.Status)
	}
	if res := idx.Lookup("tailpkg", "0.9.0"); res.Status != StatusNoKnownVuln {
		t.Fatalf("0.9.0 is below introduced and must be no-known-vuln, got %s", res.Status)
	}
}

// ---- caps / guards ----

// reduceRecord keeps at most maxExactVersions concrete versions so a huge list cannot balloon RAM.
func TestReduceRecordCapsExactVersions(t *testing.T) {
	versions := make([]string, maxExactVersions+20)
	for i := range versions {
		versions[i] = fmt.Sprintf("1.0.%d", i)
	}
	raw := rawRecord{ID: "GHSA-many", Affected: []*rawAffected{{Package: rawPackage{Name: "big", Ecosystem: "npm"}, Versions: versions}}}
	recs := reduceRecord(&raw, "npm")
	if len(recs) != 1 || len(recs[0].versions) != maxExactVersions {
		t.Fatalf("exact-version list must cap at %d, got %+v", maxExactVersions, recs)
	}
}

// reduceZip reports errEmptyDump for a zero-size dump rather than building a silent empty index.
func TestReduceZipEmptyDump(t *testing.T) {
	_, err := reduceZip(context.Background(), bytes.NewReader(nil), 0, "npm", func(*record) error { return nil })
	if err != errEmptyDump {
		t.Fatalf("a zero-size dump must return errEmptyDump, got %v", err)
	}
}

// ---- LoadIndex over httptest (no real network) ----

func serveZip(t *testing.T, body []byte) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func TestLoadIndexDownloadsAndReduces(t *testing.T) {
	r, _ := makeZip(t, map[string]string{"npm/GHSA-35jh-r3h4-6jhm.json": advLodash})
	a := New(serveZip(t, mustBytes(r)), fetch.New())
	idx, err := a.LoadIndex(context.Background(), "npm")
	if err != nil {
		t.Fatalf("LoadIndex: %v", err)
	}
	if res := idx.Lookup("lodash", "4.17.20"); res.Status != StatusVulnerable {
		t.Fatalf("downloaded index must find lodash vulnerable, got %s", res.Status)
	}
}

// A dead source → an ERROR (so the caller keeps its honest "unknown"), never a silent empty index.
func TestLoadIndexDeadSourceErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "down", http.StatusInternalServerError)
	}))
	defer srv.Close()
	a := New(srv.URL, fetch.New())
	if _, err := a.LoadIndex(context.Background(), "npm"); err == nil {
		t.Fatal("a dead source must return an error, not a silent empty index")
	}
}

// Source off (empty env URL) → an error, not a silent "no vuln".
func TestLoadIndexSourceOff(t *testing.T) {
	a := New("", fetch.New())
	if _, err := a.LoadIndex(context.Background(), "npm"); err == nil {
		t.Fatal("an empty source URL must return an error")
	}
}

func TestLoadIndexUnknownEcosystem(t *testing.T) {
	a := New("http://127.0.0.1:1/should-not-hit", fetch.New())
	if _, err := a.LoadIndex(context.Background(), "cocoapods"); err == nil {
		t.Fatal("an unsupported ecosystem must error before any network call")
	}
}

func mustBytes(r *bytes.Reader) []byte {
	b := make([]byte, r.Len())
	_, _ = r.ReadAt(b, 0)
	return b
}

func mustUnmarshal(t *testing.T, s string, v *rawRecord) {
	t.Helper()
	if err := json.Unmarshal([]byte(s), v); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
}

// ---- affected-range evaluation (OSV schema correctness) ----

// Multi-range OR: a version is affected if it falls in ANY of the affected entry's ranges[].
func TestLookupMultiRangeOR(t *testing.T) {
	idx := buildNpm(t, "GHSA-multirange-1", advMultiRange)
	for _, v := range []string{"0.5.0", "2.0.5"} {
		if res := idx.Lookup("multir", v); res.Status != StatusVulnerable {
			t.Fatalf("%s falls in a range and must be vulnerable, got %s", v, res.Status)
		}
	}
	// 1.5.0 is past the first range's fix and before the second range opens → clean.
	if res := idx.Lookup("multir", "1.5.0"); res.Status != StatusNoKnownVuln {
		t.Fatalf("1.5.0 is between the two ranges and must be no-known-vuln, got %s", res.Status)
	}
}

// Two introduced/fixed pairs in ONE range: affected in each pair's window, clean in the gap.
func TestLookupTwoIntroducedFixedPairs(t *testing.T) {
	idx := buildNpm(t, "GHSA-twopairs-1", advTwoPairs)
	affected := []string{"1.0.0", "1.5.5"}
	clean := []string{"1.3.0", "1.6.0"} // the gap, and the second fix (half-open)
	for _, v := range affected {
		if res := idx.Lookup("twopair", v); res.Status != StatusVulnerable {
			t.Fatalf("%s is inside a pair and must be vulnerable, got %s", v, res.Status)
		}
	}
	for _, v := range clean {
		if res := idx.Lookup("twopair", v); res.Status != StatusNoKnownVuln {
			t.Fatalf("%s is outside every pair and must be no-known-vuln, got %s", v, res.Status)
		}
	}
}

// GIT range: the version cannot be positioned by a commit hash, so the lookup is honestly UNKNOWN
// (package known), never a silent "no vuln". The package must still be indexed.
func TestLookupGitRangeUnknown(t *testing.T) {
	idx := buildNpm(t, "OSV-2021-GIT1", advGitOnly)
	if idx.Packages() != 1 {
		t.Fatalf("a GIT-only advisory must keep the package indexed, got %d packages", idx.Packages())
	}
	res := idx.Lookup("gitpkg", "1.0.0")
	if res.Status != StatusUnknown || !res.PackageKnown {
		t.Fatalf("a GIT-only range must be unknown+package-known (potentially affected), got %s known=%v", res.Status, res.PackageKnown)
	}
}

// Alias dedup: the same flaw under a GHSA id and a GO id (cross-aliased) folds to ONE vuln.
func TestLookupAliasDedup(t *testing.T) {
	idx := buildIdx(t, "Go", map[string]string{
		"Go/GHSA-dup-aaaa-bbbb-cccc.json": advDupGhsa,
		"Go/GO-2024-2222.json":            advDupGo,
	})
	res := idx.Lookup("example.com/pkg", "1.0.0")
	if res.Status != StatusVulnerable {
		t.Fatalf("1.0.0 is below the fix and must be vulnerable, got %s", res.Status)
	}
	if len(res.Vulns) != 1 {
		t.Fatalf("a cross-aliased duplicate must dedup to 1 vuln, got %d: %+v", len(res.Vulns), res.Vulns)
	}
}

// One run's lookups load each ecosystem's dump once — a dump is the whole ecosystem — and
// every case the source cannot answer stays unanswered: an unsupported ecosystem and an
// off source are not_checked, never clean.
func TestLookuperLoadsEachEcosystemOnce(t *testing.T) {
	r, _ := makeZip(t, map[string]string{"npm/GHSA-35jh-r3h4-6jhm.json": advLodash})
	body := mustBytes(r)
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = w.Write(body)
	}))
	defer srv.Close()
	ctx := context.Background()
	look := New(srv.URL, fetch.New()).Lookuper()
	vuln := look(ctx, "npm", "lodash", "4.17.20")
	other := look(ctx, "npm", "left-pad", "1.3.0")
	if n := hits.Load(); n != 1 {
		t.Fatalf("two npm packages must load the npm dump once, loaded %d times", n)
	}
	if vuln.State != unified.StateAffectedByAdvisory || len(vuln.Leads) == 0 {
		t.Fatalf("lodash 4.17.20 = %+v, want affected with leads", vuln)
	}
	if other.State == unified.StateNotAffectedByAdvisory || other.State.Applicable() {
		t.Fatalf("a package absent from the dump must stay unknown, got %s", other.State)
	}
	if u := look(ctx, "cobol", "x", "1"); u.State != unified.StateNotChecked || u.Err == "" {
		t.Fatalf("an unsupported ecosystem must be not_checked with a reason, got %+v", u)
	}
	if u := New("", fetch.New()).Lookuper()(ctx, "npm", "lodash", "4.17.20"); u.State != unified.StateNotChecked {
		t.Fatalf("an off source must be not_checked, got %+v", u)
	}
}

// A platform's release (a detected Shopware 5) looked up in a core package may not be one of the
// package's releases. No advisory is ever dropped for it: one that reaches the version only through the
// "introduced 0" range of an advisory listing the package's releases, while the version is older than
// every version the package's advisories name, is kept and marked (OutsideListed, a note on the lead) —
// it may not apply (Shopware 5 in a Shopware 6 package) or may (Liferay 6.2 under an artifact first
// published at 7.0). Everything else is unmarked: a range with its own bound, an advisory listing no
// versions, npm, distros, and a package's own version (an SBOM, --package).
func TestPlatformReleaseBelowEveryNamedVersionIsMarkedNotDropped(t *testing.T) {
	adv := func(id, eco, pkg, introduced, fixed string, versions ...string) string {
		vs, _ := json.Marshal(versions)
		return `{"id":"` + id + `","affected":[{"package":{"name":"` + pkg + `","ecosystem":"` + eco + `"},` +
			`"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"` + introduced + `"},{"fixed":"` + fixed + `"}]}],"versions":` + string(vs) + `}]}`
	}
	ordered := func(eco string, nameBody ...string) *Index {
		var buf bytes.Buffer
		zw := zip.NewWriter(&buf)
		for i := 0; i < len(nameBody); i += 2 {
			w, _ := zw.Create(nameBody[i])
			_, _ = w.Write([]byte(nameBody[i+1]))
		}
		_ = zw.Close()
		idx, err := BuildIndex(context.Background(), eco, bytes.NewReader(buf.Bytes()), int64(buf.Len()))
		if err != nil {
			t.Fatal(err)
		}
		return idx
	}
	idx := ordered("Packagist",
		"b.json", adv("GHSA-b", "Packagist", "shopware/core", "0", "6.5.1.0", "6.5.0.0", "6.2.0"), // read first, its own list starts above the package's
		"a.json", adv("GHSA-a", "Packagist", "shopware/core", "0", "6.4.20.0", "6.4.19.0", "6.0.0", "6.1.0"),
		"n.json", adv("GHSA-n", "Packagist", "shopware/core", "0", "6.4.0"),
		"pb.json", adv("GHSA-pb", "Packagist", "shopware/platform", "0", "6.5.1.0", "6.2.0"),
		"pe.json", adv("GHSA-pe", "Packagist", "shopware/platform", "5.0.0", "5.7.18"),
		"x.json", adv("GHSA-x", "Packagist", "drupal/drupal", "8.0.0", "8.9.0", "8.0.0", "8.5.0"),
		"y.json", adv("GHSA-y", "Packagist", "drupal/drupal", "0", "7.58"),
	)
	ids := func(r Result) string { // a marked advisory carries a "?"
		var out []string
		for _, v := range r.Vulns {
			id := v.ID
			if v.OutsideListed {
				id += "?"
			}
			out = append(out, id)
		}
		sort.Strings(out)
		return strings.Join(out, ",")
	}
	for _, tc := range []struct {
		pkg, version, want string
		below              bool
	}{
		{"shopware/core", "5.7.17", "GHSA-a?,GHSA-b?,GHSA-n", true}, // GHSA-a and GHSA-b list the releases from 6.0.0; GHSA-n lists none
		{"shopware/core", "6.1.5", "GHSA-a,GHSA-b,GHSA-n", false},   // GHSA-b's list starts at 6.2.0, but GHSA-a names 6.0.0
		{"shopware/platform", "5.7.17", "GHSA-pb,GHSA-pe", false},   // GHSA-pe names 5.0.0: 5.x may be the package's
		{"shopware/platform", "4.3.0", "GHSA-pb?", true},
		{"drupal/drupal", "7.57", "GHSA-y", true}, // below 7.58, the lowest named, but GHSA-y lists no versions
	} {
		got := idx.lookup("", tc.pkg, tc.version, true)
		if ids(got) != tc.want || got.BelowListed != tc.below {
			t.Errorf("release %s@%s = %v %q below=%v, want %q below=%v", tc.pkg, tc.version, got.Status, ids(got), got.BelowListed, tc.want, tc.below)
		}
	}
	if got := idx.Lookup("shopware/core", "5.7.17"); ids(got) != "GHSA-a,GHSA-b,GHSA-n" || got.BelowListed {
		t.Errorf("a package's own version keeps OSV's rule, unmarked: %q below=%v", ids(got), got.BelowListed)
	}
	u := ToUnified(idx.lookup("", "shopware/core", "5.7.17", true), "Packagist", "shopware/core", "5.7.17", time.Time{})
	notes := map[string]string{}
	for _, l := range u.Leads {
		notes[l.ID] = l.Note
	}
	if len(u.Leads) != 3 || !strings.Contains(notes["GHSA-a"], "older than every version") || notes["GHSA-n"] != "" {
		t.Errorf("every lead is reported, a marked one with its note: %+v", u.Leads)
	}
	npm := ordered("npm",
		"1.json", adv("GHSA-1", "npm", "lodash", "0", "4.17.21"),
		"2.json", adv("GHSA-2", "npm", "lodash", "0", "4.17.24", "4.17.23"))
	if got := npm.lookup("", "lodash", "4.17.20", true); ids(got) != "GHSA-1,GHSA-2" {
		t.Errorf("npm lists are not the registry's releases: lodash@4.17.20 = %q", ids(got))
	}
	deb := ordered("Debian", "d.json", adv("DSA-1", "Debian:12", "openssl", "0", "3.0.11-1", "3.0.9-1", "3.0.10-1"))
	if got := deb.lookup("Debian:12", "openssl", "3.0.8-1", true); ids(got) != "DSA-1" {
		t.Errorf("a distro version below the list keeps OSV's rule, unmarked: %q", ids(got))
	}
}

// The package's listed floor travels in the index file, so a run reading it still knows where the
// package's releases begin.
func TestIndexFileKeepsTheListedFloor(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dump.idx.gz")
	w := newIndexWriter(path, "stamp")
	w.put(&record{pkg: "p", ecosystem: "Packagist", id: "X-1", floor: "6.0.0", listed: true, vulnKeys: []string{"X-1"},
		ranges: []affectedRange{{typ: "ECOSYSTEM", introduced: "0", fixed: "6.4.0"}}})
	w.putSkipped(0)
	w.finish(true)
	idx, err := readIndexFile(path, "stamp", "Packagist", releaseRows("Packagist"))
	if err != nil {
		t.Fatal(err)
	}
	if got := idx.lookup("", "p", "5.7.17", true); len(got.Vulns) != 1 || !got.Vulns[0].OutsideListed {
		t.Fatalf("floor or list mark lost in the index file: release 5.7.17 = %+v", got)
	}
	if got := idx.lookup("", "p", "6.1.0", true); got.Status != StatusVulnerable {
		t.Fatalf("6.1.0 = %v, want vulnerable", got.Status)
	}
}

// An index file cut under another row format is not read — its rows would lack (or misread) fields
// the lookup now relies on — so the dump is reduced again.
func TestIndexFileOfAnotherFormatIsCutAgain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dump.idx.gz")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(f)
	if err := gob.NewEncoder(gz).Encode(indexHeader{Format: "sigforge-osv-index/9", Dump: "stamp"}); err != nil {
		t.Fatal(err)
	}
	_ = gz.Close()
	_ = f.Close()
	if _, err := readIndexFile(path, "stamp", "Packagist", releaseRows("Packagist")); !errors.Is(err, errStaleIndex) {
		t.Fatalf("an index of another format must be refused as stale, got %v", err)
	}
}
