package osv

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luannt2002/sigforge/framework/fetch"
	"github.com/luannt2002/sigforge/modules/intel/unified"
)

// One advisory, two Debian releases with different fixes — the shape of a security backport:
// Debian 12 ships the older 1.5 branch patched as 1.5-1+deb12u1, Debian 11 only fixed it in 2.0-1.
const advBackport = `{
  "id":"DSA-0000-1","aliases":["CVE-2024-0001"],
  "affected":[
    {"package":{"name":"foo","ecosystem":"Debian:11"},
      "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"2.0-1"}]}]},
    {"package":{"name":"foo","ecosystem":"Debian:12"},
      "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1:1.5-1+deb12u1"}]}]}]
}`

// A distro dump holds every release; a version is only positioned against its own release's
// records, and a release with no record for the package is unknown, never clean.
func TestDistroLookupIsScopedToRelease(t *testing.T) {
	idx := buildIdx(t, "Debian", map[string]string{"Debian/DSA-0000-1.json": advBackport})
	if r := idx.LookupIn("Debian:12", "foo", "1:1.5-1+deb12u1"); r.Status != StatusNoKnownVuln || !r.VersionPinned {
		t.Fatalf("Debian 12 foo 1:1.5-1+deb12u1 is the fixed build, got %+v", r)
	}
	if r := idx.LookupIn("Debian:12", "foo", "1:1.5-1"); r.Status != StatusVulnerable || !r.VersionPinned {
		t.Fatalf("Debian 12 foo 1:1.5-1 is before its release's fix, got %+v", r)
	}
	if r := idx.LookupIn("Debian:11", "foo", "1.9-3"); r.Status != StatusVulnerable {
		t.Fatalf("Debian 11 foo 1.9-3 is before 2.0-1, got %+v", r)
	}
	if r := idx.LookupIn("Debian:13", "foo", "2.5-1"); r.Status != StatusUnknown || r.PackageKnown {
		t.Fatalf("a release with no record for the package must be unknown, got %+v", r)
	}
}

// Real OS-package versions (epoch, tilde, apk suffixes, RPM module releases) are pinned versions,
// not ranges; manifest ranges still are not.
func TestCleanVersionKeepsOSPackageVersions(t *testing.T) {
	for _, v := range []string{"1:1.1.1n-0+deb11u4", "252.39-1~deb12u1", "1.2.3_rc1-r0", "1.1.1t-r0",
		"2:2.3.4-2.git87f9237.module_el8.5.0+119+9a9ec082"} {
		if CleanVersion(v) != v {
			t.Errorf("CleanVersion(%q) = %q; a concrete OS-package version must survive", v, CleanVersion(v))
		}
	}
	for _, r := range []string{"^4.17.0", "~1.2", ">=1.2 <2", "1.2.*", "1 || 2", ""} {
		if CleanVersion(r) != "" {
			t.Errorf("CleanVersion(%q) = %q; a range is not a pinned version", r, CleanVersion(r))
		}
	}
}

func TestEcosystemOSAndMoreLanguages(t *testing.T) {
	cases := map[string]string{"Debian:12": "Debian", "debian": "Debian", "Ubuntu:22.04:LTS": "Ubuntu",
		"Alpine:v3.18": "Alpine", "wolfi": "Wolfi", "Chainguard": "Chainguard", "Rocky Linux:8": "Rocky Linux",
		"AlmaLinux:9": "AlmaLinux", "hex": "Hex", "pub": "Pub", "cran": "CRAN", "hackage": "Hackage", "swift": "SwiftURL"}
	for in, want := range cases {
		if got, ok := Ecosystem(in); !ok || got != want {
			t.Errorf("Ecosystem(%q) = %q,%v; want %q", in, got, ok, want)
		}
	}
}

// The distro dump is one file per distro (OSV no longer exports per-release dumps): a lookup with
// a release loads it once from the base directory; without a release it is not answered.
func TestLookuperDistroRelease(t *testing.T) {
	r, _ := makeZip(t, map[string]string{"Debian/DSA-0000-1.json": advBackport})
	body := mustBytes(r)
	var hits atomic.Int32
	var path atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		path.Store(r.URL.Path)
		_, _ = w.Write(body)
	}))
	defer srv.Close()
	ctx := context.Background()
	look := New(srv.URL, fetch.New()).Lookuper()
	if u := look(ctx, "Debian:12", "foo", "1:1.5-1+deb12u1"); u.State != unified.StateNotChecked || u.Err != unified.NoteNoClearance {
		t.Fatalf("Debian 12 fixed build = %+v, want not_checked with NoteNoClearance", u)
	}
	if u := look(ctx, "Debian:11", "foo", "1.9-3"); u.State != unified.StateAffectedByAdvisory {
		t.Fatalf("Debian 11 foo 1.9-3 = %+v, want affected", u)
	}
	if n, p := hits.Load(), path.Load(); n != 1 || p != "/Debian/all.zip" {
		t.Fatalf("want one load of /Debian/all.zip, got %d of %v", n, p)
	}
	if u := look(ctx, "Debian", "foo", "1.9-3"); u.State != unified.StateNotChecked || !strings.Contains(u.Err, "release") {
		t.Fatalf("a distro package without its release must be not_checked naming the release, got %+v", u)
	}
}

// A dump announced larger than the disk ceiling is refused before its body is read, so a
// too-large ecosystem costs one response header, not hundreds of megabytes per run.
func TestDownloadRefusesOversizedDumpUpFront(t *testing.T) {
	var sent atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "999999999999")
		chunk := make([]byte, 1<<20)
		for i := 0; i < 64; i++ {
			n, err := w.Write(chunk)
			sent.Add(int64(n))
			if err != nil {
				return
			}
		}
	}))
	defer srv.Close()
	_, err := New(srv.URL, fetch.New()).LoadIndex(context.Background(), "npm")
	if err == nil || !strings.Contains(err.Error(), "ceiling") {
		t.Fatalf("want a ceiling error, got %v", err)
	}
}

// With a store, a dump is downloaded once: a later run within MaxAge reads the stored copy
// with no request and labels its verdicts snapshot; when the source fails, the stored dump
// still answers, labelled stale with the failure.
func TestLookuperUsesStoredDump(t *testing.T) {
	r, _ := makeZip(t, map[string]string{"npm/GHSA-35jh-r3h4-6jhm.json": advLodash})
	body := mustBytes(r)
	var hits atomic.Int32
	var down atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if down.Load() {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write(body)
	}))
	defer srv.Close()
	ctx := context.Background()
	c := fetch.New()
	c.CacheDir, c.MaxAge = t.TempDir(), time.Hour
	if u := New(srv.URL, c).Lookuper()(ctx, "npm", "lodash", "4.17.20"); u.Freshness != unified.FreshnessLive || u.State != unified.StateAffectedByAdvisory {
		t.Fatalf("first run = %+v, want a live affected verdict", u)
	}
	u := New(srv.URL, c).Lookuper()(ctx, "npm", "lodash", "4.17.20")
	if hits.Load() != 1 || u.Freshness != unified.FreshnessSnapshot || u.State != unified.StateAffectedByAdvisory {
		t.Fatalf("a run within MaxAge must use the stored dump with no request: hits=%d %+v", hits.Load(), u)
	}
	c.MaxAge = 0
	down.Store(true)
	u = New(srv.URL, c).Lookuper()(ctx, "npm", "lodash", "4.17.20")
	if u.Freshness != unified.FreshnessStale || !strings.Contains(u.Err, "503") || u.State != unified.StateAffectedByAdvisory {
		t.Fatalf("a failing source must answer from the stored dump labelled stale, got %+v", u)
	}
}

// A release lookup keeps only that release's rows (and release-less ones) in memory: a
// distro dump holds every release, and Ubuntu's alone reduces to millions of rows.
func TestLoadIndexKeepsOnlyTheRelease(t *testing.T) {
	r, _ := makeZip(t, map[string]string{"Debian/DSA-0000-1.json": advBackport})
	body := mustBytes(r)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(body) }))
	defer srv.Close()
	for _, store := range []string{"", t.TempDir()} {
		c := fetch.New()
		c.CacheDir = store
		idx, err := New(srv.URL, c).LoadIndex(context.Background(), "Debian:12")
		if err != nil || idx.Len() != 1 {
			t.Fatalf("store %q: a Debian:12 index must hold only its own row, got %d rows, %v", store, idx.Len(), err)
		}
	}
}

// The reduced index is cut once and kept beside the dump: while the stored dump is the same,
// a run reads the index file and never parses the dump again; a changed dump is re-cut.
func TestIndexFileReusedUntilDumpChanges(t *testing.T) {
	v1, _ := makeZip(t, map[string]string{"npm/GHSA-35jh-r3h4-6jhm.json": advLodash})
	v2, _ := makeZip(t, map[string]string{"npm/GHSA-35jh-r3h4-6jhm.json": strings.Replace(advLodash, `"fixed":"4.17.21"`, `"fixed":"4.17.19"`, 1)})
	var cur atomic.Value
	cur.Store([2]any{`"v1"`, mustBytes(v1)})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := cur.Load().([2]any)
		if r.Header.Get("If-None-Match") == v[0].(string) {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", v[0].(string))
		_, _ = w.Write(v[1].([]byte))
	}))
	defer srv.Close()
	ctx := context.Background()
	c := fetch.New()
	c.CacheDir = t.TempDir()
	if u := New(srv.URL, c).Lookuper()(ctx, "npm", "lodash", "4.17.20"); u.State != unified.StateAffectedByAdvisory {
		t.Fatalf("v1 run = %+v, want affected", u)
	}
	// Blank the stored dump without changing its size or time: only the index file can answer now.
	dumps, _ := filepath.Glob(filepath.Join(c.CacheDir, "*.body"))
	if len(dumps) != 1 {
		t.Fatalf("want one stored dump, found %v", dumps)
	}
	fi, _ := os.Stat(dumps[0])
	if err := os.WriteFile(dumps[0], make([]byte, fi.Size()), 0o644); err != nil {
		t.Fatal(err)
	}
	_ = os.Chtimes(dumps[0], fi.ModTime(), fi.ModTime())
	if u := New(srv.URL, c).Lookuper()(ctx, "npm", "lodash", "4.17.20"); u.State != unified.StateAffectedByAdvisory {
		t.Fatalf("an unchanged dump must be answered from its index file, got %+v", u)
	}
	cur.Store([2]any{`"v2"`, mustBytes(v2)})
	if u := New(srv.URL, c).Lookuper()(ctx, "npm", "lodash", "4.17.20"); u.State != unified.StateNotChecked || u.Err != unified.NoteNoClearance {
		t.Fatalf("a changed dump must be re-cut (v2 fixes 4.17.19), got %+v", u)
	}
}

// With a store, each release is its own index, yet one run asks the source for the distro's
// dump once, however many of its releases it looks up.
func TestStoreReleasesShareOneDump(t *testing.T) {
	r, _ := makeZip(t, map[string]string{"Debian/DSA-0000-1.json": advBackport})
	body := mustBytes(r)
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = w.Write(body)
	}))
	defer srv.Close()
	c := fetch.New()
	c.CacheDir = t.TempDir()
	look := New(srv.URL, c).Lookuper()
	a := look(context.Background(), "Debian:12", "foo", "1:1.5-1")
	b := look(context.Background(), "Debian:11", "foo", "1.9-3")
	if hits.Load() != 1 || a.State != unified.StateAffectedByAdvisory || b.State != unified.StateAffectedByAdvisory {
		t.Fatalf("two releases must cost one request and both answer: hits=%d %s %s", hits.Load(), a.State, b.State)
	}
}

// Two ecosystems load side by side — a scanner looks packages up from many flows at once, and one
// ecosystem's long download must not hold up another's — while each still loads once.
func TestLookuperLoadsEcosystemsInParallel(t *testing.T) {
	npm, _ := makeZip(t, map[string]string{"npm/GHSA-35jh-r3h4-6jhm.json": advLodash})
	npmBody := mustBytes(npm)
	arrived := make(chan string, 4)
	release := make(chan struct{})
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		arrived <- r.URL.Path
		<-release
		_, _ = w.Write(npmBody)
	}))
	defer srv.Close()
	for _, store := range []string{"", t.TempDir()} {
		c := fetch.New()
		c.CacheDir = store
		look := New(srv.URL, c).Lookuper()
		hits.Store(0)
		release = make(chan struct{})
		done := make(chan struct{})
		go func() {
			defer close(done)
			var wg sync.WaitGroup
			for _, eco := range []string{"npm", "npm", "PyPI", "PyPI"} {
				wg.Add(1)
				go func(e string) { defer wg.Done(); look(context.Background(), e, "lodash", "4.17.20") }(eco)
			}
			wg.Wait()
		}()
		seen := map[string]bool{}
		for len(seen) < 2 {
			select {
			case p := <-arrived:
				seen[p] = true
			case <-time.After(2 * time.Second):
				close(release) // let the held download finish so the server can shut down
				t.Fatalf("store %q: only %v in flight after 2s — ecosystems load one after another", store, seen)
			}
		}
		close(release)
		<-done
		if n := hits.Load(); n != 2 {
			t.Fatalf("store %q: want one download per ecosystem (2), got %d", store, n)
		}
	}
}

// An advisory that lists only concrete versions keeps the first maxExactVersions of them; a
// version past that cut is not known to be outside the list, so it is unknown, never clean.
func TestTruncatedVersionListIsNeverClean(t *testing.T) {
	var vs []string
	for i := 0; i < maxExactVersions+4; i++ {
		vs = append(vs, fmt.Sprintf(`"1.0.%d"`, i))
	}
	adv := `{"id":"GHSA-many","affected":[{"package":{"name":"manyver","ecosystem":"npm"},"versions":[` + strings.Join(vs, ",") + `]}]}`
	idx := buildIdx(t, "npm", map[string]string{"npm/GHSA-many.json": adv})
	if r := idx.Lookup("manyver", "1.0.5"); r.Status != StatusVulnerable {
		t.Fatalf("a listed version within the cut must be vulnerable, got %+v", r)
	}
	last := fmt.Sprintf("1.0.%d", maxExactVersions+3)
	if r := idx.Lookup("manyver", last); r.Status == StatusNoKnownVuln {
		t.Fatalf("%s is past the kept list, so it is unknown — got %+v", last, r)
	}
}

// The hint for a distro package with no release points at a form that can name one.
func TestNoReleaseHintNamesAUsableForm(t *testing.T) {
	u := New("http://127.0.0.1:1", fetch.New()).Lookuper()(context.Background(), "debian", "openssl", "3.0.11-1")
	if u.State != unified.StateNotChecked || !strings.Contains(u.Err, "distro=") || strings.Contains(u.Err, "Debian:<release>") {
		t.Fatalf("got %+v", u)
	}
	if u.Scope != "ecosystem:Debian" {
		t.Fatalf("scope %q, want the canonical ecosystem:Debian every other result uses", u.Scope)
	}
}

// A GIT range (commit bounds) cannot place a version, but it never overrides what the record
// can answer: a release-level range decides beside it, and when commit ranges are all there is,
// the versions list OSV enumerated from them decides — as an OSV client is told to read it.
func TestGitRangesDoNotMaskWhatCanBeAnswered(t *testing.T) {
	const withRange = `{"id":"PYSEC-1","affected":[{"package":{"name":"withgit","ecosystem":"PyPI"},"ranges":[
	  {"type":"GIT","repo":"https://example.test/r","events":[{"introduced":"0"},{"fixed":"6879efc2c1596d11a6a6ce296d1cf3b2f5b4f6ad"}]},
	  {"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"2.0.0"}]}]}]}`
	const gitWithList = `{"id":"PYSEC-2","affected":[{"package":{"name":"gitlist","ecosystem":"PyPI"},"ranges":[
	  {"type":"GIT","repo":"https://example.test/r","events":[{"introduced":"0"},{"fixed":"6879efc2c1596d11a6a6ce296d1cf3b2f5b4f6ad"}]}],
	  "versions":["1.0.0","1.1.0"]}]}`
	idx := buildIdx(t, "PyPI", map[string]string{"PyPI/PYSEC-1.json": withRange, "PyPI/PYSEC-2.json": gitWithList})
	for _, c := range []struct {
		name, version string
		want          Status
	}{
		{"withgit", "1.5.0", StatusVulnerable}, {"withgit", "3.0.0", StatusNoKnownVuln},
		{"gitlist", "1.1.0", StatusVulnerable}, {"gitlist", "2.0.0", StatusNoKnownVuln},
	} {
		if r := idx.Lookup(c.name, c.version); r.Status != c.want {
			t.Errorf("%s %s = %s, want %s", c.name, c.version, r.Status, c.want)
		}
	}
}

// An answer the version could not be placed in still names the advisories to look at, and a
// verdict from a stale dump keeps its reason beside the staleness.
func TestUnplacedAdvisoriesAreLeadsAndKeepTheirReason(t *testing.T) {
	r, _ := makeZip(t, map[string]string{"npm/OSV-2021-GIT1.json": advGitOnly})
	body := mustBytes(r)
	var down atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if down.Load() {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write(body)
	}))
	defer srv.Close()
	c := fetch.New()
	c.CacheDir = t.TempDir()
	u := New(srv.URL, c).Lookuper()(context.Background(), "npm", "gitpkg", "1.0.0")
	if u.State != unified.StatePotentiallyAffected || len(u.Leads) != 1 || u.Leads[0].ID != "OSV-2021-GIT1" {
		t.Fatalf("an unplaced advisory must be a lead, got %v %+v", u.State, u.Leads)
	}
	down.Store(true)
	u = New(srv.URL, c).Lookuper()(context.Background(), "npm", "gitpkg", "1.0.0")
	if u.Freshness != unified.FreshnessStale || !strings.Contains(u.Err, "placed") || !strings.Contains(u.Err, "stale") {
		t.Fatalf("a stale verdict must keep why it is potential, got %q", u.Err)
	}
}

// A dump entry that could not be read (corrupt or past the size cap) may have been about any
// package, so the dump is not provably whole: "nothing matched" is not checked, not clean.
func TestUnreadableDumpEntryMeansNotWhole(t *testing.T) {
	idx := buildIdx(t, "npm", map[string]string{"npm/GHSA-35jh-r3h4-6jhm.json": advLodash, "npm/broken.json": "{ not json"})
	u := ToUnified(idx.Lookup("lodash", "4.17.21"), "npm", "lodash", "4.17.21", time.Time{})
	if u.State != unified.StateNotChecked || u.Err == "" || u.Err == unified.NoteNoClearance {
		t.Fatalf("a dump with an unreadable entry must say only part of it was read: %v %q", u.State, u.Err)
	}
	whole := buildIdx(t, "npm", map[string]string{"npm/GHSA-35jh-r3h4-6jhm.json": advLodash})
	if u := ToUnified(whole.Lookup("lodash", "4.17.21"), "npm", "lodash", "4.17.21", time.Time{}); u.Err != unified.NoteNoClearance {
		t.Fatalf("a whole dump reaches the whole-data branch for 4.17.21, got %v %q", u.State, u.Err)
	}
}

// The count of unreadable entries travels with the index file: a later run that reads the
// stored index still knows the dump was not whole.
func TestIndexFileKeepsTheUnreadableCount(t *testing.T) {
	r, _ := makeZip(t, map[string]string{"npm/GHSA-35jh-r3h4-6jhm.json": advLodash, "npm/broken.json": "{ not json"})
	body := mustBytes(r)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(body) }))
	defer srv.Close()
	c := fetch.New()
	c.CacheDir, c.MaxAge = t.TempDir(), time.Hour
	for run := 1; run <= 2; run++ {
		u := New(srv.URL, c).Lookuper()(context.Background(), "npm", "lodash", "4.17.21")
		if u.State == unified.StateNotAffectedByAdvisory {
			t.Fatalf("run %d answered clean from a dump with an unreadable entry", run)
		}
	}
	if idx, _ := filepath.Glob(filepath.Join(c.CacheDir, "*.idx.gz")); len(idx) != 1 {
		t.Fatalf("the second run must have read the index file, found %v", idx)
	}
}

// An index file the writer did not finish — no trailer row — cannot say how many dump entries
// were unreadable, so it is cut again rather than read as whole.
func TestIndexFileWithoutTrailerIsCutAgain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dump.idx.gz")
	w := newIndexWriter(path, "stamp")
	w.put(&record{pkg: "lodash", ecosystem: "npm", id: "GHSA-1"})
	w.finish(true)
	if _, err := readIndexFile(path, "stamp", "npm", releaseRows("npm")); err == nil {
		t.Fatal("an index file without its trailer row was read as whole")
	}
}

// An advisory that names the package but places no version — no range and no versions, or a
// range with no bounding event — is a lead to investigate: neither affected nor clean.
func TestAdvisoryWithoutAPlaceableRangeIsALead(t *testing.T) {
	for name, adv := range map[string]string{
		"no ranges":       `{"id":"X-1","affected":[{"package":{"name":"lodash","ecosystem":"npm"}}]}`,
		"only a limit":    `{"id":"X-2","affected":[{"package":{"name":"lodash","ecosystem":"npm"},"ranges":[{"type":"SEMVER","events":[{"limit":"9.9.9"}]}]}]}`,
		"events left out": `{"id":"X-3","affected":[{"package":{"name":"lodash","ecosystem":"npm"},"ranges":[{"type":"ECOSYSTEM"}]}]}`,
		"inverted range":  `{"id":"X-5","affected":[{"package":{"name":"lodash","ecosystem":"npm"},"ranges":[{"type":"SEMVER","events":[{"introduced":"4.17.0"},{"fixed":"4.16.0"}]}]}]}`,
		"beside a placed": `{"id":"X-4","affected":[{"package":{"name":"lodash","ecosystem":"npm"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.0.0"}]},{"type":"SEMVER","events":[]}]}]}`,
	} {
		idx := buildIdx(t, "npm", map[string]string{"npm/x.json": adv})
		u := ToUnified(idx.Lookup("lodash", "4.17.21"), "npm", "lodash", "4.17.21", time.Time{})
		if u.State != unified.StatePotentiallyAffected || len(u.Leads) != 1 {
			t.Errorf("%s: %v with %d leads, want potentially_affected with the advisory as a lead", name, u.State, len(u.Leads))
		}
	}
}

// Entries the schema does not allow are counted unreadable, so the dump is not whole.
func TestMalformedEntriesAreUnreadable(t *testing.T) {
	for name, bad := range map[string]string{
		"null":                 `null`,
		"no id":                `{"affected":[]}`,
		"withdrawn false":      `{"id":"X-1","withdrawn":false}`,
		"withdrawn empty":      `{"id":"X-2","withdrawn":""}`,
		"withdrawn not a time": `{"id":"X-3","withdrawn":"yes"}`,
		"affected holds null":  `{"id":"X-5","affected":[null]}`,
		"package null":         `{"id":"X-6","affected":[{"package":null,"versions":["1.0.0"]}]}`,
		"package without name": `{"id":"X-7","affected":[{"package":{"ecosystem":"npm"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"}]}]}]}`,
		"two objects":          `{"id":"X-8"}{"id":"X-9"}`,
		"trailing data":        `{"id":"X-10"}garbage`,
	} {
		idx := buildIdx(t, "npm", map[string]string{"npm/GHSA-35jh-r3h4-6jhm.json": advLodash, "npm/bad.json": bad})
		if res := idx.Lookup("lodash", "4.17.21"); !res.Partial {
			t.Errorf("%s: read as a whole dump", name)
		}
	}
	for name, ok := range map[string]string{
		"withdrawal timestamp":   `{"id":"X-4","withdrawn":"2024-01-02T03:04:05.123Z"}`,
		"repository-level entry": `{"id":"X-11","affected":[{"ranges":[{"type":"GIT","events":[{"introduced":"0"}]}],"versions":["v1.0.0"]}]}`,
	} {
		idx := buildIdx(t, "npm", map[string]string{"npm/GHSA-35jh-r3h4-6jhm.json": advLodash, "npm/ok.json": ok})
		if res := idx.Lookup("lodash", "4.17.21"); res.Partial {
			t.Errorf("%s: a valid entry was counted unreadable", name)
		}
	}
}

// OSV counts a version as affected when a range places it OR the versions list names it, so
// a listed version outside every range is affected (MAL- records list versions the range
// does not reach).
func TestListedVersionOutsideTheRangesIsAffected(t *testing.T) {
	idx := buildIdx(t, "npm", map[string]string{"npm/MAL-1.json": `{"id":"MAL-1","affected":[{"package":{"name":"rum","ecosystem":"npm"},` +
		`"ranges":[{"type":"SEMVER","events":[{"introduced":"99.9.1"}]}],"versions":["99.9.0","99.9.1"]}]}`})
	for v, want := range map[string]unified.State{"99.9.0": unified.StateAffectedByAdvisory, "99.9.2": unified.StateAffectedByAdvisory, "99.8.0": unified.StateNotChecked} {
		if u := ToUnified(idx.Lookup("rum", v), "npm", "rum", v, time.Time{}); u.State != want || (want == unified.StateNotChecked && u.Err != unified.NoteNoClearance) {
			t.Errorf("rum@%s: %v %q, want %v", v, u.State, u.Err, want)
		}
	}
}

// Versions a range already places are not kept, so a long list (Debian enumerates every
// affected build) does not hit the cap and turn every other version unknown.
func TestListedVersionsInsideTheRangesDoNotFillTheCap(t *testing.T) {
	versions := make([]string, maxExactVersions+50)
	for i := range versions {
		versions[i] = fmt.Sprintf("1.%d.0", i)
	}
	listed, _ := json.Marshal(versions)
	idx := buildIdx(t, "npm", map[string]string{"npm/X-1.json": `{"id":"X-1","affected":[{"package":{"name":"big","ecosystem":"npm"},` +
		`"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"2.0.0"}]}],"versions":` + string(listed) + `}]}`})
	if u := ToUnified(idx.Lookup("big", "2.0.0"), "npm", "big", "2.0.0", time.Time{}); u.Err != unified.NoteNoClearance {
		t.Fatalf("big@2.0.0 is past the range and not listed: %v %q, want the whole-data branch", u.State, u.Err)
	}
}

// A listed version matches the installed one by the ecosystem's own ordering, not by its
// spelling: PyPI lists "1.0", the environment pins "1.0.0".
func TestListedVersionMatchesByEcosystemOrder(t *testing.T) {
	for _, tc := range []struct{ eco, listed, installed string }{
		{"PyPI", "1.0", "1.0.0"},
		{"PyPI", "1.0.0-beta1", "1.0.0b1"},
		{"Maven", "1.0", "1.0.0"},
		{"npm", "1.0.0", "1.0.0+build.5"},
	} {
		idx := buildIdx(t, tc.eco, map[string]string{tc.eco + "/X-1.json": `{"id":"X-1","affected":[{"package":{"name":"p","ecosystem":"` + tc.eco + `"},` +
			`"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"5.0"}]}],"versions":["` + tc.listed + `"]}]}`})
		if u := ToUnified(idx.Lookup("p", tc.installed), tc.eco, "p", tc.installed, time.Time{}); u.State != unified.StateAffectedByAdvisory {
			t.Errorf("%s listed %q, installed %q: %v, want affected", tc.eco, tc.listed, tc.installed, u.State)
		}
	}
}

// ...and only when that order says equal: a pre-release, a release on one side of an RPM
// version, or another Debian epoch is not the listed version.
func TestListedVersionNeedsTrueEquality(t *testing.T) {
	for _, tc := range []struct{ eco, listed, installed string }{
		{"npm", "1.0.0-rc1", "1.0.0"},
		{"Rocky Linux:8", "1.0-1.el8", "1.0"},
		{"Debian:12", "1.0-1", "1:1.0-1"},
	} {
		dir := strings.SplitN(tc.eco, ":", 2)[0]
		idx := buildIdx(t, tc.eco, map[string]string{dir + "/X-1.json": `{"id":"X-1","affected":[{"package":{"name":"p","ecosystem":"` + tc.eco + `"},` +
			`"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"0.1"}]}],"versions":["` + tc.listed + `"]}]}`})
		res := idx.LookupIn(tc.eco, "p", tc.installed)
		if u := ToUnified(res, tc.eco, "p", tc.installed, time.Time{}); u.State == unified.StateAffectedByAdvisory {
			t.Errorf("%s listed %q, installed %q: affected, want no match", tc.eco, tc.listed, tc.installed)
		}
	}
}
