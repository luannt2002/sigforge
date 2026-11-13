package osv

import (
	"context"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/luannt2002/sigforge/framework/fetch"
	"github.com/luannt2002/sigforge/modules/intel/unified"
)

// storeFiles is every file in the store with its bytes.
func storeFiles(t *testing.T, dir string) map[string]string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, e := range entries {
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		out[e.Name()] = string(b)
	}
	return out
}

// zipServer serves whatever dump holds at /npm/all.zip and counts the requests.
func zipServer(t *testing.T, dump *atomic.Value) (string, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path != "/npm/all.zip" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(dump.Load().([]byte))
	}))
	t.Cleanup(srv.Close)
	return srv.URL, &hits
}

// A run that asks the source itself (no max age) puts a new dump in the store only once its index is cut from the
// downloaded file and holds an advisory. A refused dump leaves every byte of the stored dump and its index; the run
// answers from them, labelled stale, with a note saying why — one request per run, as before.
func TestRunKeepsTheStoredDumpOverJunk(t *testing.T) {
	good, _ := makeZip(t, map[string]string{"npm/GHSA-old.json": lodashAdv("GHSA-old", "4.17.21", "")})
	noAdvisory, _ := makeZip(t, map[string]string{})
	otherShape, _ := makeZip(t, map[string]string{"npm/x.json": `{"unexpected": true, "items": [1, 2, 3]}`})
	for _, junk := range []struct {
		name string
		body []byte
		why  string
	}{
		{"html page", []byte("<html>proxy login required</html>"), "not a valid zip file"},
		{"empty body", nil, errEmptyDump.Error()},
		{"zip holding no advisory", mustBytes(noAdvisory), errBuiltNothing.Error()},
		{"zip of records of another shape", mustBytes(otherShape), errBuiltNothing.Error()},
	} {
		t.Run(junk.name, func(t *testing.T) {
			var dump atomic.Value
			dump.Store(mustBytes(good))
			url, hits := zipServer(t, &dump)
			c := fetch.New()
			c.CacheDir = t.TempDir()
			ctx := context.Background()
			pkg, _ := New(url, c).Lookupers()
			if u := pkg(ctx, "npm", "lodash", "4.17.15"); u.State != unified.StateAffectedByAdvisory || u.Freshness != unified.FreshnessLive {
				t.Fatalf("the first run must take the good dump: %+v", u)
			}
			before := storeFiles(t, c.CacheDir)
			if len(before) != 3 {
				t.Fatalf("want the dump, its meta and its index in the store, found %d files", len(before))
			}
			dump.Store(junk.body)
			a := New(url, c)
			if _, _, _, err := a.dump(ctx, c, "npm"); err != nil {
				t.Fatal(err)
			}
			// checked before the lookup reads the dump: a wrong index in the store would be cut again by then
			if after := storeFiles(t, c.CacheDir); !maps.Equal(before, after) {
				t.Fatalf("the store must keep every byte of its dump and index: %d files before, now %d", len(before), len(after))
			}
			pkg, _ = a.Lookupers()
			u := pkg(ctx, "npm", "lodash", "4.17.15")
			if after := storeFiles(t, c.CacheDir); !maps.Equal(before, after) {
				t.Fatalf("the lookup must leave the store as it was: %d files before, now %d", len(before), len(after))
			}
			if u.State != unified.StateAffectedByAdvisory || u.Freshness != unified.FreshnessStale || !strings.Contains(u.Err, "unusable body") || !strings.Contains(u.Err, junk.why) {
				t.Fatalf("want the stored dump's verdict, stale, with a note saying why: %+v", u)
			}
			if hits.Load() != 2 {
				t.Fatalf("want one request per run, sent %d over two runs", hits.Load())
			}
		})
	}
}

// With nothing stored, a refused dump leaves nothing in the store — no dump, no index — nor in the working directory,
// and the lookup is source_unavailable with why.
func TestRunStoresNoRefusedDump(t *testing.T) {
	cwd := t.TempDir()
	t.Chdir(cwd) // the refused dump has no path in the store: its index must not move beside "" either
	noAdvisory, _ := makeZip(t, map[string]string{})
	var dump atomic.Value
	dump.Store(mustBytes(noAdvisory))
	url, hits := zipServer(t, &dump)
	c := fetch.New()
	c.CacheDir = t.TempDir()
	pkg, _ := New(url, c).Lookupers()
	u := pkg(context.Background(), "npm", "lodash", "4.17.15")
	if files := storeFiles(t, c.CacheDir); len(files) != 0 {
		t.Fatalf("a refused dump must leave nothing in the store, found %d files", len(files))
	}
	if files := storeFiles(t, cwd); len(files) != 0 {
		t.Fatalf("a refused dump must leave nothing in the working directory, found %d files", len(files))
	}
	if u.State != unified.StateSourceUnavailable || !strings.Contains(u.Err, errBuiltNothing.Error()) || hits.Load() != 1 {
		t.Fatalf("want source_unavailable with why, after one request: %+v / %d", u, hits.Load())
	}
}

// On a 304 the stored dump is checked again as a new one is. One no check passed — an older binary stored it and cut
// its index — is refused: an error, never served, not even stale, and its index is removed, written nowhere else.
func TestRunRechecksTheStoredDumpOnNotModified(t *testing.T) {
	cwd := t.TempDir()
	t.Chdir(cwd)
	noAdvisory, _ := makeZip(t, map[string]string{})
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Header.Get("If-None-Match") != "" {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"v1"`)
		_, _ = w.Write(mustBytes(noAdvisory))
	}))
	defer srv.Close()
	c := fetch.New()
	c.CacheDir = t.TempDir()
	ctx := context.Background()
	stored, _, _, err := c.Download(ctx, srv.URL+"/npm/all.zip", maxZipBytes) // stored unchecked, as an older binary did
	if err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(stored)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := dumpIndex(ctx, "npm", stored, st, func(*record) bool { return true }, true); err != nil {
		t.Fatal(err)
	}
	if files := storeFiles(t, c.CacheDir); len(files) != 3 {
		t.Fatalf("want the dump, its meta and its index in the store, found %d files", len(files))
	}
	path, m, _, err := New(srv.URL, c).dump(ctx, c, "npm")
	if err == nil || !strings.Contains(err.Error(), "stored copy unusable") || !strings.Contains(err.Error(), errBuiltNothing.Error()) || path != "" || m.Stale || hits.Load() != 2 {
		t.Fatalf("a stored dump refused on a 304 must be an error, never served, after one request: %q %+v %v / %d", path, m, err, hits.Load())
	}
	if _, err := os.Stat(stored + ".idx.gz"); !os.IsNotExist(err) {
		t.Fatalf("the refused dump's index must be removed: %v", err)
	}
	if files := storeFiles(t, cwd); len(files) != 0 {
		t.Fatalf("the refused dump's index must be written nowhere else, found %d files in the working directory", len(files))
	}
}

// Without a store a run reads the dump from a temp file, as before: nothing is left behind, not even an index.
func TestRunWithoutAStoreLeavesNoFile(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	good, _ := makeZip(t, map[string]string{"npm/GHSA-old.json": lodashAdv("GHSA-old", "4.17.21", "")})
	var dump atomic.Value
	dump.Store(mustBytes(good))
	url, hits := zipServer(t, &dump)
	pkg, _ := New(url, fetch.New()).Lookupers()
	u := pkg(context.Background(), "npm", "lodash", "4.17.15")
	if files := storeFiles(t, tmp); len(files) != 0 || u.State != unified.StateAffectedByAdvisory || hits.Load() != 1 {
		t.Fatalf("want the verdict after one request and no file left behind: %d files, %+v, %d requests", len(files), u, hits.Load())
	}
}

// A dump whose index is cut still replaces the stored one, its index beside it, with one request per run.
func TestRunReplacesTheStoredDumpWithAGoodOne(t *testing.T) {
	old, _ := makeZip(t, map[string]string{"npm/GHSA-old.json": lodashAdv("GHSA-old", "4.17.21", "")})
	next, _ := makeZip(t, map[string]string{"npm/GHSA-new.json": lodashAdv("GHSA-new", "4.17.10", "")})
	var dump atomic.Value
	dump.Store(mustBytes(old))
	url, hits := zipServer(t, &dump)
	c := fetch.New()
	c.CacheDir = t.TempDir()
	ctx := context.Background()
	pkg, _ := New(url, c).Lookupers()
	pkg(ctx, "npm", "lodash", "4.17.15")
	dump.Store(mustBytes(next))
	pkg, _ = New(url, c).Lookupers()
	u := pkg(ctx, "npm", "lodash", "4.17.15")
	files := storeFiles(t, c.CacheDir)
	stored := false
	for name, b := range files {
		stored = stored || strings.HasSuffix(name, ".body") && b == string(mustBytes(next))
	}
	if !stored || len(files) != 3 || u.State == unified.StateAffectedByAdvisory || u.Freshness != unified.FreshnessLive || hits.Load() != 2 {
		t.Fatalf("want the new dump (lodash 4.17.15 past its fix) live, in the store with its index, after one request per run: stored=%v files=%d %+v / %d",
			stored, len(files), u, hits.Load())
	}
	bodies, _ := filepath.Glob(filepath.Join(c.CacheDir, "*.body"))
	st, err := os.Stat(bodies[0])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := readIndexFile(bodies[0]+".idx.gz", dumpStamp(st), "npm", func(*record) bool { return true }); err != nil {
		t.Fatalf("the index beside the new dump must be cut from it: %v", err)
	}
}
